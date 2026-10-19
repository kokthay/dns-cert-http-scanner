#!/usr/bin/env python3
"""Retry A records iteratively or with ordered public resolvers."""

import argparse
import datetime as dt
import ipaddress
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

from collect import failure_file, folder_for, save


def ipv4_addresses(detail):
    if not isinstance(detail, dict) or detail.get("status") != "NOERROR":
        return []
    data = detail.get("data")
    addresses = set()
    if isinstance(data, dict):
        for answer in data.get("answers") or []:
            if not isinstance(answer, dict) or answer.get("type") != "A":
                continue
            try:
                addresses.add(str(ipaddress.IPv4Address(answer.get("answer"))))
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, TypeError):
                continue
    return sorted(addresses)


def read_detail(path, name):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("name", "").rstrip(".").lower() != name:
            return None
        return value.get("results", {}).get("A")
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def candidates_from_db(output, include_nxdomain):
    db = output / "status.sqlite3"
    if not db.is_file():
        raise ValueError(f"Missing original scan database: {db}")
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        for rank, name, status in conn.execute(
                "SELECT rank,name,a FROM domains ORDER BY rank"):
            if status == "NXDOMAIN" and not include_nxdomain:
                continue
            folder = folder_for(output, rank, name, 7)
            if status == "NOERROR_DATA" and ipv4_addresses(
                    read_detail(folder / "a.json", name)):
                continue
            yield rank, name, status
    finally:
        conn.close()


def candidates_from_list(output, input_list):
    """Use only the supplied JSONL names, keeping their original ranks."""
    db = output / "status.sqlite3"
    if not db.is_file():
        raise ValueError(f"Missing original scan database: {db}")
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    selected = set()
    try:
        with input_list.open(encoding="utf-8-sig") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    rank, name = item["rank"], item["domain"]
                except (ValueError, TypeError, KeyError) as exc:
                    raise ValueError(f"Invalid input list line {line_number}") from exc
                if type(rank) is not int or not isinstance(name, str) or rank < 1:
                    raise ValueError(f"Invalid rank/domain at input list line {line_number}")
                if rank in selected:
                    raise ValueError(f"Duplicate rank at input list line {line_number}: {rank}")
                row = conn.execute("SELECT name,a FROM domains WHERE rank=?",
                                   (rank,)).fetchone()
                if row is None or row[0] != name:
                    raise ValueError(f"Input list line {line_number} does not match "
                                     f"the original rank/domain: {rank}, {name!r}")
                selected.add(rank)
                yield rank, name, row[1]
    finally:
        conn.close()


def status(detail):
    return (detail.get("status", "UNKNOWN") if isinstance(detail, dict)
            else "MISSING_OUTPUT")


def google_report(output, candidates):
    recovered = failures = 0
    with (output / "a_google_status.jsonl").open("w", encoding="utf-8") as statuses, \
         (output / "a_google_recovered.jsonl").open("w", encoding="utf-8") as good, \
         failure_file(output, "a_google_failures.jsonl").open("w", encoding="utf-8") as bad:
        for rank, name, old_status in candidates:
            path = folder_for(output, rank, name, 7) / "a_google.json"
            detail = read_detail(path, name)
            addresses = ipv4_addresses(detail)
            item = {"rank": rank, "domain": name,
                    "iterative_a_status": old_status,
                    "google_status": status(detail), "ipv4": addresses}
            statuses.write(json.dumps(item) + "\n")
            if addresses:
                good.write(json.dumps(item) + "\n")
                recovered += 1
            else:
                bad.write(json.dumps(item) + "\n")
                failures += 1
    return recovered, failures


def final_report(output, selected, mode):
    recovered = failures = 0
    sources = {"iterative": 0, "iterative_retry": 0,
               "google": 0, "cloudflare": 0}
    with (output / "a_fallback_status.jsonl").open("w", encoding="utf-8") as statuses, \
         (output / "a_fallback_recovered.jsonl").open("w", encoding="utf-8") as good, \
         failure_file(output, "a_fallback_failures.jsonl").open("w", encoding="utf-8") as bad:
        for rank, name, old_status in selected:
            folder = folder_for(output, rank, name, 7)
            current = read_detail(folder / "a.json", name)
            current_addresses = ipv4_addresses(current)
            try:
                current_data = json.loads((folder / "a.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                current_data = {}
            source = (current_data.get("a_source", "iterative")
                      if current_addresses else None)
            original_status = current_data.get("original_iterative_a_status", old_status)
            google = read_detail(folder / "a_google.json", name)
            cloudflare = read_detail(folder / "a_cloudflare.json", name)
            iterative_retry = read_detail(folder / "a_iterative_retry.json", name)
            item = {"rank": rank, "domain": name,
                    "original_iterative_a_status": original_status,
                    "mode": mode,
                    "google_status": status(google),
                    "cloudflare_status": status(cloudflare),
                    "iterative_retry_status": status(iterative_retry),
                    "source": source,
                    "ipv4": current_addresses}
            statuses.write(json.dumps(item) + "\n")
            if source:
                good.write(json.dumps(item) + "\n")
                recovered += 1
                sources[source] = sources.get(source, 0) + 1
            else:
                bad.write(json.dumps(item) + "\n")
                failures += 1
    return recovered, failures, sources


def promote(output, candidates, mode):
    """Replace a.json only with a verified IPv4 response; keep its original."""
    conn = sqlite3.connect(output / "status.sqlite3")
    changed = 0
    try:
        for rank, name, old_status in candidates:
            folder = folder_for(output, rank, name, 7)
            stages = (("iterative_retry",) if mode == "iterative" else
                      ("google", "cloudflare"))
            for source in stages:
                path = folder / f"a_{source}.json"
                detail = read_detail(path, name)
                if not ipv4_addresses(detail):
                    continue
                original = folder / "a.json"
                backup = folder / "a_iterative_original.json"
                if original.is_file() and not backup.exists():
                    temporary = folder / f".a_iterative_original.{os.getpid()}.tmp"
                    try:
                        shutil.copy2(original, temporary)
                        os.replace(temporary, backup)
                    finally:
                        temporary.unlink(missing_ok=True)
                result = json.loads(path.read_text(encoding="utf-8"))
                result["a_source"] = source
                result["original_a_file"] = (backup.name if backup.exists() else None)
                result["original_iterative_a_status"] = old_status
                save(original, result)
                conn.execute("UPDATE domains SET a='NOERROR_DATA' WHERE rank=?", (rank,))
                conn.commit()
                changed += 1
                break
    finally:
        conn.close()
    return changed


def reconcile_db(output, selected):
    """Repair a DB status if an earlier run saved a usable A before stopping."""
    conn = sqlite3.connect(output / "status.sqlite3")
    try:
        with conn:
            for rank, name, old_status in selected:
                if old_status == "NOERROR_DATA":
                    continue
                path = folder_for(output, rank, name, 7) / "a.json"
                if ipv4_addresses(read_detail(path, name)):
                    conn.execute("UPDATE domains SET a='NOERROR_DATA' WHERE rank=?",
                                 (rank,))
    finally:
        conn.close()


def run_stage(output, candidates, args, label, resolver):
    """Run one resolver against remaining names; preserve per-domain results."""
    filename = f"a_{label}.json"
    pending = {}
    input_path = output / f"a-{label}-pending.txt"
    with input_path.open("w", encoding="utf-8") as stream:
        for rank, name, old_status in candidates:
            folder = folder_for(output, rank, name, 7)
            if label == "cloudflare" and ipv4_addresses(
                    read_detail(folder / "a_google.json", name)):
                continue
            path = folder / filename
            current = read_detail(path, name) if path.is_file() else None
            # Previous versions may have randomly chosen 8.8.4.4. Require
            # a fresh 8.8.8.8 result for the explicit ordered fallback.
            if current is not None:
                saved = json.loads(path.read_text(encoding="utf-8"))
                same_resolver = saved.get("requested_resolvers") == (
                    [resolver] if resolver else [])
                if same_resolver and (not args.retry_existing_failures or
                                      ipv4_addresses(current)):
                    continue
            stream.write(name + "\n")
            pending[name] = rank, old_status
    print(f"{label}: {len(pending)} queries pending", file=sys.stderr, flush=True)
    received = set()
    exit_code = 0
    if pending:
        log_dir = output / "logs"
        log_dir.mkdir(exist_ok=True)
        command = ["zdns", "A", f"--input-file={input_path}",
                   f"--threads={args.threads}",
                   f"--go-processes={args.go_processes}",
                   f"--timeout={args.timeout}",
                   f"--per-ip-ns-rate-limit={args.per_ns_qps}",
                   f"--per-name-ns-rate-limit={args.per_ns_qps}", "--quiet"]
        if resolver is None:
            command.append("--iterative")
        else:
            command.append(f"--name-servers={resolver}")
        log_path = log_dir / f"a_{label}.stderr.log"
        with log_path.open("w", encoding="utf-8") as log, \
             subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log,
                              text=True, bufsize=1) as proc:
            try:
                for line in proc.stdout:
                    result = json.loads(line)
                    name = result["name"].rstrip(".").lower()
                    if name not in pending or name in received or not isinstance(
                            result.get("results", {}).get("A"), dict):
                        raise ValueError(f"Unexpected or invalid {label} result: {name}")
                    rank, old_status = pending[name]
                    result["rank"] = rank
                    result["measurement"] = ("iterative_A_retry" if resolver is None
                                             else "recursive_A_fallback")
                    result["resolver_label"] = label
                    result["requested_resolvers"] = [resolver] if resolver else []
                    result["iterative_a_status"] = old_status
                    result["measured_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
                    folder = folder_for(output, rank, name, 7)
                    folder.mkdir(parents=True, exist_ok=True)
                    save(folder / filename, result)
                    received.add(name)
                    if len(received) % 100 == 0:
                        print(f"{label} A saved {len(received)}/{len(pending)}",
                              file=sys.stderr, flush=True)
            except BaseException:
                proc.terminate()
                proc.wait()
                raise
            exit_code = proc.wait()
        if exit_code != 0 or len(received) != len(pending):
            try:
                error_tail = log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
            except OSError:
                error_tail = "(error log unreadable)"
            raise RuntimeError(
                f"{label}: ZDNS exited {exit_code}; received {len(received)}/"
                f"{len(pending)} outputs. See {log_path}.\n{error_tail}")
    return {"pending": len(pending), "received": len(received),
            "zdns_exit_code": exit_code, "resolver": resolver}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--iterative", action="store_true",
                      help="Retry selected A records by iterative resolution")
    mode.add_argument("--public-ns", action="store_true",
                      help="Try Google 8.8.8.8, then Cloudflare 1.1.1.1")
    parser.add_argument("--output", type=Path, default=Path("/work/result"))
    parser.add_argument("--input-list", type=Path,
                        help="JSONL rank/domain list; query only names in this file")
    parser.add_argument("--google-resolver", default="8.8.8.8")
    parser.add_argument("--cloudflare-resolver", default="1.1.1.1")
    parser.add_argument("--threads", type=int, default=64)
    parser.add_argument("--go-processes", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--per-ns-qps", type=int, default=100)
    parser.add_argument("--include-nxdomain", action="store_true",
                        help="Also check names reported NXDOMAIN by the iterative scan")
    parser.add_argument("--retry-existing-failures", action="store_true",
                        help="Requery saved fallback responses with no IPv4 address")
    args = parser.parse_args()
    if min(args.threads, args.go_processes, args.timeout, args.per_ns_qps) < 1:
        parser.error("Threads, processes, timeout, and rate must be positive")
    if args.public_ns:
        for resolver in (args.google_resolver, args.cloudflare_resolver):
            try:
                ipaddress.ip_address(resolver)
            except ValueError:
                parser.error(f"Resolver must be a literal IP address: {resolver!r}")
    args.output.mkdir(parents=True, exist_ok=True)
    if args.input_list is not None:
        selected = list(candidates_from_list(args.output, args.input_list))
    else:
        selected = list(candidates_from_db(args.output, args.include_nxdomain))
    candidates = [(rank, name, old_status) for rank, name, old_status in selected
                  if not ipv4_addresses(read_detail(
                      folder_for(args.output, rank, name, 7) / "a.json", name))]
    print(f"Selected {len(selected)}; A without IPv4: {len(candidates)}",
          file=sys.stderr, flush=True)
    if args.iterative:
        stages = {"iterative_retry": run_stage(args.output, candidates, args,
                                                "iterative_retry", None)}
        chosen_mode = "iterative"
    else:
        google = run_stage(args.output, candidates, args, "google",
                           args.google_resolver)
        google_recovered, google_failed = google_report(args.output, candidates)
        save(args.output / "a_google_summary.json", {
            "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "candidate_domains": len(candidates),
            "attempted_this_run": google["pending"],
            "received_this_run": google["received"],
            "recovered_ipv4": google_recovered,
            "without_ipv4": google_failed, "zdns_exit_code": google["zdns_exit_code"],
            "resolver": args.google_resolver})
        print(f"Google: {google_recovered} with IPv4; {google_failed} remaining",
              file=sys.stderr, flush=True)
        cloudflare = run_stage(args.output, candidates, args, "cloudflare",
                               args.cloudflare_resolver)
        stages = {"google": google, "cloudflare": cloudflare}
        chosen_mode = "public-ns"
    changed = promote(args.output, candidates, chosen_mode)
    reconcile_db(args.output, selected)
    recovered, failures, sources = final_report(args.output, selected, chosen_mode)
    save(args.output / "a_fallback_summary.json", {
        "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "mode": chosen_mode, "selected_domains": len(selected),
        "candidate_domains": len(candidates), "stages": stages,
        "overwritten_a_files": changed, "with_ipv4": recovered,
        "sources": sources, "without_ipv4": failures})
    print(f"A retry complete: {changed} a.json files replaced; "
          f"{failures} selected domains still without IPv4. See "
          f"{args.output / 'a_fallback_status.jsonl'}", file=sys.stderr, flush=True)
    return int(any(stage["zdns_exit_code"] != 0 or
                   stage["received"] != stage["pending"]
                   for stage in stages.values()))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted; saved per-domain results can be resumed", file=sys.stderr)
        sys.exit(130)
    except (OSError, ValueError, RuntimeError, sqlite3.DatabaseError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
