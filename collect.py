#!/usr/bin/env python3
"""Iterative ZDNS MULTIPLE scan, saving all requested records per domain."""

import argparse
import concurrent.futures
import csv
import datetime as dt
import json
import re
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

RECORD_TYPES = ("A", "AAAA", "NS", "SOA", "CNAME", "HTTPS", "SVCB",
                "TLSA", "CAA", "DNSKEY", "DS")
COLS = tuple(rr.lower() for rr in RECORD_TYPES)
TRANSIENT = {"MISSING_OUTPUT", "MISSING_RESULT"}
RETRY_STATUSES = {"SERVFAIL", "TIMEOUT", "ERROR", *TRANSIENT}
NAME_RE = re.compile(
    r"(?=^.{1,253}\.?$)^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.?$", re.I
)
STATUS_RE = re.compile(r"\b(bogus|insecure|secure)\b", re.I)


def save(path, value):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def read_domains(path):
    names = []
    seen = set()
    with path.open(encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, 1):
            name = line.strip().rstrip(".").lower()
            if not name:
                continue
            if not NAME_RE.fullmatch(name):
                raise ValueError(f"Invalid domain at line {line_number}: {line.strip()!r}")
            if name in seen:
                raise ValueError(f"Repeated domain at line {line_number}: {name}")
            seen.add(name)
            names.append(name)
    if not names:
        raise ValueError("Input file contains no domains")
    return names


def read_retry_list(path, names):
    """Read newline-delimited JSON and verify ranks against the full input."""
    selected = set()
    with path.open(encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                rank, name = item["rank"], item["domain"]
            except (ValueError, TypeError, KeyError) as exc:
                raise ValueError(f"Invalid retry list line {line_number}") from exc
            if (type(rank) is not int or rank < 1 or rank > len(names)
                    or name != names[rank - 1]):
                raise ValueError(f"Retry list line {line_number} does not match "
                                 f"the input rank/domain: {rank!r}, {name!r}")
            selected.add(rank)
    if not selected:
        raise ValueError("Retry list is empty")
    return selected


def folder_for(output, rank, name, width):
    return output / "domains" / f"{(rank - 1) // 10000:03d}" / f"{rank:0{width}d}-{name}"


def failure_file(output, filename):
    folder = output / "failures_domians"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / filename


def status_of(detail):
    status = detail.get("status", "UNKNOWN")
    if status == "NOERROR":
        data = detail.get("data")
        return "NOERROR_DATA" if isinstance(data, dict) and data.get("answers") else "NOERROR_EMPTY"
    return status


def recover_status(path, rrtype):
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
        detail = result["results"][rrtype]
        return status_of(detail) if isinstance(detail, dict) else None
    except (OSError, ValueError, TypeError, KeyError):
        return None


def connect_db(output, names):
    conn = sqlite3.connect(output / "status.sqlite3")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    fields = ", ".join(f"{col} TEXT" for col in COLS)
    conn.execute(f"CREATE TABLE IF NOT EXISTS domains "
                 f"(rank INTEGER PRIMARY KEY, name TEXT UNIQUE, {fields}, dnssec TEXT)")
    with conn:
        conn.executemany("INSERT OR IGNORE INTO domains(rank,name) VALUES (?,?)",
                         ((rank, name) for rank, name in enumerate(names, 1)))
    if conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0] != len(names):
        raise ValueError("Existing results use a different input; choose a new output directory")
    for existing, expected in zip(conn.execute("SELECT rank,name FROM domains ORDER BY rank"),
                                  enumerate(names, 1)):
        if existing != expected:
            raise ValueError("Input order changed; choose a new output directory")
    return conn


def write_inputs(conn, output, width, retry_failed, retry_ranks=None):
    """Create one line per domain needing work; trigger only the missing modules."""
    config = output / "multiple.ini"
    config.write_text("[Application Options]\niterative=true\n" +
                      "".join(f"[{rr}]\ntrigger = \"{rr.lower()}-trigger\"\n"
                              for rr in RECORD_TYPES), encoding="utf-8")
    pending = output / ("retry-pending-domains.csv" if retry_ranks is not None
                        else "pending-domains.csv")
    manifest = output / ("retry_manifest.csv" if retry_ranks is not None
                         else "manifest.csv")
    record_domains = dnssec_only = recovered = 0
    fields = "rank,name," + ",".join(COLS) + ",dnssec"
    with pending.open("w", encoding="utf-8") as requests, \
         manifest.open("w", newline="", encoding="utf-8") as listing:
        writer = csv.writer(listing)
        writer.writerow(("rank", "domain"))
        for rank, name, *states in conn.execute(f"SELECT {fields} FROM domains ORDER BY rank"):
            if retry_ranks is not None and rank not in retry_ranks:
                continue
            writer.writerow((rank, name))
            folder = folder_for(output, rank, name, width)
            needed = []
            for rr, state in zip(RECORD_TYPES, states[:-1]):
                path = folder / f"{rr.lower()}.json"
                if not path.is_file() or state is None or state in TRANSIENT:
                    # A crash may leave a complete file ahead of the SQLite commit.
                    if path.is_file() and (state is None or state in TRANSIENT):
                        restored = recover_status(path, rr)
                        if restored is not None:
                            conn.execute(f"UPDATE domains SET {rr.lower()}=? WHERE rank=?",
                                         (restored, rank))
                            recovered += 1
                            if retry_ranks is not None and restored in RETRY_STATUSES:
                                needed.append(rr)
                            continue
                    needed.append(rr)
                elif retry_ranks is not None and state in RETRY_STATUSES:
                    needed.append(rr)
                elif retry_ranks is None and retry_failed and state not in ("NOERROR_DATA", "NOERROR_EMPTY"):
                    needed.append(rr)
            if needed:
                requests.write(name + ",," +
                               ",".join(rr.lower() + "-trigger" for rr in needed) + "\n")
                record_domains += 1
            if states[-1] is not None and not (folder / "dnssec.json").is_file():
                conn.execute("UPDATE domains SET dnssec=NULL WHERE rank=?", (rank,))
                states[-1] = None
            if not needed and (states[-1] is None or
                               (retry_ranks is not None and states[-1] == "indeterminate")):
                dnssec_only += 1
            if rank % 1000 == 0:
                conn.commit()
    conn.commit()
    return record_domains, dnssec_only, recovered


def validate_dnssec(name, folder, anchor, timeout):
    command = ["unbound-host", "-v", "-f", str(anchor), "-t", "SOA", name]
    try:
        run = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        matches = [match.lower() for match in STATUS_RE.findall(run.stdout + "\n" + run.stderr)]
        state = matches[0] if matches and len(set(matches)) == 1 else "indeterminate"
        if run.returncode != 0 and state != "bogus":
            state = "indeterminate"
        data = {"name": name, "query_type": "SOA", "state": state,
                "secure": int(state == "secure"), "exit_code": run.returncode,
                "stdout": run.stdout, "stderr": run.stderr}
        if state == "indeterminate":
            data["reason"] = "No unambiguous validation result; inspect validator output"
    except subprocess.TimeoutExpired:
        data = {"name": name, "query_type": "SOA", "state": "indeterminate",
                "secure": 0, "reason": f"Validator timed out after {timeout}s"}
    folder.mkdir(parents=True, exist_ok=True)
    save(folder / "dnssec.json", data)
    return data["state"]


class Progress:
    def __init__(self, output, interval, total, queued, record_queued):
        self.output = output
        self.interval = interval
        self.total = total
        self.queued = queued
        self.record_queued = record_queued
        self.records = 0
        self.completed = 0
        self.inflight = 0
        self.last = "waiting for first ZDNS response"
        self.started = time.monotonic()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def update(self, label, increment=0, record_increment=0, inflight_diff=0,
               immediate=False):
        with self.lock:
            self.last = label
            self.completed += increment
            self.records += record_increment
            self.inflight += inflight_diff
            if immediate:
                self._print()

    def _print(self):
        elapsed = int(time.monotonic() - self.started)
        print(f"[{elapsed}s] records {self.records}/{self.record_queued} | "
              f"fully complete {self.completed}/{self.queued} queued "
              f"({self.total} input) | DNSSEC active {self.inflight} | "
              f"{self.last}", file=sys.stderr, flush=True)

    def _loop(self):
        while not self.stop.wait(self.interval):
            with self.lock:
                self._print()

    def close(self):
        self.stop.set()
        self.thread.join()
        with self.lock:
            self._print()


def process_result(result, conn, output, width, progress, each, retry_failed,
                   retry_ranks=None):
    name = result["name"].rstrip(".").lower()
    row = conn.execute("SELECT " + "rank," + ",".join(COLS) +
                       ",dnssec FROM domains WHERE name=?", (name,)).fetchone()
    if row is None:
        raise ValueError(f"Unexpected output domain: {name}")
    rank, *states = row
    folder = folder_for(output, rank, name, width)
    details = result.get("results")
    if not isinstance(details, dict):
        raise ValueError(f"Invalid results object: {name}")
    label = f"{rank:0{width}d}-{name}"
    progress.update(f"writing records for {label}", immediate=each)
    folder.mkdir(parents=True, exist_ok=True)
    for index, rr in enumerate(RECORD_TYPES):
        detail = details.get(rr)
        if detail is None:
            old = states[index]
            path = folder / f"{rr.lower()}.json"
            if old is None or old in TRANSIENT or not path.is_file():
                save(path, {"name": name, "rrtype": rr,
                            "error": "Module result absent from ZDNS MULTIPLE output; retry on next run"})
                conn.execute(f"UPDATE domains SET {rr.lower()}=? WHERE rank=?",
                             ("MISSING_RESULT", rank))
            continue
        if not isinstance(detail, dict):
            raise ValueError(f"Invalid {rr} result: {name}")
        path = folder / f"{rr.lower()}.json"
        old = states[index]
        if old in ("NOERROR_DATA", "NOERROR_EMPTY") and path.is_file():
            continue
        if old not in (None, *TRANSIENT) and path.is_file() and not retry_failed \
                and retry_ranks is None:
            continue
        payload = {key: value for key, value in result.items() if key != "results"}
        payload["results"] = {rr: detail}
        save(path, payload)
        conn.execute(f"UPDATE domains SET {rr.lower()}=? WHERE rank=?",
                     (status_of(detail), rank))
    needs_validation = (states[-1] is None or
                        not (folder / "dnssec.json").is_file() or
                        (retry_ranks is not None and states[-1] == "indeterminate"))
    # Record files are complete and durable before the parallel DNSSEC task starts.
    conn.commit()
    progress.update(f"saved records for {label}", record_increment=1,
                    increment=int(not needs_validation), immediate=each)
    if progress.records % 1000 == 0:
        save(output / ("retry_progress.json" if retry_ranks is not None else "progress.json"),
             {"last_records_rank": rank, "last_records_domain": name,
              "records_saved_this_run": progress.records,
              "fully_completed_this_run": progress.completed,
              "requested_this_run": progress.queued})
    return rank, name, folder if needs_validation else None


def drain_validations(futures, conn, progress, each, block):
    if not futures:
        return
    if block:
        done, _ = concurrent.futures.wait(futures,
                    return_when=concurrent.futures.FIRST_COMPLETED)
    else:
        done = [future for future in futures if future.done()]
    for future in done:
        rank, name, width = futures[future]
        state = future.result()
        conn.execute("UPDATE domains SET dnssec=? WHERE rank=?", (state, rank))
        conn.commit()
        progress.update(f"fully finished {rank:0{width}d}-{name} "
                        f"(DNSSEC {state})", increment=1, inflight_diff=-1,
                        immediate=each)
        del futures[future]


def scan(conn, output, width, args, count, progress, pool):
    log_dir = output / "logs"
    log_dir.mkdir(exist_ok=True)
    log_path = log_dir / ("retry.stderr.log" if args.retry_list else "multiple.stderr.log")
    command = ["zdns", "MULTIPLE",
               f"--multi-config-file={output / 'multiple.ini'}",
               f"--input-file={output / ('retry-pending-domains.csv' if args.retry_list else 'pending-domains.csv')}",
               f"--threads={args.threads}", f"--go-processes={args.go_processes}",
               f"--timeout={args.timeout}",
               f"--per-ip-ns-rate-limit={args.per_ns_qps}",
               f"--per-name-ns-rate-limit={args.per_ns_qps}", "--quiet"]
    received = set()
    errors = []
    futures = {}
    with log_path.open("w", encoding="utf-8") as log, \
         subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log,
                          text=True, bufsize=1) as proc:
        try:
            for line in proc.stdout:
                try:
                    result = json.loads(line)
                    name = result["name"].rstrip(".").lower()
                    if name in received:
                        raise ValueError(f"Duplicate ZDNS output: {name}")
                    if len(received) >= count:
                        raise ValueError(f"Extra ZDNS output: {name}")
                except (ValueError, KeyError, TypeError, AttributeError) as exc:
                    if len(errors) < 20:
                        errors.append(f"{exc}: {line.strip()[:200]}")
                    continue
                rank, name, folder = process_result(result, conn, output, width,
                                  progress, args.progress_every_domain,
                                  args.retry_failed, args.retry_ranks)
                received.add(name)
                if folder is not None:
                    future = pool.submit(validate_dnssec, name, folder, args.anchor,
                                         args.validation_timeout)
                    futures[future] = rank, name, width
                    progress.update(f"DNSSEC queued for {rank:0{width}d}-{name}",
                                    inflight_diff=1)
                drain_validations(futures, conn, progress,
                                  args.progress_every_domain,
                                  block=len(futures) >= args.validation_workers * 4)
            while futures:
                drain_validations(futures, conn, progress,
                                  args.progress_every_domain, block=True)
        except BaseException:
            proc.terminate()
            proc.wait()
            raise
        exit_code = proc.wait()
    if not received:
        if args.retry_ranks is not None:
            export_status(conn, output, width, args.retry_ranks)
        raise RuntimeError(f"ZDNS produced no usable results (exit {exit_code}); "
                           f"inspect {log_path}. Existing files and statuses were preserved.")
    progress.update("checking missing ZDNS responses", immediate=True)
    # Mark missing output as retryable, without overwriting any good existing files.
    missing = 0
    for name, in conn.execute("SELECT name FROM domains ORDER BY rank"):
        if args.retry_ranks is not None and name not in args.retry_names:
            continue
        if name in received:
            continue
        row = conn.execute("SELECT rank," + ",".join(COLS) +
                           " FROM domains WHERE name=?", (name,)).fetchone()
        rank, *states = row
        folder = folder_for(output, rank, name, width)
        for rr, state in zip(RECORD_TYPES, states):
            if state is None or state in TRANSIENT:
                path = folder / f"{rr.lower()}.json"
                restored = recover_status(path, rr) if path.is_file() else None
                if restored is not None:
                    conn.execute(f"UPDATE domains SET {rr.lower()}=? WHERE rank=?",
                                 (restored, rank))
                    continue
                conn.execute(f"UPDATE domains SET {rr.lower()}=? WHERE rank=?",
                             ("MISSING_OUTPUT", rank))
                missing += 1
        if rank % 1000 == 0:
            conn.commit()
    conn.commit()
    return {"exit_code": exit_code, "requested_domains": count,
            "received_domains": len(received), "missing_records": missing,
            "unexpected_output": errors, "stderr_file": str(log_path.relative_to(output))}


def validate_pending(conn, output, width, args, progress, pool):
    if args.retry_ranks is None:
        remaining = conn.execute(
            "SELECT COUNT(*) FROM domains WHERE dnssec IS NULL").fetchone()[0]
        rows = conn.execute("SELECT rank,name FROM domains WHERE dnssec IS NULL ORDER BY rank")
    else:
        rows = []
        for rank in sorted(args.retry_ranks):
            name, state = conn.execute("SELECT name,dnssec FROM domains WHERE rank=?",
                                       (rank,)).fetchone()
            if state in (None, "indeterminate") and name not in args.retry_record_names:
                rows.append((rank, name))
        remaining = len(rows)
    if remaining:
        print(f"Validating DNSSEC for {remaining} domains without a result ...",
              file=sys.stderr, flush=True)
    futures = {}
    for rank, name in rows:
        folder = folder_for(output, rank, name, width)
        label = f"{rank:0{width}d}-{name}"
        future = pool.submit(validate_dnssec, name, folder, args.anchor,
                             args.validation_timeout)
        futures[future] = rank, name, width
        progress.update(f"DNSSEC queued for {label}", inflight_diff=1,
                        immediate=args.progress_every_domain)
        drain_validations(futures, conn, progress, args.progress_every_domain,
                          block=len(futures) >= args.validation_workers * 4)
    while futures:
        drain_validations(futures, conn, progress, args.progress_every_domain,
                          block=True)


def export_status(conn, output, width, retry_ranks=None):
    issue_count = 0
    fields = "rank,name," + ",".join(COLS) + ",dnssec"
    status_path = output / ("retry_domain_status.csv" if retry_ranks is not None
                            else "domain_status.csv")
    failure_path = failure_file(output, "retry_failures.jsonl" if retry_ranks is not None
                                else "failures.jsonl")
    with status_path.open("w", newline="", encoding="utf-8") as stream, \
         failure_path.open("w", encoding="utf-8") as failures:
        writer = csv.writer(stream)
        writer.writerow(("rank", "domain", "folder", *COLS, "dnssec", "overall"))
        for rank, name, *states in conn.execute(f"SELECT {fields} FROM domains ORDER BY rank"):
            if retry_ranks is not None and rank not in retry_ranks:
                continue
            overall = "ok"
            for rr, state in zip(RECORD_TYPES, states[:-1]):
                if state not in ("NOERROR_DATA", "NOERROR_EMPTY"):
                    overall = "failed"
                    failures.write(json.dumps({"rank": rank, "domain": name,
                                               "type": rr, "status": state}) + "\n")
                    issue_count += 1
            if states[-1] in ("bogus", "indeterminate", None):
                overall = "failed"
                failures.write(json.dumps({"rank": rank, "domain": name,
                                           "type": "DNSSEC", "status": states[-1]}) + "\n")
                issue_count += 1
            writer.writerow((rank, name, str(folder_for(output, rank, name, width).relative_to(output)),
                             *states, overall))
    return issue_count


def run_ns_probe(args):
    """Run the resumable NS address stage after releasing collector resources."""
    command = [sys.executable, str(Path(__file__).resolve().with_name("ns_ips.py")),
               "--output", str(args.output), "--threads", str(args.threads),
               "--go-processes", str(args.go_processes),
               "--timeout", str(args.timeout), "--per-ns-qps", str(args.per_ns_qps),
               "--progress-seconds", str(args.progress_seconds)]
    if args.progress_every_domain:
        command.append("--progress-every-domain")
    if args.retry_failed:
        command.append("--retry-failed")
    print("Starting NS address stage (iterative A + AAAA for saved NS hostnames)",
          file=sys.stderr, flush=True)
    code = subprocess.run(command).returncode
    return code if code >= 0 else 128 - code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("/work/domains.txt"))
    parser.add_argument("--output", type=Path, default=Path("/work/result"))
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("--go-processes", type=int, default=2,
                        help="Maximum CPU cores used by the ZDNS Go runtime")
    parser.add_argument("--per-ns-qps", type=int, default=200,
                        help="Limit per nameserver IP/name; not total outgoing queries per second")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--validation-timeout", type=int, default=30)
    parser.add_argument("--validation-workers", type=int, default=2,
                        help="Concurrent Unbound DNSSEC checks; bounded to 4x this many queued")
    parser.add_argument("--progress-seconds", type=int, default=5)
    parser.add_argument("--progress-every-domain", action="store_true",
                        help="Print each current/finished domain (very verbose for 1M names)")
    parser.add_argument("--retry-failed", action="store_true",
                        help="Requery saved DNS error statuses in addition to missing results")
    parser.add_argument("--retry-list", type=Path,
                        help="JSONL rank/domain list; retry only selected domains' transient "
                             "DNS statuses and indeterminate DNSSEC")
    parser.add_argument("--with-ns-ips", action="store_true",
                        help="After the main scan, resolve saved NS hostnames to A and AAAA "
                             "using the same lookup settings; covers all saved domains")
    parser.add_argument("--anchor", type=Path, default=Path("/usr/share/dns/root.key"))
    args = parser.parse_args()
    if min(args.threads, args.go_processes, args.per_ns_qps, args.timeout,
           args.validation_timeout, args.validation_workers, args.progress_seconds) < 1:
        parser.error("Thread counts, CPU count, rates, and timeouts must be positive")
    if not args.anchor.is_file() or not args.anchor.stat().st_size:
        parser.error(f"DNSSEC root trust anchor missing: {args.anchor}")
    names = read_domains(args.input)
    args.retry_ranks = read_retry_list(args.retry_list, names) if args.retry_list else None
    args.retry_names = ({names[rank - 1] for rank in args.retry_ranks}
                        if args.retry_ranks is not None else None)
    args.output.mkdir(parents=True, exist_ok=True)
    width = max(7, len(str(len(names))))
    conn = connect_db(args.output, names)
    queued, dnssec_only, recovered = write_inputs(conn, args.output, width,
                                                  args.retry_failed, args.retry_ranks)
    args.retry_record_names = ({line.split(",", 1)[0] for line in
                               (args.output / "retry-pending-domains.csv").read_text(
                                   encoding="utf-8").splitlines()}
                               if args.retry_ranks is not None else None)
    print(f"Input {len(names)} | domains needing records {queued} | "
          f"DNSSEC-only {dnssec_only} | recovered saved records {recovered}",
          file=sys.stderr, flush=True)
    progress = Progress(args.output, args.progress_seconds,
                        len(args.retry_ranks) if args.retry_ranks is not None else len(names),
                        queued + dnssec_only, queued)
    try:
        report = {"exit_code": 0, "requested_domains": 0, "received_domains": 0,
                  "missing_records": 0, "unexpected_output": []}
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=args.validation_workers) as pool:
            if queued:
                report = scan(conn, args.output, width, args, queued, progress, pool)
            if report["exit_code"] or report["missing_records"]:
                print("ZDNS did not finish every requested domain; deferring "
                      "DNSSEC-only work until the missing records are retried.",
                      file=sys.stderr, flush=True)
            else:
                validate_pending(conn, args.output, width, args, progress, pool)
        progress.update("exporting ordered status and failure reports", immediate=True)
        issues = export_status(conn, args.output, width, args.retry_ranks)
        dnssec_counts = dict(conn.execute("SELECT dnssec, COUNT(*) FROM domains GROUP BY dnssec"))
        save(args.output / ("retry_summary.json" if args.retry_list else "summary.json"),
             {"finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "domain_count": len(args.retry_ranks) if args.retry_ranks is not None else len(names),
              "record_types": list(RECORD_TYPES),
              "scan": report, "dnssec_counts": dnssec_counts, "failure_event_count": issues})
        save(args.output / ("retry_progress.json" if args.retry_list else "progress.json"),
             {"last_run_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "queued": queued, "received": report["received_domains"],
              "missing_records": report["missing_records"],
              "dnssec_counts": dnssec_counts})
        print(f"Finished. Status: {args.output / ('retry_domain_status.csv' if args.retry_list else 'domain_status.csv')}; "
              f"issues: {issues}", file=sys.stderr, flush=True)
        result_code = int(bool(report["exit_code"] or report["unexpected_output"] or issues))
    finally:
        progress.close()
        conn.close()
    if args.with_ns_ips:
        if report["exit_code"] or report["missing_records"] or report["unexpected_output"]:
            print("NS address stage deferred: the main ZDNS process did not finish "
                  "cleanly. Rerun the same command to resume.", file=sys.stderr, flush=True)
            return 1
        result_code = max(result_code, run_ns_probe(args))
    return result_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted; rerun with the same input/output to resume", file=sys.stderr)
        sys.exit(130)
    except (OSError, ValueError, RuntimeError, sqlite3.DatabaseError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
