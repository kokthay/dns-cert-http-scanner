#!/usr/bin/env python3
"""Resolve every NS hostname from saved NS answers to observed A and AAAA addresses."""

import argparse
import datetime as dt
import ipaddress
import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from collect import NAME_RE, failure_file, folder_for, save, status_of


RETRY_STATES = {"TIMEOUT", "SERVFAIL", "ERROR", "MISSING_RESULT", "MISSING_OUTPUT"}


def normalize_ns(value):
    if not isinstance(value, str):
        return None
    name = value.rstrip(".").lower()
    return name if NAME_RE.fullmatch(name) else None


def read_ns(path, domain):
    try:
        item = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(item, dict) or item.get("name", "").rstrip(".").lower() != domain:
            return "INVALID_NS_FILE", []
        detail = item["results"]["NS"]
        if not isinstance(detail, dict):
            return "INVALID_NS_FILE", []
        state = detail.get("status", "UNKNOWN")
        if state != "NOERROR":
            return str(state), []
        data = detail.get("data") or {}
        if not isinstance(data, dict):
            return "INVALID_NS_FILE", []
        answers = data.get("answers") or []
        if not isinstance(answers, list):
            return "INVALID_NS_FILE", []
        ns_answers = [answer for answer in answers
                      if isinstance(answer, dict) and answer.get("type") == "NS"]
        hosts = [normalize_ns(answer.get("answer", answer.get("ns")))
                 for answer in ns_answers]
        if any(host is None for host in hosts):
            return "INVALID_NS_ANSWER", sorted(set(host for host in hosts if host))
        return "NOERROR", sorted(set(hosts))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return "MISSING_NS_FILE" if not path.exists() else "INVALID_NS_FILE", []


def connect_cache(output):
    conn = sqlite3.connect(output / "ns_ips.sqlite3")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("CREATE TABLE IF NOT EXISTS domain_index ("
                 "rank INTEGER PRIMARY KEY, domain TEXT NOT NULL, ns_status TEXT NOT NULL, "
                 "ns_names TEXT NOT NULL, materialized INTEGER NOT NULL DEFAULT 0, "
                 "result_status TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS domain_ns ("
                 "rank INTEGER NOT NULL, host TEXT NOT NULL, PRIMARY KEY(rank,host))")
    conn.execute("CREATE INDEX IF NOT EXISTS domain_ns_host_idx ON domain_ns(host)")
    conn.execute("CREATE TABLE IF NOT EXISTS ns_hosts ("
                 "host TEXT PRIMARY KEY, a_json TEXT, aaaa_json TEXT, "
                 "a_status TEXT, aaaa_status TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS run_pending (host TEXT PRIMARY KEY)")
    return conn


def index_nameservers(source, cache, output, width, progress_seconds):
    indexed = changed = 0
    last = time.monotonic()
    rows = source.execute("SELECT rank,name FROM domains ORDER BY rank")
    try:
        for rank, domain in rows:
            path = folder_for(output, rank, domain, width) / "ns.json"
            ns_status, names = read_ns(path, domain)
            encoded = json.dumps(names, separators=(",", ":"))
            old = cache.execute("SELECT domain,ns_status,ns_names FROM domain_index "
                                "WHERE rank=?", (rank,)).fetchone()
            if old is not None and old[0] != domain:
                raise ValueError(f"NS cache rank {rank} belongs to {old[0]!r}, "
                                 f"not {domain!r}; use the original input")
            if old != (domain, ns_status, encoded):
                cache.execute("INSERT INTO domain_index(rank,domain,ns_status,ns_names,"
                              "materialized,result_status) VALUES (?,?,?,?,0,NULL) "
                              "ON CONFLICT(rank) DO UPDATE SET "
                              "domain=excluded.domain,ns_status=excluded.ns_status,"
                              "ns_names=excluded.ns_names,materialized=0,result_status=NULL",
                              (rank, domain, ns_status, encoded))
                cache.execute("DELETE FROM domain_ns WHERE rank=?", (rank,))
                cache.executemany("INSERT INTO domain_ns(rank,host) VALUES (?,?)",
                                  ((rank, host) for host in names))
                cache.executemany("INSERT OR IGNORE INTO ns_hosts(host) VALUES (?)",
                                  ((host,) for host in names))
                changed += 1
            elif not (path.parent / "ns_ips.json").is_file():
                cache.execute("UPDATE domain_index SET materialized=0 "
                              "WHERE rank=? AND materialized!=0", (rank,))
            indexed += 1
            if indexed % 1000 == 0:
                cache.commit()
            if time.monotonic() - last >= progress_seconds:
                print(f"NS indexing: {indexed} domains, {changed} changed",
                      file=sys.stderr, flush=True)
                last = time.monotonic()
    finally:
        rows.close()
    cache.commit()
    if cache.execute("SELECT COUNT(*) FROM domain_index").fetchone()[0] != indexed:
        raise ValueError("Existing NS address cache belongs to a different input set; "
                         "choose a new output directory or remove ns_ips.sqlite3")
    print(f"NS indexing complete: {indexed} domains, {changed} changed", file=sys.stderr)
    return indexed


def write_pending(cache, output, retry_failed):
    cache.execute("DELETE FROM run_pending")
    pending = output / "ns-ip-pending.txt"
    condition = ("a_status IS NULL OR aaaa_status IS NULL OR "
                 "a_status IN ('MISSING_RESULT','MISSING_OUTPUT') OR "
                 "aaaa_status IN ('MISSING_RESULT','MISSING_OUTPUT')")
    if retry_failed:
        condition += " OR a_status IN ({0}) OR aaaa_status IN ({0})".format(
            ",".join("?" for _ in RETRY_STATES))
        params = tuple(sorted(RETRY_STATES)) * 2
    else:
        params = ()
    count = 0
    with pending.open("w", encoding="utf-8") as stream:
        for host, in cache.execute("SELECT host FROM ns_hosts WHERE (" + condition +
                                   ") AND EXISTS (SELECT 1 FROM domain_ns WHERE "
                                   "domain_ns.host=ns_hosts.host) ORDER BY host", params):
            stream.write(host + "\n")
            cache.execute("INSERT INTO run_pending(host) VALUES (?)", (host,))
            count += 1
            if count % 1000 == 0:
                cache.commit()
    cache.commit()
    print(f"Distinct NS hostnames to query: {count}", file=sys.stderr, flush=True)
    return pending, count


def run_zdns(cache, output, input_path, count, args):
    if not count:
        return {"requested": 0, "received": 0, "missing": 0, "exit_code": 0}
    config = output / "ns-ip-multiple.ini"
    config.write_text("[Application Options]\niterative=true\n[A]\n[AAAA]\n",
                      encoding="utf-8")
    log_dir = output / "logs"
    log_dir.mkdir(exist_ok=True)
    log_path = log_dir / "ns_ips.stderr.log"
    command = ["zdns", "MULTIPLE", f"--multi-config-file={config}",
               f"--input-file={input_path}", f"--threads={args.threads}",
               f"--go-processes={args.go_processes}", f"--timeout={args.timeout}",
               f"--per-ip-ns-rate-limit={args.per_ns_qps}",
               f"--per-name-ns-rate-limit={args.per_ns_qps}", "--quiet"]
    received = 0
    last = time.monotonic()
    invalidate = bool(cache.execute(
        "SELECT 1 FROM domain_index WHERE materialized=1 LIMIT 1").fetchone())
    with log_path.open("w", encoding="utf-8") as log, \
         subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log,
                          text=True, bufsize=1) as proc:
        try:
            for line in proc.stdout:
                try:
                    result = json.loads(line)
                    host = normalize_ns(result["name"])
                    details = result["results"]
                    if not host or not isinstance(details, dict):
                        raise ValueError("invalid ZDNS result")
                except (ValueError, TypeError, KeyError) as exc:
                    raise ValueError(f"Invalid NS address output: {line[:300]}") from exc
                if not cache.execute("SELECT 1 FROM run_pending WHERE host=?",
                                     (host,)).fetchone():
                    raise ValueError(f"Unexpected or duplicate NS hostname: {host}")
                a, aaaa = (details.get("A"), details.get("AAAA"))
                states = [status_of(d) if isinstance(d, dict) else "MISSING_RESULT"
                          for d in (a, aaaa)]
                cache.execute("UPDATE ns_hosts SET a_json=?,aaaa_json=?,"
                              "a_status=?,aaaa_status=? WHERE host=?",
                              (json.dumps(a) if isinstance(a, dict) else None,
                               json.dumps(aaaa) if isinstance(aaaa, dict) else None,
                               states[0], states[1], host))
                cache.execute("DELETE FROM run_pending WHERE host=?", (host,))
                if invalidate:
                    cache.execute("UPDATE domain_index SET materialized=0 "
                                  "WHERE rank IN (SELECT rank FROM domain_ns WHERE host=?)",
                                  (host,))
                received += 1
                if received % 250 == 0:
                    cache.commit()
                if time.monotonic() - last >= args.progress_seconds:
                    print(f"NS A+AAAA saved: {received}/{count} distinct hosts",
                          file=sys.stderr, flush=True)
                    last = time.monotonic()
        except BaseException:
            cache.commit()
            proc.terminate()
            proc.wait()
            raise
        exit_code = proc.wait()
    cache.commit()
    missing = cache.execute("SELECT COUNT(*) FROM run_pending").fetchone()[0]
    if exit_code or missing:
        error_tail = log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
        raise RuntimeError(f"NS lookup stopped: ZDNS exit {exit_code}, received "
                           f"{received}/{count}, missing {missing}. See {log_path}.\n"
                           f"{error_tail}")
    print(f"NS A+AAAA complete: {received}/{count} distinct hosts", file=sys.stderr)
    return {"requested": count, "received": received, "missing": missing,
            "exit_code": exit_code}


def addresses(payload, family):
    if not payload:
        return []
    detail = json.loads(payload)
    if detail.get("status") != "NOERROR":
        return []
    data = detail.get("data") or {}
    found = set()
    for item in data.get("answers") or []:
        if not isinstance(item, dict) or item.get("type") != family:
            continue
        try:
            ip = ipaddress.ip_address(item.get("answer"))
        except (ValueError, TypeError):
            continue
        if ip.version == (4 if family == "A" else 6):
            found.add(str(ip))
    return sorted(found, key=lambda value: int(ipaddress.ip_address(value)))


def materialize(cache, output, width, progress_seconds, progress_every_domain=False):
    total = cache.execute("SELECT COUNT(*) FROM domain_index WHERE materialized=0").fetchone()[0]
    done = 0
    last = time.monotonic()
    cursor = cache.execute("SELECT rank,domain,ns_status,ns_names FROM domain_index "
                           "WHERE materialized=0 ORDER BY rank")
    try:
        for rank, domain, ns_status, ns_names in cursor:
            names = json.loads(ns_names)
            records = []
            all_v4, all_v6 = set(), set()
            problems = False
            empty_hosts = False
            for host in names:
                row = cache.execute("SELECT a_json,aaaa_json,a_status,aaaa_status "
                                    "FROM ns_hosts WHERE host=?", (host,)).fetchone()
                a_json, aaaa_json, a_state, aaaa_state = row if row else (None, None, None, None)
                v4, v6 = addresses(a_json, "A"), addresses(aaaa_json, "AAAA")
                all_v4.update(v4)
                all_v6.update(v6)
                if not v4 and not v6:
                    empty_hosts = True
                if any(state not in ("NOERROR_DATA", "NOERROR_EMPTY")
                       for state in (a_state, aaaa_state)):
                    problems = True
                records.append({"host": host, "ipv4": v4, "ipv6": v6,
                                "a_status": a_state or "MISSING_OUTPUT",
                                "aaaa_status": aaaa_state or "MISSING_OUTPUT"})
            if ns_status != "NOERROR":
                status = "NS_ERROR"
            elif not names:
                status = "NO_NAMESERVERS"
            elif problems:
                status = "LOOKUP_ERROR"
            elif not all_v4 and not all_v6:
                status = "NO_ADDRESS"
            elif empty_hosts:
                status = "PARTIAL"
            else:
                status = "OK"
            document = {"rank": rank, "domain": domain, "source": "ns.json",
                        "ns_status": ns_status, "status": status,
                        "nameservers": records,
                        "all_ipv4": sorted(all_v4, key=lambda ip: int(ipaddress.ip_address(ip))),
                        "all_ipv6": sorted(all_v6, key=lambda ip: int(ipaddress.ip_address(ip)))}
            folder = folder_for(output, rank, domain, width)
            folder.mkdir(parents=True, exist_ok=True)
            save(folder / "ns_ips.json", document)
            cache.execute("UPDATE domain_index SET materialized=1,result_status=? "
                          "WHERE rank=?", (status, rank))
            done += 1
            if progress_every_domain:
                print(f"NS addresses saved {rank:0{width}d}-{domain} ({status})",
                      file=sys.stderr, flush=True)
            if done % 250 == 0:
                cache.commit()
            if time.monotonic() - last >= progress_seconds:
                print(f"NS address files: {done}/{total}", file=sys.stderr, flush=True)
                last = time.monotonic()
    finally:
        cursor.close()
    cache.commit()
    print(f"NS address files complete: {done}/{total} written", file=sys.stderr)
    return done


def export(cache, output, count, lookup, written):
    summary = {"finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
               "domains": count, "distinct_ns_hosts": cache.execute(
                   "SELECT COUNT(DISTINCT host) FROM domain_ns").fetchone()[0],
               "lookup": lookup, "files_written_this_run": written,
               "statuses": dict(cache.execute(
                   "SELECT result_status,COUNT(*) FROM domain_index GROUP BY result_status"))}
    active = ("EXISTS (SELECT 1 FROM domain_ns WHERE domain_ns.host=ns_hosts.host)")
    for family in ("a", "aaaa"):
        summary[f"{family}_statuses"] = dict(cache.execute(
            f"SELECT {family}_status,COUNT(*) FROM ns_hosts WHERE {active} "
            f"GROUP BY {family}_status"))
    with failure_file(output, "ns_ips_host_failures.jsonl").open("w", encoding="utf-8") as stream:
        for host, a_state, aaaa_state in cache.execute(
                f"SELECT host,a_status,aaaa_status FROM ns_hosts WHERE {active} ORDER BY host"):
            for family, state in (("A", a_state), ("AAAA", aaaa_state)):
                if state not in ("NOERROR_DATA", "NOERROR_EMPTY"):
                    stream.write(json.dumps({"host": host, "type": family,
                                             "status": state or "MISSING_OUTPUT"}) + "\n")
    with (output / "ns_ips_status.jsonl").open("w", encoding="utf-8") as status_file, \
         failure_file(output, "ns_ips_failures.jsonl").open("w", encoding="utf-8") as failures:
        for rank, domain, ns_status, state in cache.execute(
                "SELECT rank,domain,ns_status,result_status FROM domain_index ORDER BY rank"):
            item = {"rank": rank, "domain": domain, "ns_status": ns_status,
                    "status": state}
            status_file.write(json.dumps(item) + "\n")
            if state != "OK":
                failures.write(json.dumps(item) + "\n")
    save(output / "ns_ips_summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("/work/result"))
    parser.add_argument("--threads", type=int, default=64)
    parser.add_argument("--go-processes", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--per-ns-qps", type=int, default=200)
    parser.add_argument("--progress-seconds", type=int, default=5)
    parser.add_argument("--progress-every-domain", action="store_true",
                        help="Print each finished ranked domain (very verbose for 1M)")
    parser.add_argument("--retry-failed", action="store_true",
                        help="Requery saved DNS errors (TIMEOUT/SERVFAIL/ERROR)")
    args = parser.parse_args()
    if min(args.threads, args.go_processes, args.timeout, args.per_ns_qps,
           args.progress_seconds) < 1:
        parser.error("Threads, CPU count, timeouts, rates and progress interval must be positive")
    source_path = args.output / "status.sqlite3"
    if not source_path.is_file():
        parser.error(f"Missing original collector database: {source_path}")
    source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
    cache = connect_cache(args.output)
    try:
        count = source.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
        width = max(7, len(str(count)))
        index_nameservers(source, cache, args.output, width, args.progress_seconds)
        pending, needed = write_pending(cache, args.output, args.retry_failed)
        lookup = run_zdns(cache, args.output, pending, needed, args)
        written = materialize(cache, args.output, width, args.progress_seconds,
                              args.progress_every_domain)
        summary = export(cache, args.output, count, lookup, written)
        print(f"NS address probe complete: {summary['statuses']}. "
              f"See {args.output / 'ns_ips_summary.json'}", file=sys.stderr)
        return int(any(state != "OK" for state in summary["statuses"]))
    finally:
        cache.close()
        source.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted; rerun with the same output directory", file=sys.stderr)
        sys.exit(130)
    except (OSError, ValueError, RuntimeError, sqlite3.DatabaseError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
