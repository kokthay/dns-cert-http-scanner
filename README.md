# Iterative ZDNS collector

This collector reads one domain per line from `domains.txt`. It runs ZDNS
`MULTIPLE` with `iterative=true` to request A, AAAA, NS, SOA, CNAME, HTTPS,
SVCB, TLSA, CAA, DNSKEY and DS. It then runs `unbound-host` to classify a
DNSSEC SOA validation as secure, insecure, bogus or indeterminate.

ZDNS remains one long-running process across the pending domains, so its
iterative cache can be reused. It performs the selected record queries for
each domain in the same MULTIPLE task. The collector writes and commits all
returned record files for a domain before reading the next ZDNS response.
DNSSEC checks for different domains run concurrently in a bounded pool, and
their statuses are committed as they finish. With multiple ZDNS threads,
domains **finish out of input order**. The rank in the folder always comes
from the original input line.

## Included tools and features

| Tool | Features |
| --- | --- |
| `collect.py` | Iterative A, AAAA, NS, SOA, CNAME, HTTPS, SVCB, TLSA, CAA, DNSKEY and DS; separate Unbound SOA DNSSEC validation. |
| Collection controls | ZDNS threads, Go CPU parallelism, DNSSEC worker count, per-nameserver rate limits, DNS and validation timeouts, progress heartbeat and per-domain output. |
| Storage and resume | Original ranks, seven-digit folder names (expanding if needed), 10,000 domains per shard, atomic per-record JSON writes, SQLite checkpoints and ordered status/failure reports. |
| Selected retries | Retry a JSONL rank/domain list or saved DNS errors, retaining successful results and validating original ranks. |
| `fallback_a.py` | Choose iterative A retries or ordered Google then Cloudflare fallback; promote usable IPv4 responses into `a.json`, preserve an original backup, annotate source, and update SQLite A status. |
| `ns_ips.py` | Read saved NS answers, resolve each distinct hostname to A and AAAA iteratively, save per-domain address sets, resume from SQLite, retry failed hostname lookups, and export domain/hostname failure reports. |

Add `--with-ns-ips` to the main collector to run the NS address probe
automatically afterward. The probe can also run separately against an
existing output directory without repeating the original record scan.

## Collect records, DNSSEC, and NS addresses in one command

After building the image, run:

```bash
docker compose run --rm scanner \
  --input /work/domains.txt --output /work/result \
  --with-ns-ips \
  --threads 64 --go-processes 4 --validation-workers 8 \
  --timeout 20 --validation-timeout 20 --per-ns-qps 200
```

The collector first finishes the DNS record and DNSSEC stage and closes its
database, then launches `ns_ips.py` to resolve distinct saved NS hostnames
to A and AAAA. It passes through the same threads, Go parallelism, lookup
timeout, rate limits, progress settings, and `--retry-failed` flag.
The DNSSEC worker count and validation timeout apply only to the first stage.
Main and NS reports remain separate. Ordinary DNS outcomes such as TIMEOUT,
SERVFAIL, NXDOMAIN or bogus validation do not prevent the NS stage from
processing available NS records. A failed ZDNS process, missing output,
unexpected output, or interruption stops the sequence; rerun the same
command to resume both stages from their checkpoints. Exit code 1 means
one or both stages reported unresolved outcomes, even if both stages ran.
Without `--with-ns-ips`, the collector behaves as before. When combined with
`--retry-list`, the main retry is limited to that list, but the NS stage
indexes **all saved domains** in the output directory.

For a new region, copy the same code and ordered domain list, use a fresh
results directory, and record the vantage point and measurement times.
`compose.yaml` mounts `/home/test/zdns` to `/work`; change that host path if
you store the input and results elsewhere.

## Output folders

The default output is `/work/result`, which maps to
`/home/test/zdns/result` with the supplied Compose file. Ranked per-domain
files live under `result/domains/`; all failure reports live under
`result/failures_domians/` (spelling retained as requested): `failures.jsonl`,
`retry_failures.jsonl`, `ns_ips_failures.jsonl`, `ns_ips_host_failures.jsonl`,
`a_google_failures.jsonl`, and `a_fallback_failures.jsonl`. Each tool creates
its own reports when that stage runs. Databases, summaries, and status
reports stay directly under `result/`, and tool stderr logs stay in
`result/logs/`. Failed record JSON files stay in the original ranked domain
folders so retries and resume work.

To resume an existing scan previously stored in `results/`, keep using
`--output /work/results`, or rename the **whole** old `results` directory to
`result` while all scanners are stopped and only if `result` does not already
exist. Moving only `domains/` loses the checkpoint association. Choosing a
new empty output directory starts a new scan. Old failure reports at the
output root are historical snapshots; new runs write to `failures_domians/`.

## Install and run on your Docker host

Extract the archive and run these commands from its `zdns-iterative` folder:

```bash
mkdir -p /home/test/zdns
cp domains.txt /home/test/zdns/domains.txt
docker compose build --no-cache scanner
docker compose run --rm scanner
```

Replace the example input with your own list before starting. For a resumed
scan, **keep your original** `/home/test/zdns/domains.txt` and
`/home/test/zdns/result`; do not copy the example input over them. Stop the
old container first (Ctrl+C in its terminal, or `docker stop <container-id>`
if it runs in the background). Do not run two collectors against the same
output directory. Rebuild the image from these new files:

```bash
docker compose build --no-cache scanner
docker compose run --rm scanner
```

The new collector ignores the old `multiple_complete` marker in
`progress.json`. It reads `status.sqlite3` and checks saved record files.
It preserves completed `a.json` files and sends only missing types on resume.
Do not reorder or change the input list when resuming in the same output
directory. Backing up `/home/test/zdns/result` before upgrading a long scan
is sensible.

For a more detailed terminal stream:

```bash
docker compose run --rm scanner \
  --input /work/domains.txt --output /work/result \
  --threads 8 --go-processes 2 --validation-workers 2 --per-ns-qps 200 \
  --progress-every-domain
```

Without `--progress-every-domain`, the terminal prints a heartbeat every
five seconds. It distinguishes domains with all record files saved from
domains with both records and DNSSEC finished, and shows the number of DNSSEC
checks in flight. The label shows the most recently handled domain; several
ZDNS queries and DNSSEC checks may be active at once.

`--per-ns-qps 200` limits the query rate **per nameserver IP/name** in
ZDNS. It does not cap total network traffic or the separate Unbound query.
The Compose configuration limits the whole container to 4 CPUs. It starts
ZDNS with 8 network lookup threads and `--go-processes 2`, while 2 DNSSEC
worker threads each run an independent `unbound-host` process. A lookup
thread is not dedicated to one CPU core. The Python collector writes record
files and SQLite updates on one main thread; this could become the bottleneck
on very fast DNS and storage, so measure actual records/second and CPU usage
before increasing worker counts. `--go-processes` limits Go CPU parallelism,
not the other processes in the container.

## Outputs

```text
results/
  manifest.csv
  domain_status.csv
  failures.jsonl
  summary.json
  progress.json
  status.sqlite3
  pending-domains.csv
  multiple.ini
  logs/multiple.stderr.log
  domains/000/0000001-google.com/
    a.json
    aaaa.json
    ns.json
    soa.json
    cname.json
    https.json
    svcb.json
    tlsa.json
    caa.json
    dnskey.json
    ds.json
    dnssec.json
    ns_ips.json
```

There are 10,000 ranks per shard, so rank 1,000,000 gets a seven-digit folder
name under `domains/099/`. Successful queries with no answer are
`NOERROR_EMPTY`; they are not scan failures. Missing output and missing
module responses are recorded as retryable statuses. `domain_status.csv`
and `failures.jsonl` are exported when the run ends; the live checkpoint
is `status.sqlite3`, with `progress.json` updated every 1,000 record-complete
domains. If a run is interrupted, restart it against the same input and output.
If ZDNS exits without a usable response, the collector stops immediately and
points to `logs/multiple.stderr.log`; it does not start a long DNSSEC pass.
If only some ZDNS responses arrive, missing records are marked for retry and
remaining DNSSEC-only work waits for the next run. A full DNSSEC result already
written for another domain is preserved.
Add `--retry-failed` to also requery DNS error statuses previously saved
(such as TIMEOUT and SERVFAIL). A prior `MISSING_OUTPUT` or
`MISSING_RESULT` is retried by default.

## Resolve the IP addresses of every NS hostname

After the original scan has saved its `ns.json` files, run the separate NS
address probe in the same image. Stop other collectors using this results
directory first, rebuild after copying the new `ns_ips.py`, and run:

```bash
docker compose build scanner
docker compose run --rm --entrypoint python3 scanner /opt/ns_ips.py \
  --output /work/result --threads 64 --go-processes 4 \
  --timeout 20 --per-ns-qps 200
```

The probe reads only `results.NS.data.answers` with type `NS` from each saved
`ns.json`. It queries A and AAAA for **every distinct NS hostname** in one
long-running iterative ZDNS `MULTIPLE` process. Shared NS hostnames are
queried once and reused for every domain that lists them. Its checkpoint is
`result/ns_ips.sqlite3`: raw A and AAAA response details and their statuses
are saved by NS hostname there. Each domain gets its own `ns_ips.json` with
every observed IPv4 and IPv6 address grouped by NS hostname, address-family
statuses, and a union across that domain's nameservers. The existing `ns.json`
and all other records are preserved.

Progress appears during indexing, querying, and per-domain writing. The
ordered `ns_ips_status.jsonl`, `ns_ips_failures.jsonl`, and
`ns_ips_summary.json` are exported at the end. `NO_NAMESERVERS` records that
the NS answer contained no NS names; `NS_ERROR` identifies an unreadable or
unsuccessful source NS lookup; `LOOKUP_ERROR` indicates an NS hostname A or
AAAA lookup error; `NO_ADDRESS` and `PARTIAL` distinguish zero addresses and
one or more nameservers without either address. The detailed statuses are in
each `ns_ips.json`. Repeating the command resumes missing lookups and files;
use `--retry-failed` to requery saved hostname failures. The probe does not
change the original collector's `status.sqlite3` or its old reports. If NS
records are refreshed later, rerunning this probe picks up changed NS sets.
`ns_ips_host_failures.jsonl` gives each failed hostname, record type, and DNS
status (for example, TIMEOUT or SERVFAIL); the summary counts A and AAAA
statuses separately. Add `--progress-every-domain` to print each finished
ranked domain. The SQLite cache keeps the original response details,
including timestamps, TTLs, and responding resolver data when ZDNS supplies them.

The address lists contain **all A and AAAA records observed in these
responses**, not a guarantee of every address a geographically distributed
nameserver might return at other times or vantage points.

## Retry a selected set with longer timeouts

After the original collector has stopped, copy your newline-delimited JSON
list to `/home/test/zdns/retry_domains.json`. Each line must contain the
**original** rank and domain, for example:

```json
{"rank": 138, "domain": "nih.gov"}
{"rank": 999968, "domain": "anonfile.com"}
```

Keep the original million-line `/home/test/zdns/domains.txt` and the existing
`/home/test/zdns/result` directory. The full input verifies that the retry
list ranks still match; only selected domains are sent to ZDNS. Rebuild the
image after changing `collect.py`, then run:

```bash
docker compose build scanner
docker compose run --rm scanner \
  --input /work/domains.txt --output /work/result \
  --retry-list /work/retry_domains.json \
  --timeout 300 --validation-timeout 300 \
  --threads 32 --go-processes 4 --validation-workers 8 \
  --per-ns-qps 200
```

Both timeouts are in seconds. The ZDNS timeout applies to a domain lookup;
the validation timeout applies to a separate Unbound check. Selected domains
retry saved SERVFAIL, TIMEOUT, ERROR, missing module/output states, and any
record file that is absent. Existing successful files are preserved. DNSSEC
`indeterminate` is revalidated; `bogus`, `insecure`, and `secure` are retained.
NXDOMAIN is retained. Queries for other ranks are not retried. The output
contains `retry_domain_status.csv`, `retry_failures.jsonl`, and
`retry_summary.json`. The retry failure report includes all remaining
non-success statuses for the selected domains, including any retained
NXDOMAIN or bogus status. The original full-scan reports remain as snapshots;
the updated results and live statuses are in the per-domain files and
`status.sqlite3`. Do not run the full collector and the retry simultaneously
against the same results directory.

## Retry missing A addresses

After the iterative scan/retry stops, use your already extracted JSONL list of
domains without an A address. Place it at `/home/test/zdns/skipped_domain.json`
with one original rank/domain per line, then rebuild the image. Choose one
mode. To try Google Public DNS first and Cloudflare only if Google returns no
usable IPv4 A address:

```bash
docker compose build scanner
docker compose run --rm --entrypoint python3 scanner /opt/fallback_a.py \
  --output /work/result --input-list /work/skipped_domain.json \
  --public-ns \
  --threads 64 --go-processes 4 \
  --timeout 20 --per-ns-qps 100
```

To retry the selected A records with ZDNS iterative resolution instead:

```bash
docker compose run --rm --entrypoint python3 scanner /opt/fallback_a.py \
  --output /work/result --input-list /work/skipped_domain.json \
  --iterative \
  --threads 64 --go-processes 4 \
  --timeout 20 --per-ns-qps 100
```

`--iterative` and `--public-ns` are mutually exclusive. Public mode invokes
ZDNS separately with `8.8.8.8` and then `1.1.1.1`, each as its sole resolver;
iterative mode follows DNS delegations itself. Neither mode silently uses your
machine's resolver. It verifies the supplied rank/domain pairs against
`status.sqlite3` and queries only listed names whose current `a.json` lacks a
usable IPv4 A address. Listed NXDOMAIN names are included. Omit `--input-list`
to select all saved domains lacking an address; that automatic selection skips
NXDOMAIN unless you add `--include-nxdomain`.

The tool saves stage responses in `a_iterative_retry.json`, `a_google.json`, or
`a_cloudflare.json` within each ranked domain directory. **When a stage returns
a usable IPv4 address, it replaces `a.json`** with that response, marks it
`a_source: iterative_retry`, `google`, or `cloudflare`, backs up the prior file
as `a_iterative_original.json` once, and sets the SQLite A status to
`NOERROR_DATA`. If neither public resolver succeeds, the existing `a.json`
is untouched. A rerun skips valid saved stage results; add
`--retry-existing-failures` to requery saved stages without IPv4.

`a_fallback_status.jsonl`, `a_fallback_recovered.jsonl`,
`a_fallback_failures.jsonl`, and `a_fallback_summary.json` summarize the
selected list and the source of each resulting A address. The public mode also
writes `a_google_*.jsonl` and `a_google_summary.json`. Reports are written at
the end; per-domain JSON files are saved during measurement. Original
full-scan `domain_status.csv` and `failures.jsonl` remain snapshots, so use
the updated SQLite database and fallback reports after this run. Do not run
this tool concurrently with the full collector or another retry against the
same results directory. Public resolver results can differ due to DNSSEC
validation, caches, or location; retain and use `a_source` in your analysis.

If ZDNS exits before producing an output for every requested name, the retry
now stops at that stage and prints the end of its ZDNS error log. The full logs
are `/work/result/logs/a_google.stderr.log`, `a_cloudflare.stderr.log`, or
`a_iterative_retry.stderr.log`. Already saved per-domain stage responses remain
available for the next run. After a failure, inspect the log and fix its
cause before starting the full list again. For a quick resolver check inside
the image, run `docker compose run --rm --entrypoint zdns scanner A google.com
--name-servers=8.8.8.8`. Public resolver mode is ZDNS's default, so the
fallback does not pass an `--iterative` flag in that mode.

`dnssec.json` has `secure: 1` only for a validated secure SOA query,
and `secure: 0` for the other states. The DNSKEY and DS requests alone do
not prove a working chain of trust. TLSA at an apex does not discover
`_443._tcp.example.com`, and CAA is queried at the given name only.

At a million domains, this file layout can approach 12 million JSON files
and one million directories. Check both disk space and inodes with `df -h`
and `df -i`. Each DNSSEC validation still starts an `unbound-host`
process, with only a bounded number running at once; this can be slow. The Docker build needs network
access to GitHub, Docker Hub and Debian packages, and the running container
needs outbound UDP and TCP port 53. This release has been verified with
simulated ZDNS and Unbound tools; no Docker daemon was available for a live
DNS integration test here.
