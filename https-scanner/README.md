# HTTPS certificate and header collector (v2)

Collect certificates and HTTP response headers by connecting directly to supplied
IP addresses. No DNS lookups, certificate identity/trust validation, browser
rendering, or automatic redirect following.

## Normal build and run

Project directory: `/home/test/zdns/https-scanner/`.
Input: `/home/test/zdns/results/websites_ipv4.jsonl`.
Results: `/home/test/zdns/results/cert_http/`.
Failures: `/home/test/zdns/results/failures_certHTTP/`.

```bash
cd /home/test/zdns/https-scanner
docker compose build cert-http
docker compose run --rm cert-http
```

The paths are fixed in `compose.yaml`. No exports or `.env` setup are needed.
The project is explicitly named `https-scanner`, separate from the ZDNS Compose
project. Output directories are created automatically. Docker's default root
user is used; new files are root-owned.

On the Linux server, Compose uses host networking so the collector uses the
host's IPv4/IPv6 routes. IPv6 destinations still require working IPv6 connectivity
on that host. A missing route is recorded as a short network error status.

To give all settings explicitly:

```bash
docker compose run --rm cert-http \
  --input /work/results/websites_ipv4.jsonl \
  --output /work/results/cert_http \
  --failures-output /work/results/failures_certHTTP \
  --workers 100 --rate 50 --timeout 20s
```

For a pilot, add `--limit 1000`. This limits nonblank input rows before grouping
repeated domains. For a background run, use `docker compose up -d cert-http`,
then `docker compose logs -f cert-http`. Stop a background run with
`docker compose stop cert-http`, or a foreground run with Ctrl+C. Run only one
scanner against an output root at a time.

## Input: one or multiple IPs

One complete JSON object per line, with no trailing comma or backslash:

```jsonl
{"rank":999994,"domain":"celestialfault.dev","ips":["104.21.88.188","172.67.152.45"]}
{"rank":697,"domain":"nodeflix.net","ips":["2a0b:64c0:100::25e0"]}
```

IPv4 and IPv6 can be mixed in the same list. The filename is configurable;
`websites_ipv4.jsonl` is just the retained default name and does not restrict the
address family. The old single-IP format is also supported:

```jsonl
{"rank":1,"domain":"google.com","ip":"142.250.110.102"}
```

If a row has both `ip` and `ips`, `ip` is tried first. Repeated rows for the same
rank/domain are merged before probing; their IPs retain first-appearance order.
Duplicate IPs are removed after canonicalization (including IPv4-mapped IPv6).
A rank assigned to different domains is logged as `INVALID_INPUT`.

Names may contain ASCII letters, digits, hyphens, underscores, and dots.
Use punycode for internationalized names. Domains are lowercased and a final
root dot is removed. Underscore names such as `_wildcard_.ph` are accepted.
Invalid IPs are logged as `INVALID_IP`; other valid IPs on that row are still
tried. Malformed JSON is logged as `INVALID_INPUT`.

The scanner first reads and groups the input in memory so repeated IPv4/IPv6
rows cannot cause a successful domain to be scanned again. Memory usage scales
with the number of domains and candidate IPs. Network work uses a bounded worker
pool and results are written immediately after each domain task completes.

## Collection order and stopping

For each domain, in the supplied IP order:

1. Connect to the IP on TCP port 443 and attempt HTTP/1.1 over TLS.
2. If both a peer certificate and final HTTP response headers are obtained,
   save the result and stop. Do not try HTTP/2 or remaining IPs.
3. If TCP connection itself fails, move directly to the next IP. Changing the
   HTTP version cannot repair a refused/unreachable TCP connection.
4. If TCP connected but the TLS/HTTP/1.1 collection failed, reconnect to the
   same IP and attempt HTTP/2, requiring ALPN `h2`.
5. Stop on HTTP/2 success. Otherwise move to the next IP.
6. If all candidate IPs fail, retain partial evidence and record a domain failure.

Success means certificate + HTTP response headers from the SAME attempt.
Certificates from one connection are not paired with headers from another.
Any obtained final HTTP status counts, including 301, 403, 404, or 500.
Redirects are stored with their `Location` and are not followed.

Each attempt uses the original domain as TLS SNI and HTTP Host/authority.
The socket destination is always a supplied IP literal; environment proxies,
DNS resolution, AIA fetching, and redirect-target resolution are not used.
There is no implicit `www` change. HTTP/3 is not supported by this version.
TLS 1.2 and 1.3 are supported; older-only TLS endpoints can fail the handshake.

## Certificates are collected, not validated

The scanner does not check certificate hostnames, trust roots, validity dates,
revocation, browser CT policy, or chain validity. `tls.json` states
`verification_performed: false`. Certificate name mismatch, expired certificates,
self-signed certificates, and unknown issuers do not cause collection errors.
Certificate metadata (subject, issuer, SANs, dates, algorithms, policy OIDs,
and hashes) is still stored, together with the complete certificates.

The TLS handshake must still function; protocol, parsing, and cryptographic
handshake failures remain collection failures. A certificate does not prove the
collected HTTP response is authenticated for the input domain.

## Output layout

The existing layout is preserved, for example:

```text
/home/test/zdns/results/cert_http/000/0000001-google.com/http.json
/home/test/zdns/results/cert_http/000/0000001-google.com/tls.json
/home/test/zdns/results/cert_http/000/0000001-google.com/certificate.pem
/home/test/zdns/results/cert_http/000/0000001-google.com/chain.pem
```

The shard is `floor((rank - 1) / 10000)`, formatted with three digits. The rank
in a domain directory has at least seven digits. Ranks 1–10,000 use `000`;
10,001–20,000 use `001`; 1,000,000 uses `099`. Extremely long directory names
are shortened with a stable hash suffix to fit filesystem limits; the full
name stays in JSON.

| File | Contents |
|---|---|
| `http.json` | Collection `status`, chosen IP, complete input IP list, timestamps, HTTP response and headers, and the sequence of attempts |
| `tls.json` | TLS details and metadata for every certificate sent; no validation results |
| `certificate.pem` | Chosen attempt's leaf certificate |
| `chain.pem` | All certificates sent in that attempt, in received order including the leaf |

For HTTP/1.1, raw header text and all parsed values are retained, including
repeated headers and framing fields such as `Transfer-Encoding`. For HTTP/2,
all decoded regular response-header values are saved, and `:status` is
represented by `response.status_code`. HTTP/2 has binary framing, so there is no
raw HTTP/1-style text in `raw_headers`. Informational responses are separate.
Bodies and body trailers are not collected. Buffered protocol reads may receive
some body bytes before the connection/stream is closed.

If multiple attempts were needed, each attempt's HTTP/TLS metadata and any
received certificates are also preserved under directories such as:

```text
000/0000001-google.com/attempts/0001-104.21.88.188-http1/
000/0000001-google.com/attempts/0002-104.21.88.188-http2/
000/0000001-google.com/attempts/0003-172.67.152.45-http1/
```

The exact relative directory is in `http.json` under `attempts[].directory`.
A simple first-attempt success needs only the four main files. If everything
fails, the main files retain the latest attempt with a certificate (or the last
attempt if none supplied one). Its status explains the failure of that chosen
partial result; `attempts` retains every other error. Certificate PEM files are
absent when no certificate was received. The server-sent chain may omit a root
or intermediates; it is not a constructed/validated chain.

## Errors and short status codes

A failure entry is created only if all candidate IP/protocol attempts fail to
collect BOTH a certificate and HTTP headers. Certificate-validation complaints
are never generated. If an earlier attempt fails but a later attempt succeeds,
the domain status is `OK` and there is no per-domain failure entry. Earlier
attempt statuses remain in `http.json` and its attempt files.

Example failure:

```json
{
  "rank":10001,
  "domain":"example.com",
  "ip":"192.0.2.10",
  "status":"CONNECTION_REFUSED",
  "stage":"tcp",
  "error":"dial tcp 192.0.2.10:443: connect: connection refused",
  "certificate_obtained":false,
  "http_obtained":false
}
```

The actual record also includes time, attempts, and result-directory fields.

| Status | Meaning |
|---|---|
| `OK` | Certificate and headers collected |
| `TIMEOUT` | TCP, TLS, or HTTP timeout; inspect `stage` |
| `CONNECTION_REFUSED` | TCP connection refused |
| `CONNECTION_RESET` | Connection reset |
| `NETWORK_UNREACHABLE` | No network route, including unavailable IPv6 routing |
| `HOST_UNREACHABLE` | Destination host unreachable |
| `ADDRESS_UNAVAILABLE` | Local address unavailable |
| `CONNECTION_CLOSED` | Peer closed early / EOF / broken pipe |
| `CONNECTION_ERROR` | Other TCP error |
| `TLS_HANDSHAKE_ERROR` | TLS handshake failed |
| `ALPN_UNSUPPORTED` | HTTP/2 ALPN unavailable or rejected |
| `HTTP_PARSE_ERROR` | Malformed HTTP/1 response or too many informational responses |
| `HTTP_ERROR` | Other HTTP exchange/protocol failure |
| `HEADER_LIMIT` | Response-header limit exceeded |
| `NO_CERTIFICATE` | Headers obtained without a peer certificate |
| `CANCELED` | Scan interrupted |
| `INVALID_INPUT` / `INVALID_IP` | Input errors |
| `LOCAL_IO_ERROR` | Local file/log/read/write failure |

Latest per-domain failure:
`failures_certHTTP/<shard>/<rank-domain>/errors.json`.
Run failure/input/local-error log:
`failures_certHTTP/_runs/<UTC-timestamp>/errors.jsonl`.
Run summary (written on completion or handled interruption):
`failures_certHTTP/_runs/<UTC-timestamp>/summary.json` and the matching path
under `cert_http/_runs/`. Both contain:

```json
{
  "domain_status_counts":{"OK":100,"TIMEOUT":4,"CONNECTION_REFUSED":2},
  "attempt_status_counts":{"HTTP/1.1:OK":98,"HTTP/1.1:TIMEOUT":6,"HTTP/2:OK":2}
}
```

Counts here are illustrative. Domain counts include cached/imported observations
considered in this run. Attempt counts include failed attempts recovered by a
later success, so these counters answer different questions. Input errors are
in `input_errors.jsonl` and counted under `counters.invalid_input`.

Historical run logs are preserved; use the latest run when analyzing the new
status schema. A successful later result removes an old per-domain failure,
including an older certificate-validation-only failure.

## Resume and upgrade

By default, completed matching successes and failures are skipped. A cached
success must use an IP still in the input list. A cached failure is reusable
only when the candidate IP set is unchanged. If a new candidate is added to a
failed domain, its task runs again. Port and User-Agent must also match.
Interrupted domain results are incomplete and are retried on resume.

Old HTTP/1.1 results containing both certificate and headers are imported in
place without reconnecting, even if the old certificate validation failed.
Their old validation fields are removed. Old unsuccessful results are re-probed
using the new IP and HTTP/2 fallback policy. This avoids repeating successful
work while giving old failures the new fallback attempts.

To retry completed collection failures:

```bash
docker compose run --rm cert-http --retry-failed
```

To force a fresh scan:

```bash
docker compose run --rm cert-http --resume=false
```

Files are atomically replaced individually, with `http.json` written last as
the completion marker. This supports process-interruption resume; it is not a
power-failure durability transaction. Disk errors stop scanning and are logged
when the error log remains writable; failures preventing any logging go to
stderr. Invalid input does not stop valid tasks, but gives a nonzero exit code
at the end. Remote collection failures alone do not change the process exit
code. Handled SIGINT/SIGTERM exits 130.

## Concurrency and timeouts

`--workers 100` means up to 100 simultaneous domain tasks. Each domain tries
its IPs/protocols sequentially. `--rate 50` limits ALL new connections per
second across workers, including HTTP/2 retries; `--rate 0` removes that limit.
A rate is a ceiling, not a guaranteed completion speed.

`--timeout 20s` applies to EACH protocol attempt, not the entire domain. TCP
has a 5s timeout, TLS 5s, and HTTP write/headers 10s, all bounded by that
attempt's total timeout. Rate-limit waits occur before the per-attempt timeout.
A domain with several failing IPs can therefore take much longer than 20s.
Response headers default to a 1 MiB limit per attempt. HTTP/1 applies this to
received text; HTTP/2 applies it to decoded header sizes. The representations
have different byte accounting. At most 15 informational responses are allowed.

## Development and validation

Requires Go 1.25+; only the standard library is used. Docker builds run the
included tests. The runtime image is `scratch`; no CA root package is needed
because certificate validation is not performed. The default stable Go image
can be pinned with `--build-arg GO_IMAGE=<approved-tag-or-digest>`.

```bash
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /tmp/https-scanner .
```

Tests use controlled local HTTP/1.1, HTTP/2, and IPv6 TLS endpoints, without
public-network measurements. See `VALIDATION.md`. Docker was unavailable in the
authoring environment; actual container building/running was not executed here.

References: https://pkg.go.dev/net/http, https://pkg.go.dev/crypto/tls, and
https://docs.docker.com/engine/network/drivers/host/.
## Optional Python fallback (HTTP/1.1, HTTP/2, HTTP/3)

The Go scanner still tries HTTP/1.1 and HTTP/2. To retry incomplete collections
with independent Python clients and HTTP/3, run the separate `cert-http-python`
service **after** Go finishes. See [PYTHON_FALLBACK.md](PYTHON_FALLBACK.md) for
commands, provenance, output files and UDP requirements. Successful results
from either scanner are reused.

