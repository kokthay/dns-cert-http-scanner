# Validation update — 2026-10-20

- Go 1.26.1 on Linux/amd64: full `go test -race ./...` passed after adding
  Python-success resume and `HTTP_PROTOCOL_ERROR` classification. Header-size
  errors retain `HEADER_LIMIT` precedence.
- Python 3.12.14: 16 local-only unit/integration tests passed with pinned
  aioquic 1.7.0, h2 4.4.1 and h11 0.16.0.
- Real local TCP/TLS HTTP/1.1, HTTP/2 and UDP/QUIC HTTP/3 endpoints tested;
  the HTTP/3 test includes 103 followed by final 403 response headers.
- Reproduced DATA-before-HEADERS on HTTP/2: certificate retained, final headers
  absent, status HTTP_PROTOCOL_ERROR.
- Tested expired/wrong-hostname certificates, full supplied chain, duplicate
  headers, SNI/Host, no DNS, IPv6, ordered IP fallback, TCP-refused/UDP-success,
  cached successes and failures, summaries, metadata errors, cancellation,
  header limits, preservation of Go partial results and rejection of QUIC
  preferred-address migration.
- Python Dockerfile targets Python 3.13. Docker is unavailable in this
  environment, so image builds and container execution remain untested here.
  The Dockerfile itself runs the Python integration suite during build.
- No public million-domain scan was run.

## Previous v2 validation record

Validated using Go 1.27.2 on Linux/amd64:

- Collection-only behavior: mismatching/untrusted certificates are retained,
  produce status OK when headers are obtained, and never enter failure logs.
- HTTP/1.1 success skips HTTP/2 and remaining IPs; redirects are not followed.
- Real HTTP/2 over TLS, including a strict h2-only endpoint and an HTTP/1
  connection that provides a certificate but closes before headers.
- Connection refusal advances to the next IP without a redundant protocol retry.
- Stop after the first complete certificate/header collection.
- Preserve failed-attempt certificates and short error statuses.
- HTTP/1.1 raw/framing/repeated headers and informational responses.
- HTTP/2 repeated headers, header limits, and header timeouts.
- Actual IPv6 loopback collection.
- Error classification, cancellation, safe paths, and shard boundaries.
- Merge repeated domain rows and deduplicate IPs, including mapped addresses.
- Invalid IPs do not suppress valid candidates; malformed/conflicting input logs.
- Resume, selective failed-result retry, and status-count summaries.
- Old successful results imported without reconnecting; old validation fields
  and current validation-only failure entries removed.

Go race tests, vet, static build, and native CLI checks passed. The CLI check
included an expired certificate for a different name, a refused first IP,
successful second IP, stop-before-third-IP behavior, exact certificate PEM,
clean failure logs, summary counts, and resume without reconnecting.
Compose fixed paths and Linux host-network mode were parsed and checked.
No million-domain public scan was run. Docker is unavailable here; the Docker
image build and container execution were not tested in this environment.
