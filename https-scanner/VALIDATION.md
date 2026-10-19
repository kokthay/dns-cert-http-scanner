# v2 validation

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
