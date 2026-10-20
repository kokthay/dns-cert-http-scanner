# Python fallback after Go: HTTP/1.1, HTTP/2, HTTP/3

Run this after the Go scan has finished. It uses independent Python protocol
implementations (`h11`, `h2`, `aioquic`) and retries domains for which either the
certificate or final response headers are missing. A malformed server response
can fail in both implementations; recovery is not guaranteed.

## Run

The project folder remains `/home/test/zdns/https-scanner/`. Existing files in
`/home/test/zdns/results` are reused; do not delete them.

```bash
cd /home/test/zdns/https-scanner
docker compose build cert-http-python
docker compose run --rm cert-http-python \
  --input /work/results/websites_ips.jsonl \
  --output /work/results/cert_http \
  --failures-output /work/results/failures_certHTTP \
  --workers 50 --rate 25 --timeout 20s
```

Use `websites_ipv4.jsonl` instead if that is your actual input filename. Both
`{"rank":1,"domain":"example.com","ip":"192.0.2.1"}` and
`{"rank":1,"domain":"example.com","ips":["192.0.2.1","2001:db8::1"]}` work.
Repeated rank/domain rows merge their candidate IPs in order. Invalid rows go
into the Python run's `input_errors.jsonl` and do not stop valid rows. Input is
grouped in memory, like the current Go scanner.

`--workers` limits concurrent domains. `--rate` limits new TCP connections and
QUIC connection attempts combined; QUIC retransmissions and packets are not
individually rate limited. The 20-second total timeout applies to each protocol
attempt; the TCP, TLS/QUIC-handshake and HTTP-header sublimits are 5, 5 and 10
seconds. With several IPs a domain may take longer. Cleanup is bounded separately.

For another fallback retry of cached failures, add `--retry-failed`. Successful
Go or Python results continue to be skipped.

## Order

For each supplied IP, the fallback tries HTTP/1.1, HTTP/2, then HTTP/3, stopping
as soon as a single attempt yields both certificate and final response headers.
It then stops trying that domain's remaining IPs. If TCP fails, HTTP/2 on that
IP is skipped, but HTTP/3 is still attempted because it uses UDP.

All attempts use the input domain for SNI and Host/`:authority`, connect to
the supplied literal IP and port, request `GET /`, ignore proxy environment
variables, and do not follow redirects, Alt-Svc targets, or QUIC preferred
addresses. There is no DNS lookup. HTTP/3 is attempted directly on **UDP 443**
(or `--port`); HTTP/1.1 and HTTP/2 use TCP on that port. UDP may be filtered even
when TCP works. Only standard HTTP/3 with ALPN `h3` is attempted, not old draft
versions. TLS 1.2/1.3 are used for TCP and TLS 1.3 for QUIC.

Any final status, including 301, 403 or 500, counts as an HTTP response.
Informational responses are retained separately. Response bodies and trailers
are not collected; some body bytes can arrive in the same network read and are
discarded. Header limits default to 1 MiB and pre-header wire input is bounded.
All certificate name, trust, and expiry checks remain disabled. The server's
certificate message must still be parseable and its cryptographic handshake must
work. The entire chain supplied by the peer is retained; missing intermediates
are not fetched. HTTP/2 and HTTP/3 headers are decoded, with repeated values
retained; only HTTP/1.1 has original raw header text.

## Files and provenance

For a domain such as rank 1 / `example.com`:

| Path within `results/cert_http/000/0000001-example.com/` | Purpose |
|---|---|
| `http.json`, `tls.json`, `certificate.pem`, `chain.pem` | Usual main results; updated only when Python obtains both certificate and headers |
| `go_original/` | Original main Go files, saved before a Python success replaces them; Go `attempts/` stays in place |
| `python_fallback/attempts/` | Every completed Python attempt, including partial certificates |
| `python_fallback/http.json`, `tls.json`, `certificate.pem`, `chain.pem` | Best Python observation, including partial collection if no attempt succeeds |
| `python_fallback/fallback.json` | Python outcome, candidate list and attempt summaries |

A successful fallback removes `errors.json` and `errors_python.json` for that
domain from `failures_certHTTP`. Prior run logs remain historical. If fallback
still fails, the original Go main files and `errors.json` stay intact, while
`failures_certHTTP/000/0000001-example.com/errors_python.json` records the new
outcome, partial-collection booleans, and attempt statuses. If certificates were
obtained on several attempts, each is retained in its attempt folder.

Python runs write progress, `errors.jsonl`, `input_errors.jsonl` and
`summary.json` under `cert_http/_runs/python-.../`. Summaries report short domain
and attempt statuses. Interrupted domains have no completed fallback marker and
are retried on restart; a certificate obtained before interruption is retained
under `python_fallback/interrupted-.../`. The updated Go scanner recognizes
successful Python observations during resume, including HTTP/3 observations.

Run Go and Python sequentially; do not run simultaneous writers on these paths.
Both services run as root by default, as in the previous configuration.

## Add after the existing pipeline

From `/home/test/zdns`, append this after the Go HTTPS stage succeeds:

```bash
&& docker compose -f ./https-scanner/compose.yaml build cert-http-python \
&& docker compose -f ./https-scanner/compose.yaml run --rm cert-http-python \
  --input /work/results/websites_ips.jsonl \
  --output /work/results/cert_http \
  --failures-output /work/results/failures_certHTTP \
  --workers 50 --rate 25 --timeout 20s
```

Go returns a nonzero exit for invalid input or local failures, so `&&` deliberately
stops the pipeline in those cases; ordinary website collection failures do not
prevent the fallback stage. The two scanners have separate worker/rate settings.

## About `received DATA before a HEADERS frame`

That HTTP/2 error means body DATA arrived before valid final response headers.
Go rejects that stream. In this scanner TLS has already been completed before
HTTP/2 starts, so its certificate normally remains available. An informational
response such as 103 is not a final response. Check the domain's `http.json`
`success`, `certificate_count`, `response` and `attempts` to determine its final
outcome; another candidate IP may have subsequently succeeded.

## Local tests

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-fallback.txt
.venv/bin/python -m unittest -v test_fallback_http
```

Fixtures use local TLS and QUIC servers with an expired certificate for another
hostname. Tests verify the supplied SNI/Host, IPv4/IPv6, duplicate headers,
informational responses, an HTTP/2 DATA-before-HEADERS failure with certificate
retention, TCP refusal followed by UDP success, IP ordering, successful-result
preservation, resume, timeouts and cancellation. No public websites are probed.
