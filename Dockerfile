FROM golang:1.25-bookworm AS build
ARG ZDNS_REF=v2.1.1
RUN git clone --depth 1 --branch "$ZDNS_REF" https://github.com/zmap/zdns.git /src/zdns
WORKDIR /src/zdns
RUN go build -o /zdns .

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends unbound-host dns-root-data \
    && rm -rf /var/lib/apt/lists/* \
    && test -s /usr/share/dns/root.key
COPY --from=build /zdns /usr/local/bin/zdns
COPY collect.py /opt/collect.py
COPY fallback_a.py /opt/fallback_a.py
COPY ns_ips.py /opt/ns_ips.py
WORKDIR /work
ENTRYPOINT ["python3", "/opt/collect.py"]
