cd /home/test/zdns && docker compose build scanner && (
  scan_status=0

  docker compose run --rm scanner \
    --input /work/domains.txt \
    --output /work/results \
    --with-ns-ips \
    --threads 512 --go-processes 4 \
    --validation-workers 128 \
    --timeout 40 --validation-timeout 40 \
    || scan_status=$?

  if [ "$scan_status" -le 1 ]; then
    docker compose run --rm --entrypoint python3 scanner /opt/fallback_a.py \
      --output /work/results \
      --public-ns \
      --include-nxdomain \
      --threads 512 --go-processes 4 \
      --timeout 40 \
    && python3 ./extract_ip_records.py \
      ./results/domains \
      ./results/websites_ips.jsonl \
      --skipped-output ./results/skipped_domain.json \
    && docker compose -f ./https-scanner/compose.yaml build cert-http \
    && docker compose -f ./https-scanner/compose.yaml run --rm cert-http \
      --input /work/results/websites_ips.jsonl \
      --output /work/results/cert_http \
      --failures-output /work/results/failures_certHTTP \
      --workers 400 \
      --rate 200 \
      --timeout 20s
  else
    echo "Scanner stopped with exit code $scan_status; fallback not started."
    exit "$scan_status"
  fi
)