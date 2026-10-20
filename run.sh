cd /home/test/zdns && sudo docker compose build scanner && (
  scan_status=0

  sudo docker compose run --rm scanner \
    --input /work/domains.txt \
    --output /work/results \
    --with-ns-ips \
    --threads 351 --go-processes 4 \
    --validation-workers 90 \
    --timeout 60 --validation-timeout 60 \
    || scan_status=$?

  if [ "$scan_status" -le 1 ]; then
    sudo docker compose run --rm --entrypoint python3 scanner /opt/fallback_a.py \
      --output /work/results \
      --public-ns \
      --include-nxdomain \
      --threads 351 --go-processes 4 \
      --timeout 60 \
    && sudo python3 ./extract_ip_records.py \
      ./results/domains \
      ./results/websites_ips.jsonl \
      --skipped-output ./results/skipped_domain.json \
    && sudo docker compose -f ./https-scanner/compose.yaml build \
      cert-http cert-http-python \
    && sudo docker compose -f ./https-scanner/compose.yaml run --rm cert-http \
      --input /work/results/websites_ips.jsonl \
      --output /work/results/cert_http \
      --failures-output /work/results/failures_certHTTP \
      --workers 400 \
      --rate 200 \
      --timeout 60s \
    && sudo docker compose -f ./https-scanner/compose.yaml run --rm cert-http-python \
      --input /work/results/websites_ips.jsonl \
      --output /work/results/cert_http \
      --failures-output /work/results/failures_certHTTP \
      --workers 200 \
      --rate 100 \
      --timeout 60s
  else
    echo "Scanner stopped with exit code $scan_status; fallback not started."
    exit "$scan_status"
  fi
)