bash <<'BASH'
set -euo pipefail

cd /home/test/zdns

# Choose the final archive name:
final_name="eu-archive.tar.zst"
# final_name="na-archive.tar.zst"

destination="test@192.168.200.98:/home/test/"

# Require a filename without directory components.
if [[ "$final_name" == */* || "$final_name" != *.tar.zst ]]; then
  echo "ERROR: final_name must be a filename ending in .tar.zst"
  exit 1
fi

final_archive="$PWD/$final_name"

if [ -e "$final_archive" ]; then
  echo "ERROR: $final_archive already exists. Choose another name."
  exit 1
fi

stamp="$(date +%Y%m%d-%H%M%S)-$$"
archive="$PWD/archive-$stamp.tar.zst"
logs="$PWD/archive-check-$stamp"
mkdir -p "$logs"

trap 'echo "FAILED: Workflow stopped. Review terminal output and logs: $logs"' ERR

sudo -v

echo "Building DNS scanner..."
sudo docker compose build scanner

echo "Running DNS scanner..."
scan_status=0
sudo docker compose run --rm scanner \
  --input /work/domains.txt \
  --output /work/results \
  --with-ns-ips \
  --threads 351 --go-processes 4 \
  --validation-workers 90 \
  --timeout 40 --validation-timeout 40 \
  || scan_status=$?

if [ "$scan_status" -gt 1 ]; then
  echo "Scanner stopped with exit code $scan_status; workflow stopped."
  exit "$scan_status"
fi

echo "Running DNS fallback..."
sudo docker compose run --rm --entrypoint python3 scanner /opt/fallback_a.py \
  --output /work/results \
  --public-ns \
  --include-nxdomain \
  --threads 351 --go-processes 4 \
  --timeout 40

echo "Extracting website IP addresses..."
sudo python3 ./extract_ip_records.py \
  ./results/domains \
  ./results/websites_ips.jsonl \
  --skipped-output ./results/skipped_domain.json

echo "Building certificate and HTTP scanners..."
sudo docker compose -f ./https-scanner/compose.yaml build \
  cert-http cert-http-python

echo "Running certificate and HTTP scanner..."
sudo docker compose -f ./https-scanner/compose.yaml run --rm cert-http \
  --input /work/results/websites_ips.jsonl \
  --output /work/results/cert_http \
  --failures-output /work/results/failures_certHTTP \
  --workers 600 \
  --rate 300 \
  --timeout 60s

echo "Running Python certificate and HTTP fallback..."
sudo docker compose -f ./https-scanner/compose.yaml run --rm cert-http-python \
  --input /work/results/websites_ips.jsonl \
  --output /work/results/cert_http \
  --failures-output /work/results/failures_certHTTP \
  --workers 600 \
  --rate 300 \
  --timeout 60s

echo "All scan stages completed."

echo "Creating archive with progress..."
sudo tar -cf - -C / home/test/zdns/results \
  2> "$logs/archive-create.log" |
  pv -brt |
  zstd -T0 > "$archive.partial"

mv "$archive.partial" "$archive"

echo "Verification 1/3: Compressed archive integrity..."
zstd -t "$archive" > "$logs/integrity.log" 2>&1
echo "Integrity check passed."

echo "Verification 2/3: Comparing archived contents with originals..."
sudo tar --zstd -df "$archive" -C / \
  > "$logs/content.log" 2>&1
echo "Content comparison passed."

echo "Verification 3/3: Checking complete path coverage..."
echo "Building and sorting source paths..."
sudo find /home/test/zdns/results -printf '%p\n' \
  2> "$logs/find-errors.log" |
  sed 's|^/||; s|/$||' |
  LC_ALL=C sort > "$logs/source-paths.txt"

echo "Building and sorting archive paths..."
tar --zstd -tf "$archive" \
  2> "$logs/archive-list-errors.log" |
  sed 's|/$||' |
  LC_ALL=C sort > "$logs/archive-paths.txt"

diff -u "$logs/source-paths.txt" "$logs/archive-paths.txt" \
  > "$logs/path-differences.log"

echo "PASS: All three archive checks passed."

echo "Renaming verified archive to $final_name..."
mv -n "$archive" "$final_archive"

if [ -e "$archive" ]; then
  echo "ERROR: Rename did not complete; transfer stopped."
  exit 1
fi

archive="$final_archive"

echo "Transferring $final_name to $destination ..."
rsync -t --partial --append-verify \
  --info=progress2 --stats \
  "$archive" \
  "$destination"

echo "SUCCESS: Archive verified, renamed, and transferred."
echo "Local archive: $archive"
echo "Remote archive: ${destination}${final_name}"
echo "Verification logs: $logs"
BASH