#!/usr/bin/env bash
# Run OMEGA-5.0 against every obfuscated JS sample; capture exit, time, RSS.
set -u

OMEGA=/workspace/omega-sast-test/omega-sast/bin/omega.js
SAMPLES_DIR=/workspace/omega-sast-test/obfuscated-zip-test/obfuscated_js_samples
LOG_DIR=/workspace/omega-sast-test/obfuscated-zip-test/logs
OUT_DIR=/workspace/omega-sast-test/obfuscated-zip-test/results
SUMMARY=/workspace/omega-sast-test/obfuscated-zip-test/summary.tsv

mkdir -p "$LOG_DIR" "$OUT_DIR"
echo -e "bundle\tsize_bytes\texit_code\tduration_ms\tpeak_rss_kb" > "$SUMMARY"

for bundle in "$SAMPLES_DIR"/*.js; do
  name=$(basename "$bundle" .js)
  size=$(stat -c %s "$bundle")
  outdir="$OUT_DIR/$name"
  logfile="$LOG_DIR/$name.log"

  echo "==> $name.js  (${size} bytes)"

  start_ms=$(date +%s%3N)
  node "$OMEGA" "$bundle" --security --report --out "$outdir" \
      > "$logfile" 2>&1 &
  pid=$!
  peak_kb=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ -r /proc/$pid/status ]; then
      rss=$(awk '/^VmRSS:/ {print $2}' /proc/$pid/status 2>/dev/null)
      [ -n "$rss" ] && [ "$rss" -gt "$peak_kb" ] && peak_kb="$rss"
    fi
    sleep 0.05
  done
  wait "$pid"; rc=$?
  end_ms=$(date +%s%3N)
  dur=$((end_ms - start_ms))

  printf "%s\t%s\t%s\t%s\t%s\n" "$name" "$size" "$rc" "$dur" "$peak_kb" >> "$SUMMARY"
  echo "    exit=$rc  duration=${dur}ms  rss_peak=${peak_kb}KB"
done

echo
echo "=== Summary ==="
cat "$SUMMARY"
