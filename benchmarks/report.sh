#!/usr/bin/env bash
set -euo pipefail
export LC_NUMERIC=C

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"

if [[ ! -d "$RESULTS_DIR" ]] || [[ -z "$(ls -A "$RESULTS_DIR"/*.json 2>/dev/null)" ]]; then
    echo "No benchmark results found in $RESULTS_DIR"
    echo "Run ./run-benchmarks.sh first."
    exit 1
fi

printf "%-16s | %-16s | %6s | %10s | %9s | %9s | %9s | %6s\n" \
    "HAProxy Version" "Config" "Conc." "RPS" "p50 (ms)" "p95 (ms)" "p99 (ms)" "Errors"
printf "%s\n" "$(printf '%.0s-' {1..100})"

for result_file in "$RESULTS_DIR"/*.json; do
    filename=$(basename "$result_file" .json)

    jq -e . "$result_file" > /dev/null 2>&1 || continue

    qps=$(jq -r '.ActualQPS // 0' "$result_file" 2>/dev/null)
    p50=$(jq -r '(.DurationHistogram.Percentiles // [] | map(select(.Percentile == 50)) | .[0].Value // 0) * 1000' "$result_file" 2>/dev/null)
    p95=$(jq -r '(.DurationHistogram.Percentiles // [] | map(select(.Percentile == 95)) | .[0].Value // 0) * 1000' "$result_file" 2>/dev/null)
    p99=$(jq -r '(.DurationHistogram.Percentiles // [] | map(select(.Percentile == 99)) | .[0].Value // 0) * 1000' "$result_file" 2>/dev/null)

    total=$(jq -r '.DurationHistogram.Count // 0' "$result_file" 2>/dev/null)
    ok=$(jq -r '.RetCodes["200"] // 0' "$result_file" 2>/dev/null)
    errors=$((total - ok))

    version=$(jq -r '.Labels // "" | split(",") | map(select(startswith("haproxy="))) | .[0] // "" | sub("haproxy=";"")' "$result_file" 2>/dev/null)
    config=$(jq -r '.Labels // "" | split(",") | map(select(startswith("config="))) | .[0] // "" | sub("config=";"")' "$result_file" 2>/dev/null)
    concurrency=$(jq -r '.Labels // "" | split(",") | map(select(startswith("concurrency="))) | .[0] // "" | sub("concurrency=";"")' "$result_file" 2>/dev/null)

    if [[ -z "$version" ]]; then
        version=$(echo "$filename" | cut -d'_' -f1)
        config=$(echo "$filename" | cut -d'_' -f2)
        concurrency=$(echo "$filename" | cut -d'_' -f3 | sed 's/^c//')
    fi

    printf "%-16s | %-16s | %6s | %10.1f | %9.2f | %9.2f | %9.2f | %6d\n" \
        "$version" "$config" "$concurrency" "$qps" "$p50" "$p95" "$p99" "$errors"
done | sort -t'|' -k1,1 -k3,3n -k2,2

echo ""
echo "Results directory: $RESULTS_DIR"
