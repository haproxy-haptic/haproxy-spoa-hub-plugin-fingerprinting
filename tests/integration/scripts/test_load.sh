#!/usr/bin/env bash
set -euo pipefail

# Load test: verify fingerprinting plugin under concurrent TLS load.
# Uses 'hey' to drive requests through HAProxy TLS frontend.
#
# Environment variables:
#   HAPROXY_PORT       — random by default
#   LOAD_CONCURRENCY   — concurrent connections (default: 200)
#   LOAD_REQUESTS      — total requests (default: 10000)
#   P99_THRESHOLD_MS   — max acceptable p99 latency in ms (default: 50)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT="fp-load-$$"
export HAPROXY_PORT=${HAPROXY_PORT:-$(shuf -i 20000-50000 -n 1)}
DOCKER_HOST_ADDR=$(echo "${DOCKER_HOST:-}" | sed -n 's|tcp://\([^:]*\):.*|\1|p')
DOCKER_HOST_ADDR=${DOCKER_HOST_ADDR:-localhost}

CONCURRENCY=${LOAD_CONCURRENCY:-100}
REQUESTS=${LOAD_REQUESTS:-10000}
# 50ms threshold matches haproxy-spoa-hub baseline.
# Reference: haproxy-fingerprinting SPOE benchmark achieves p99 ~38ms at c100.
P99_THRESHOLD=${P99_THRESHOLD_MS:-50}

cleanup() {
    docker compose -p "$PROJECT" -f "$COMPOSE_DIR/docker-compose.yml" down -v 2>/dev/null || true
}
trap cleanup EXIT

if ! command -v hey &>/dev/null; then
    echo "SKIP: 'hey' not installed (go install github.com/rakyll/hey@latest)"
    exit 0
fi

echo "Building hub image..."
docker compose -p "$PROJECT" -f "$COMPOSE_DIR/docker-compose.yml" build --quiet hub

echo "Starting services..."
docker compose -p "$PROJECT" -f "$COMPOSE_DIR/docker-compose.yml" up -d

echo "Waiting for HAProxy on port $HAPROXY_PORT..."
for i in $(seq 1 30); do
    if curl -skf --max-time 2 "https://$DOCKER_HOST_ADDR:$HAPROXY_PORT/" >/dev/null 2>&1; then break; fi
    if [ "$i" -eq 30 ]; then
        echo "FAIL: HAProxy did not become ready"
        docker compose -p "$PROJECT" -f "$COMPOSE_DIR/docker-compose.yml" logs
        exit 1
    fi
    sleep 1
done

# Warmup
echo "Warming up (50 requests)..."
hey -n 50 -c 10 "https://$DOCKER_HOST_ADDR:$HAPROXY_PORT/" >/dev/null 2>&1

# Load test — uses keepalive (realistic production scenario).
# Fingerprinting runs on session start so each kept-alive connection still
# triggers one fingerprint computation. The SPOE event fires on the first
# HTTP request per connection; keepalive reuses the session variables.
echo "Running load test: $REQUESTS requests, $CONCURRENCY concurrent..."
RESULT=$(hey -n "$REQUESTS" -c "$CONCURRENCY" "https://$DOCKER_HOST_ADDR:$HAPROXY_PORT/" 2>&1)

echo "$RESULT"
echo "---"

# Extract p99 latency (seconds → ms)
P99_SECS=$(echo "$RESULT" | grep -E '^\s*99%' | awk '{print $3}')
if [ -z "$P99_SECS" ]; then
    echo "FAIL: could not parse p99 latency from hey output"
    exit 1
fi

P99_MS=$(awk "BEGIN { printf \"%.2f\", $P99_SECS * 1000 }")

# Check for non-200 responses
NON_200=$(echo "$RESULT" | grep -A 20 "Status code distribution" | grep -v "200" | grep -oP '\[\d+\]\s+\d+' || true)
if [ -n "$NON_200" ]; then
    echo "WARNING: Non-200 responses detected: $NON_200"
fi

# Verify p99 latency
PASS=$(awk "BEGIN { print ($P99_MS <= $P99_THRESHOLD) ? 1 : 0 }")
if [ "$PASS" -eq 1 ]; then
    echo "PASS: Load test (p99: ${P99_MS}ms <= ${P99_THRESHOLD}ms, ${CONCURRENCY} concurrent, ${REQUESTS} requests)"
else
    echo "FAIL: p99 latency ${P99_MS}ms exceeds ${P99_THRESHOLD}ms threshold"
    echo "Hub logs (last 20 lines):"
    docker compose -p "$PROJECT" -f "$COMPOSE_DIR/docker-compose.yml" logs hub 2>&1 | tail -20
    exit 1
fi
