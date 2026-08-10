#!/usr/bin/env bash
set -euo pipefail

# E2E quickstart: build, start HAProxy+hub+plugin, send TLS request,
# verify fingerprint variables are returned in response headers.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT="fp-e2e-$$"
export HAPROXY_PORT=${HAPROXY_PORT:-$(shuf -i 20000-50000 -n 1)}
DOCKER_HOST_ADDR=$(echo "${DOCKER_HOST:-}" | sed -n 's|tcp://\([^:]*\):.*|\1|p')
DOCKER_HOST_ADDR=${DOCKER_HOST_ADDR:-localhost}

cleanup() {
    docker compose -p "$PROJECT" -f "$COMPOSE_DIR/docker-compose.yml" down -v 2>/dev/null || true
}
trap cleanup EXIT

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

echo "Sending TLS request..."
RESPONSE_HEADERS=$(curl -sk -D - -o /dev/null --max-time 5 "https://$DOCKER_HOST_ADDR:$HAPROXY_PORT/" 2>/dev/null)
RESPONSE_BODY=$(curl -sk --max-time 5 "https://$DOCKER_HOST_ADDR:$HAPROXY_PORT/" 2>/dev/null)

echo "Response body:"
echo "$RESPONSE_BODY"
echo "---"

# Verify fingerprint hash is present and is 32-char hex
HASH=$(echo "$RESPONSE_BODY" | grep "^hash=" | head -1 | cut -d= -f2 | tr -d '[:space:]')

if [ -z "$HASH" ]; then
    echo "FAIL: fingerprint hash not found in response"
    echo "Response headers:"
    echo "$RESPONSE_HEADERS"
    sleep 1
    echo "Hub logs:"
    docker compose -p "$PROJECT" -f "$COMPOSE_DIR/docker-compose.yml" logs hub 2>&1
    exit 1
fi

if [ ${#HASH} -ne 32 ]; then
    echo "FAIL: hash length is ${#HASH}, expected 32"
    exit 1
fi

# Match in-shell: with `| grep -q`, grep exits on first match, the
# producer takes SIGPIPE, and pipefail reports 141 -- a match read as a miss.
if ! [[ "$HASH" =~ ^[0-9a-f]{32}$ ]]; then
    echo "FAIL: hash is not valid hex: $HASH"
    exit 1
fi

# Verify hub logs show plugin activity
sleep 1
HUB_LOGS=$(docker compose -p "$PROJECT" -f "$COMPOSE_DIR/docker-compose.yml" logs hub 2>&1)

if [[ "$HUB_LOGS" != *"plugin loaded"* ]]; then
    echo "FAIL: hub logs missing 'plugin loaded'"
    echo "$HUB_LOGS"
    exit 1
fi

echo "PASS: E2E quickstart"
echo "  hash: $HASH"
