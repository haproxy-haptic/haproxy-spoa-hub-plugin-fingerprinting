#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# haproxy-spoa-hub is expected as a sibling directory
HUB_ROOT="$(cd "$PROJECT_ROOT/../haproxy-spoa-hub" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
CLUSTER_NAME="fingerprinting-bench"

HAPROXY_VERSION="${HAPROXY_VERSION:-3.3}"
CONFIGS=("baseline" "fingerprinting")
CONCURRENCY_LEVELS=(${CONCURRENCY_LEVELS:-100 1000 5000 10000})
BENCH_DURATION="30s"

RESULTS_ONLY=false

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --version VERSION    HAProxy version (default: 3.0)"
    echo "  --results-only       Skip running, just print report"
    echo "  -h, --help           Show this help"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) HAPROXY_VERSION="$2"; shift 2 ;;
        --results-only) RESULTS_ONLY=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

if ! kind version &>/dev/null; then
    if [[ -x /home/linuxbrew/.linuxbrew/bin/kind ]]; then
        export PATH="/home/linuxbrew/.linuxbrew/bin:$PATH"
    fi
fi

if [[ "$RESULTS_ONLY" == true ]]; then
    exec "$SCRIPT_DIR/report.sh"
fi

# Generate TLS certs if needed
"$SCRIPT_DIR/certs/generate-certs.sh"

mkdir -p "$RESULTS_DIR"

# --- Create kind cluster ---
echo "=== Creating kind cluster '$CLUSTER_NAME' ==="
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo "Cluster '$CLUSTER_NAME' already exists, reusing."
else
    kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"
fi

cleanup() {
    echo "=== Deleting kind cluster '$CLUSTER_NAME' ==="
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
}
trap cleanup EXIT

# --- Build Docker images ---
echo "=== Building Docker images ==="

# Baseline HAProxy (haproxytech image)
echo "--- Building baseline HAProxy $HAPROXY_VERSION ---"
echo "FROM haproxytech/haproxy-debian:${HAPROXY_VERSION}" | \
    docker build --platform linux/amd64 -t "bench-baseline:${HAPROXY_VERSION}" - 2>/dev/null
docker save "bench-baseline:${HAPROXY_VERSION}" | \
    kind load image-archive /dev/stdin --name "$CLUSTER_NAME"

# HAProxy for fingerprinting (same base image)
echo "FROM haproxytech/haproxy-debian:${HAPROXY_VERSION}" | \
    docker build --platform linux/amd64 -t "bench-haproxy:${HAPROXY_VERSION}" - 2>/dev/null
docker save "bench-haproxy:${HAPROXY_VERSION}" | \
    kind load image-archive /dev/stdin --name "$CLUSTER_NAME"

# Hub + fingerprinting plugin
echo "--- Building hub + fingerprinting plugin ---"
docker build \
    -t bench-hub:latest \
    -f "$SCRIPT_DIR/docker/Dockerfile.hub" \
    "$PROJECT_ROOT/.."
docker save bench-hub:latest | \
    kind load image-archive /dev/stdin --name "$CLUSTER_NAME"

# Fortio
echo "FROM fortio/fortio:latest" | \
    docker build --platform linux/amd64 -t bench-fortio:latest - 2>/dev/null
docker save bench-fortio:latest | \
    kind load image-archive /dev/stdin --name "$CLUSTER_NAME"

image_for_config() {
    local config="$1"
    case "$config" in
        baseline)       echo "bench-baseline:${HAPROXY_VERSION}" ;;
        fingerprinting) echo "bench-haproxy:${HAPROXY_VERSION}" ;;
    esac
}

run_benchmark() {
    local config="$1" concurrency="$2"
    local ns="bench-${HAPROXY_VERSION}-${config}-c${concurrency}"
    ns="${ns//./-}"
    local image labels result_file

    image=$(image_for_config "$config")
    labels="haproxy=${HAPROXY_VERSION},config=${config},concurrency=${concurrency}"
    result_file="${RESULTS_DIR}/${HAPROXY_VERSION}_${config}_c${concurrency}.json"

    echo "--- Running: HAProxy $HAPROXY_VERSION / $config / c=$concurrency ---"

    kubectl create namespace "$ns" 2>/dev/null || true

    # TLS secret
    kubectl -n "$ns" create secret generic haproxy-tls \
        --from-file="server.pem=$SCRIPT_DIR/certs/server.pem" \
        2>/dev/null || true

    # HAProxy config
    kubectl -n "$ns" create configmap haproxy-config \
        --from-file="haproxy.cfg=$SCRIPT_DIR/configs/haproxy-${config}.cfg" \
        2>/dev/null || true

    if [[ "$config" == "fingerprinting" ]]; then
        # SPOE + hub configs
        kubectl -n "$ns" create configmap spoe-config \
            --from-file="spoe-fingerprint.conf=$SCRIPT_DIR/configs/spoe-fingerprint.conf" \
            2>/dev/null || true
        kubectl -n "$ns" create configmap hub-config \
            --from-file="config.toml=$SCRIPT_DIR/configs/hub-config.toml" \
            2>/dev/null || true

        sed "s|HAPROXY_IMAGE_PLACEHOLDER|${image}|g" \
            "$SCRIPT_DIR/manifests/fingerprinting-deployment.yaml" | \
            kubectl -n "$ns" apply -f -
    else
        sed "s|HAPROXY_IMAGE_PLACEHOLDER|${image}|g" \
            "$SCRIPT_DIR/manifests/baseline-deployment.yaml" | \
            kubectl -n "$ns" apply -f -
    fi

    kubectl -n "$ns" apply -f "$SCRIPT_DIR/manifests/haproxy-service.yaml"
    kubectl -n "$ns" rollout status deployment/haproxy --timeout=120s

    # Run fortio
    sed -e "s|CONCURRENCY_PLACEHOLDER|${concurrency}|g" \
        -e "s|LABELS_PLACEHOLDER|${labels}|g" \
        "$SCRIPT_DIR/manifests/fortio-job.yaml" | kubectl -n "$ns" apply -f -

    kubectl -n "$ns" wait --for=condition=complete job/fortio-bench --timeout=300s || {
        echo "WARNING: fortio job did not complete for $ns"
        kubectl -n "$ns" logs job/fortio-bench > "$result_file" 2>/dev/null || true
        kubectl delete namespace "$ns" --wait=false 2>/dev/null || true
        return 1
    }

    # Extract JSON result
    local start_line end_line
    start_line=$(kubectl -n "$ns" logs job/fortio-bench | grep -n "^{$" | tail -1 | cut -d: -f1)
    end_line=$(kubectl -n "$ns" logs job/fortio-bench | grep -n "^}$" | tail -1 | cut -d: -f1)
    if [[ -n "$start_line" && -n "$end_line" ]]; then
        kubectl -n "$ns" logs job/fortio-bench | \
            sed -n "${start_line},${end_line}p" | \
            grep -v "^Successfully wrote" > "$result_file"
    else
        kubectl -n "$ns" logs job/fortio-bench > "$result_file"
    fi

    kubectl delete namespace "$ns" --wait=false 2>/dev/null || true
    echo "  -> Results saved to $result_file"
}

# --- Run benchmark matrix ---
echo ""
echo "=== Starting benchmark matrix ==="
echo "  HAProxy version:  $HAPROXY_VERSION"
echo "  Configurations:   ${CONFIGS[*]}"
echo "  Concurrency:      ${CONCURRENCY_LEVELS[*]}"
echo "  Duration:          $BENCH_DURATION per run"
echo ""

for config in "${CONFIGS[@]}"; do
    for concurrency in "${CONCURRENCY_LEVELS[@]}"; do
        run_benchmark "$config" "$concurrency" || true
    done
done

echo ""
echo "=== All benchmarks complete ==="
echo ""

"$SCRIPT_DIR/report.sh"
