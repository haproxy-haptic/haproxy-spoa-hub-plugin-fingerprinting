#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -f "$CERT_DIR/server.pem" && -f "$CERT_DIR/server.key" ]]; then
    echo "Certificates already exist in $CERT_DIR, skipping generation."
    exit 0
fi

echo "Generating self-signed CA and server certificate..."

# CA key and cert
openssl genrsa -out "$CERT_DIR/ca.key" 2048 2>/dev/null
openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" \
    -sha256 -days 365 -out "$CERT_DIR/ca.pem" \
    -subj "/CN=Benchmark CA" 2>/dev/null

# Server key and CSR
openssl genrsa -out "$CERT_DIR/server.key" 2048 2>/dev/null
openssl req -new -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/CN=*.bench.local" 2>/dev/null

# Sign server cert with CA
openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/server.crt" \
    -days 365 -sha256 \
    -extfile <(printf "subjectAltName=DNS:*.bench.local,DNS:haproxy,DNS:localhost") 2>/dev/null

# Combined PEM for HAProxy (cert + key)
cat "$CERT_DIR/server.crt" "$CERT_DIR/server.key" > "$CERT_DIR/server.pem"

# Cleanup intermediate files
rm -f "$CERT_DIR/server.csr"

echo "Certificates generated in $CERT_DIR"
