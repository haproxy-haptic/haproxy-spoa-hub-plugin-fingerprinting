# Quickstart: JA4 TLS Fingerprinting

**Feature**: 002-ja4-fingerprinting

## Prerequisites

- Rust toolchain (edition 2024, minimum 1.86)
- haproxy-spoa-hub built and available
- HAProxy 2.8+ with `USE_OPENSSL=1`

## Build

```bash
cargo build --release
```

Output: `target/release/libfingerprinting_plugin.so`

## Configure

### 1. Hub configuration (hub.toml)

```toml
[[plugins]]
name = "fingerprinting"
library = "libfingerprinting_plugin.so"
messages = ["get-fingerprint"]
```

### 2. SPOE configuration (spoe-fingerprint.conf)

```
[fingerprinting]
spoe-agent fingerprinting-agent
    messages get-fingerprint
    option var-prefix spoe
    option continue-on-error
    timeout hello      2s
    timeout idle       5m
    timeout processing 50ms
    use-backend spoa-hub-backend

spoe-message get-fingerprint
    args proto=ssl_fc_protocol_hello_id ciphers=ssl_fc_cipherlist_bin(1) extensions=ssl_fc_extlist_bin(1) curves=ssl_fc_eclist_bin(1) formats=ssl_fc_ecformats_bin supported_versions=ssl_fc_supported_versions_bin(1) sigalgs=ssl_fc_sigalgs_bin(1) alpn=ssl_fc_alpn sni=ssl_fc_has_sni
    event on-frontend-http-request if !{ var(sess.spoe.fingerprinting.hash) -m found }
```

### 3. HAProxy configuration

```haproxy
global
    tune.ssl.capture-buffer-size 256

frontend https
    bind *:443 ssl crt /etc/haproxy/cert.pem
    filter spoe engine fingerprinting config /etc/haproxy/spoe-fingerprint.conf

    # JA3N variables (from feature 001 config)
    http-request set-header X-Fingerprint-Hash %[var(sess.spoe.fingerprinting.hash)]

    # JA4 variables
    http-request set-header X-JA4     %[var(sess.spoe.fingerprinting.ja4)]
    http-request set-header X-JA4-Raw %[var(sess.spoe.fingerprinting.ja4_r)]

    default_backend servers

backend spoa-hub-backend
    mode spop
    server hub /var/run/spoe/hub.sock
```

## Verify

```bash
curl -k https://localhost:443/ -v 2>&1 | grep -E 'X-(Fingerprint|JA4)'
```

Expected output:
```
< X-Fingerprint-Hash: <32-char hex>
< X-JA4: t13d1207h2_<12-char hash>_<12-char hash>
< X-JA4-Raw: t13d1207h2_<sorted cipher hex>_<sorted ext hex>_<sigalg hex>
```

## Run Tests

```bash
cargo test
```
