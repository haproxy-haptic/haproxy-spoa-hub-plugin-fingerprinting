# Quickstart: TLS Fingerprinting Plugin

**Feature**: 001-tls-fingerprinting

## Prerequisites

- Rust toolchain (edition 2024, minimum 1.86)
- haproxy-spoa-hub built and available
- HAProxy 2.8+ with `USE_OPENSSL=1`

## Build

```bash
cargo build --release
```

Output: `target/release/libfingerprinting.so`

## Configure

### 1. Hub configuration (hub.toml)

```toml
[[plugins]]
name = "fingerprinting"
library = "libfingerprinting.so"
messages = ["get-fingerprint"]

[plugins.params]
ja3 = true
ja3n = true
```

### 2. SPOE configuration (spoe-fingerprint.conf)

```
[get-fingerprint]
spoe-message get-fingerprint
    args proto=ssl_fc_protocol_hello_id ciphers=ssl_fc_cipherlist_bin extensions=ssl_fc_extlist_bin curves=ssl_fc_eclist_bin formats=ssl_fc_ecformats_bin
    event on-client-session
```

### 3. HAProxy configuration

```haproxy
global
    tune.ssl.capture-buffer-size 256

frontend https
    bind *:443 ssl crt /etc/haproxy/cert.pem
    filter spoe engine fingerprinting config /etc/haproxy/spoe-fingerprint.conf

    http-request set-header X-JA3-Hash  %[var(sess.fingerprinting.ja3_hash)]
    http-request set-header X-JA3N-Hash %[var(sess.fingerprinting.ja3n_hash)]
    http-request set-header X-JA3-Raw   %[var(sess.fingerprinting.ja3_raw)]
    http-request set-header X-JA3N-Raw  %[var(sess.fingerprinting.ja3n_raw)]

    default_backend servers
```

## Verify

```bash
curl -k https://localhost:443 -v 2>&1 | grep X-JA3
```

Expected output:
```
< X-JA3-Hash: <32-char hex>
< X-JA3N-Hash: <32-char hex>
< X-JA3-Raw: 771,4865-4866-...,0-5-10-...,29-23-24,0
< X-JA3N-Raw: 771,4865-4866-...,0-5-10-...,29-23-24,0
```

## Run Tests

```bash
cargo test
```
