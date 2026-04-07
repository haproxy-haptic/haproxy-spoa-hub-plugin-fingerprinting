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

Output: `target/release/libfingerprinting.so`

## Configure

### 1. Hub configuration (hub.toml)

```toml
[[plugins]]
name = "fingerprinting"
library = "libfingerprinting.so"
messages = ["get-fingerprint"]
```

### 2. SPOE configuration (spoe-fingerprint.conf)

```
[get-fingerprint]
spoe-message get-fingerprint
    args proto=ssl_fc_protocol_hello_id ciphers=ssl_fc_cipherlist_bin extensions=ssl_fc_extlist_bin curves=ssl_fc_eclist_bin formats=ssl_fc_ecformats_bin supported_versions=ssl_fc_supported_versions_bin sigalgs=ssl_fc_sigalgs_bin alpn=ssl_fc_alpn
    event on-client-session
```

### 3. HAProxy configuration

```haproxy
global
    tune.ssl.capture-buffer-size 256

frontend https
    bind *:443 ssl crt /etc/haproxy/cert.pem
    filter spoe engine fingerprinting config /etc/haproxy/spoe-fingerprint.conf

    # JA3/JA3N variables
    http-request set-header X-JA3-Hash    %[var(sess.fingerprinting.ja3_hash)]
    http-request set-header X-JA3N-Hash   %[var(sess.fingerprinting.ja3n_hash)]

    # JA4 variables
    http-request set-header X-JA4         %[var(sess.fingerprinting.ja4)]
    http-request set-header X-JA4-Raw     %[var(sess.fingerprinting.ja4_r)]

    default_backend servers
```

## Verify

```bash
curl -k https://localhost:443 -v 2>&1 | grep -E 'X-JA[34]'
```

Expected output:
```
< X-JA3-Hash: <32-char hex>
< X-JA3N-Hash: <32-char hex>
< X-JA4: t13d1207h2_<12-char hash>_<12-char hash>
< X-JA4-Raw: t13d1207h2_<sorted cipher hex list>_<sorted ext hex list>_<sigalg hex list>
```

## Run Tests

```bash
cargo test
```
