# HAProxy SPOA Hub — Fingerprinting Plugin

[![Build Status](https://gitlab.com/haproxy-haptic/haproxy-spoa-hub-plugin-fingerprinting/badges/master/pipeline.svg)](https://gitlab.com/haproxy-haptic/haproxy-spoa-hub-plugin-fingerprinting/-/pipelines)

A [haproxy-spoa-hub](https://gitlab.com/haproxy-haptic/haproxy-spoa-hub) plugin that computes TLS fingerprints from ClientHello data. Currently supports JA3 and JA3N; JA4 support is planned.

## Overview

TLS fingerprinting extracts a stable identifier from the TLS ClientHello message sent by every client at the start of a connection. This fingerprint can be used for bot detection, client classification, rate limiting, or logging — without inspecting application-layer traffic.

The plugin receives pre-parsed ClientHello fields from HAProxy via the SPOE protocol and returns an MD5 hash and raw fingerprint string as session-scoped variables.

**JA3 vs JA3N:** Both use the same algorithm. JA3N additionally sorts extensions numerically and excludes extension 41 (pre_shared_key), producing fingerprints that are stable across TLS extension randomization (Chrome 110+, Firefox 114+) and session resumption. The plugin's behavior is controlled by two configuration parameters — there is no separate "JA3 mode" or "JA3N mode."

## Quick Start

### Prerequisites

- [haproxy-spoa-hub](https://gitlab.com/haproxy-haptic/haproxy-spoa-hub) built and running
- HAProxy >= 2.8 with `USE_OPENSSL=1`
- Rust toolchain (>= 1.86) for building the plugin

### Build

```bash
cargo build --release
```

The output is `target/release/libfingerprinting_plugin.so`. Copy it to the hub's plugin directory.

### Configure the Hub

Add the plugin to your hub configuration:

```toml
[[plugins]]
name = "fingerprinting"
library = "libfingerprinting_plugin.so"
messages = ["get-fingerprint"]
```

By default, the plugin produces JA3N fingerprints (sorted extensions, extension 41 excluded). To customize:

```toml
[plugins.params]
sort_extensions = false     # JA3 instead of JA3N
exclude_extension = -1      # include all extensions (no exclusion)
```

### Configure HAProxy

#### SPOE agent definition (`spoe-fingerprint.conf`)

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
    args proto=ssl_fc_protocol_hello_id ciphers=ssl_fc_cipherlist_bin extensions=ssl_fc_extlist_bin curves=ssl_fc_eclist_bin formats=ssl_fc_ecformats_bin
    event on-frontend-http-request if !{ var(sess.spoe.fingerprinting.hash) -m found }
```

The `if` condition ensures the fingerprint is computed only once per TLS session, not on every HTTP request within a kept-alive connection.

#### HAProxy frontend (`haproxy.cfg`)

```haproxy
global
    tune.ssl.capture-buffer-size 256

frontend https
    bind *:443 ssl crt /etc/haproxy/cert.pem
    filter spoe engine fingerprinting config /etc/haproxy/spoe-fingerprint.conf

    http-request set-header X-Fingerprint-Hash %[var(sess.spoe.fingerprinting.hash)]
    http-request set-header X-Fingerprint-Raw  %[var(sess.spoe.fingerprinting.raw)]

    default_backend app

backend spoa-hub-backend
    mode spop
    server hub /var/run/spoe/hub.sock
```

!!! warning
    `tune.ssl.capture-buffer-size` must be at least 256 bytes. Without it, HAProxy does not capture ClientHello data and the plugin receives empty fields.

### Verify

```bash
curl -k https://localhost:443/ -v 2>&1 | grep X-Fingerprint
```

## Configuration Reference

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sort_extensions` | boolean | `true` | Sort extensions numerically (JA3N behavior). Set to `false` for standard JA3. |
| `exclude_extension` | integer | `41` | Extension ID to exclude from the fingerprint. Set to `-1` to include all extensions. Extension 41 (pre_shared_key) is excluded by default because it contains session-specific data that changes per connection. |

### Output Variables

The plugin sets two session-scoped variables, namespaced under the plugin name by the hub:

| Variable | Example HAProxy access | Description |
|----------|----------------------|-------------|
| `hash` | `%[var(sess.spoe.fingerprinting.hash)]` | 32-character lowercase hex MD5 digest |
| `raw` | `%[var(sess.spoe.fingerprinting.raw)]` | Raw fingerprint string: `version,ciphers,extensions,curves,formats` |

### Getting Both JA3 and JA3N

Register the plugin twice under different names:

```toml
[[plugins]]
name = "ja3"
library = "libfingerprinting_plugin.so"
messages = ["get-fingerprint"]

[plugins.params]
sort_extensions = false

[[plugins]]
name = "ja3n"
library = "libfingerprinting_plugin.so"
messages = ["get-fingerprint"]

[plugins.params]
sort_extensions = true
```

This produces separate variables: `sess.spoe.ja3.hash`, `sess.spoe.ja3n.hash`, etc.

## Performance

Benchmarked with HAProxy 3.3, haproxy-spoa-hub, fortio (30s, keepalive), Kind cluster:

| Config | Concurrency | Requests/sec | p50 | p99 |
|--------|------------|-------------|-----|-----|
| Baseline (TLS, no SPOE) | 100 | 143,000 | 0.67ms | 2.59ms |
| Fingerprinting (SPOE) | 100 | 140,000 | 0.68ms | 2.61ms |

SPOE overhead is ~10us at p50 — effectively within measurement noise. The plugin computation itself takes ~1.7us per fingerprint (Criterion benchmark).

## Development

### Commands

```bash
cargo build --release            # Build plugin .so
cargo test                       # Unit tests (27 tests)
cargo bench                      # Criterion microbenchmarks
cargo clippy -- -D warnings      # Lint
```

### Running Benchmarks

The `benchmarks/` directory contains a Kind-based benchmark suite that compares the fingerprinting plugin against a baseline HAProxy (TLS only, no SPOE):

```bash
cd benchmarks
CONCURRENCY_LEVELS="100 1000" ./run-benchmarks.sh
```

Requires: Docker, kind, kubectl, and a local checkout of [haproxy-spoa-hub](https://gitlab.com/haproxy-haptic/haproxy-spoa-hub) as a sibling directory.

### Project Structure

```
src/
  lib.rs              Module declarations
  plugin.rs           SpoePlugin implementation (define_plugin! macro)
  config.rs           Plugin configuration (sort_extensions, exclude_extension)
  technique.rs        FingerprintTechnique trait (extensibility point)
  common/
    grease.rs         GREASE value detection (RFC 8701)
    parse.rs          Binary field parsing (big-endian u16, u8)
    types.rs          ClientHelloData struct
  ja3/
    mod.rs            JA3/JA3N technique implementations
    fingerprint.rs    Core compute_ja3() algorithm

tests/
  ja3_test.rs         Correctness tests against authoritative JA3 vectors
  grease_test.rs      GREASE detection
  parse_test.rs       Binary parsing edge cases
  plugin_test.rs      Configuration and integration tests
```

## License

MIT
