# HAProxy SPOA Hub — Fingerprinting Plugin

[![Build Status](https://gitlab.com/haproxy-haptic/haproxy-spoa-hub-plugin-fingerprinting/badges/master/pipeline.svg)](https://gitlab.com/haproxy-haptic/haproxy-spoa-hub-plugin-fingerprinting/-/pipelines)

A [haproxy-spoa-hub](https://gitlab.com/haproxy-haptic/haproxy-spoa-hub) plugin that computes TLS fingerprints from ClientHello data. Supports JA3, JA3N, and JA4.

## Overview

TLS fingerprinting extracts a stable identifier from the TLS ClientHello message sent by every client at the start of a connection. This fingerprint can be used for bot detection, client classification, rate limiting, or logging — without inspecting application-layer traffic.

The plugin receives pre-parsed ClientHello fields from HAProxy via the SPOE protocol and returns fingerprint hashes and raw strings as session-scoped variables.

### Supported Fingerprinting Methods

**JA3/JA3N** produce a 32-character MD5 hash of the raw fingerprint string `version,ciphers,extensions,curves,formats`. Both use the same algorithm — JA3N additionally sorts extensions numerically and excludes extension 41 (pre_shared_key), producing fingerprints that are stable across TLS extension randomization (Chrome 110+, Firefox 114+) and session resumption. The behavior is controlled by configuration parameters.

**JA4** produces a structured 36-character fingerprint in `a_b_c` format. Section A is human-readable metadata (protocol type, TLS version, SNI presence, cipher/extension counts, ALPN indicator). Sections B and C are truncated SHA256 hashes of sorted cipher suites and extensions/signature algorithms respectively. JA4 is designed to survive extension randomization by default and provides partial matching — you can match on section A alone for broad classification.

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

```toml
[[plugins]]
name = "fingerprinting"
library = "libfingerprinting_plugin.so"
messages = ["get-fingerprint"]
```

By default, the plugin produces JA3N and JA4 fingerprints. To customize:

```toml
[plugins.params]
sort_extensions = false     # JA3 instead of JA3N
exclude_extensions = []     # include all extensions (no exclusion)
ja4 = false                 # disable JA4
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
    args proto=ssl_fc_protocol_hello_id ciphers=ssl_fc_cipherlist_bin(1) extensions=ssl_fc_extlist_bin(1) curves=ssl_fc_eclist_bin(1) formats=ssl_fc_ecformats_bin supported_versions=ssl_fc_supported_versions_bin(1) sigalgs=ssl_fc_sigalgs_bin(1) alpn=ssl_fc_alpn sni=ssl_fc_has_sni
    event on-frontend-http-request if !{ var(sess.spoe.fingerprinting.hash) -m found }
```

The `if` condition ensures the fingerprint is computed only once per TLS session, not on every HTTP request within a kept-alive connection.

The `supported_versions`, `sigalgs`, `alpn`, and `sni` arguments are only needed for JA4. If you only use JA3/JA3N, you can omit them.

#### HAProxy frontend (`haproxy.cfg`)

```haproxy
global
    tune.ssl.capture-buffer-size 256

frontend https
    bind *:443 ssl crt /etc/haproxy/cert.pem
    filter spoe engine fingerprinting config /etc/haproxy/spoe-fingerprint.conf

    # JA3/JA3N
    http-request set-header X-Fingerprint-Hash %[var(sess.spoe.fingerprinting.hash)]
    http-request set-header X-Fingerprint-Raw  %[var(sess.spoe.fingerprinting.raw)]

    # JA4
    http-request set-header X-JA4     %[var(sess.spoe.fingerprinting.ja4)]
    http-request set-header X-JA4-Raw %[var(sess.spoe.fingerprinting.ja4_r)]

    default_backend app

backend spoa-hub-backend
    mode spop
    server hub /var/run/spoe/hub.sock
```

!!! warning
    `tune.ssl.capture-buffer-size` must be at least 256 bytes. Without it, HAProxy does not capture ClientHello data and the plugin receives empty fields.

### Verify

```bash
curl -k https://localhost:443/ -v 2>&1 | grep -E 'X-(Fingerprint|JA4)'
```

## Configuration Reference

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sort_extensions` | boolean | `true` | Sort extensions numerically (JA3N behavior). Set to `false` for standard JA3. |
| `exclude_extensions` | array of integers | `[41]` | TLS extension IDs to omit from the JA3/JA3N extensions field before hashing. Set to `[]` to include all extensions. See below. |
| `ja4` | boolean | `true` | Enable JA4 fingerprinting. When disabled, only JA3/JA3N variables are produced. |

#### Why exclude extensions?

Some TLS extensions carry per-session data that changes on every connection, even from the same client. If included in the fingerprint, they make the hash unstable — the same browser would produce a different fingerprint every time it connects.

The default excludes extension 41 (`pre_shared_key`), which contains TLS session resumption tickets. This is the standard behavior for JA3N.

You can exclude multiple extensions:

```toml
[plugins.params]
exclude_extensions = [41, 43]
```

Set `exclude_extensions = []` if you want the raw JA3 fingerprint with no extensions removed.

### Output Variables

The plugin sets session-scoped variables, namespaced under the plugin name by the hub:

| Variable | Format | Description |
|----------|--------|-------------|
| `hash` | 32-char lowercase hex | JA3/JA3N MD5 digest |
| `raw` | Variable length | JA3/JA3N raw fingerprint string: `version,ciphers,extensions,curves,formats` |
| `ja4` | 36 chars (`a_b_c`) | JA4 fingerprint with SHA256-truncated sections |
| `ja4_r` | Variable length | JA4 raw fingerprint with full sorted hex lists |

In HAProxy, access these as `%[var(sess.spoe.fingerprinting.hash)]`, `%[var(sess.spoe.fingerprinting.ja4)]`, etc.

### Getting Both JA3 and JA3N

Register the plugin twice under different names:

```toml
[[plugins]]
name = "ja3"
library = "libfingerprinting_plugin.so"
messages = ["get-fingerprint"]

[plugins.params]
sort_extensions = false
exclude_extensions = []
ja4 = false

[[plugins]]
name = "ja3n"
library = "libfingerprinting_plugin.so"
messages = ["get-fingerprint"]

[plugins.params]
sort_extensions = true
exclude_extensions = [41]
ja4 = false
```

This produces separate variables: `sess.spoe.ja3.hash`, `sess.spoe.ja3n.hash`, etc.

### JA4 Known Limitation: ALPN

HAProxy does not expose the client-offered ALPN list from the ClientHello. The `ssl_fc_alpn` fetch returns the server-negotiated ALPN protocol. The plugin uses this as a best-effort approximation for JA4's ALPN indicator field. In practice, servers almost always select the client's preferred protocol, so the field matches in the vast majority of cases.

When the server overrides client preference, section A (and therefore the full JA4 hash) will differ from reference implementations that have access to the raw ClientHello. This is the same approach used by other HAProxy JA4 implementations ([FriendlyCaptcha](https://github.com/FriendlyCaptcha/ja4-haproxy), [O-X-L](https://github.com/O-X-L/haproxy-ja4-fingerprint)).

## Performance

Benchmarked with HAProxy 3.3, haproxy-spoa-hub, fortio (30s, keepalive), Kind cluster:

| Config | Concurrency | Requests/sec | p50 | p99 |
|--------|------------|-------------|-----|-----|
| Baseline (TLS, no SPOE) | 100 | 143,000 | 0.67ms | 2.59ms |
| Fingerprinting (SPOE) | 100 | 140,000 | 0.68ms | 2.61ms |

SPOE overhead is ~10us at p50. Plugin computation (Criterion benchmarks):

| Fingerprint | Time |
|-------------|------|
| JA3N | 1.9 us |
| JA4 | 5.7 us |
| JA3N + JA4 combined | 7.5 us |

## Development

### Commands

```bash
cargo build --release            # Build plugin .so
cargo test                       # Unit tests (40 tests)
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
  config.rs           Plugin configuration (sort_extensions, exclude_extensions, ja4)
  technique.rs        FingerprintTechnique trait (extensibility point)
  common/
    grease.rs         GREASE value detection (RFC 8701)
    parse.rs          Binary field parsing (big-endian u16, u8)
    types.rs          ClientHelloData struct
  ja3/
    mod.rs            JA3/JA3N technique implementations
    fingerprint.rs    Core compute_ja3() algorithm (MD5)
  ja4/
    mod.rs            JA4 module entry point
    fingerprint.rs    JA4 computation (SHA256, sections A/B/C)
    section_a.rs      Section A metadata (TLS version, SNI, ALPN)

tests/
  ja3_test.rs         JA3 correctness (open-ch/ja3, Wireshark vectors)
  ja4_test.rs         JA4 correctness (FoxIO reference vectors)
  grease_test.rs      GREASE detection
  parse_test.rs       Binary parsing edge cases
  plugin_test.rs      Configuration and integration tests
```

## License

MIT
