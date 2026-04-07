# Research: TLS Fingerprinting Plugin

**Feature**: 001-tls-fingerprinting
**Date**: 2026-04-06

## Decision: Plugin API Integration

**Decision**: Use `haproxy-spoa-hub-plugin-api` crate with the `define_plugin!` macro to implement the `SpoePlugin` trait.

**Rationale**: This is the only supported plugin interface for haproxy-spoa-hub. The macro handles FFI safety (abi_stable), panic catching, and factory function generation. Existing example plugins (noop, echo, delay) demonstrate the pattern.

**Alternatives considered**:
- Direct abi_stable implementation without macro — rejected because the macro provides panic safety and reduces boilerplate with no downside.

## Decision: SPOE Message Format

**Decision**: Use individual SPOE message arguments sourced from HAProxy's `ssl_fc_*` sample fetch functions, matching the existing haproxy-fingerprinting project's conventions.

**Rationale**: HAProxy's SSL capture buffer stores pre-parsed field arrays, not raw ClientHello bytes. The `ssl_fc_*_bin` fetches expose these fields individually. The existing haproxy-fingerprinting SPOE agent already uses this exact format (`proto`, `ciphers`, `extensions`, `curves`, `formats`), proving it works.

**SPOE argument list**:

| Argument | HAProxy Fetch | Format |
|----------|---------------|--------|
| `proto` | `ssl_fc_protocol_hello_id` | Integer (u16 TLS version) |
| `ciphers` | `ssl_fc_cipherlist_bin` | Binary big-endian u16 pairs |
| `extensions` | `ssl_fc_extlist_bin` | Binary big-endian u16 pairs |
| `curves` | `ssl_fc_eclist_bin` | Binary big-endian u16 pairs |
| `formats` | `ssl_fc_ecformats_bin` | Binary u8 values |

**Note on GREASE filtering**: The `_bin` fetches accept an optional `(1)` argument to pre-filter GREASE. The plugin performs its own GREASE filtering for consistency, so these fetches are called without the filter argument.

## Decision: JA3 Algorithm Implementation

**Decision**: Implement a single `compute_ja3()` function parameterized by `sort_extensions: bool`. JA3N calls it with `true`, JA3 with `false`. Both exclude extension 41 (pre_shared_key).

**Rationale**: JA3 and JA3N differ only in extension sorting. A single parameterized function eliminates duplication. The existing C implementation in haproxy-fingerprinting uses the same approach (`sort_ext` and `exclude_ext` parameters on `compute_ja3()`).

## Decision: MD5 Hashing

**Decision**: Use the `md-5` crate from the RustCrypto project.

**Rationale**: Same crate used by the existing haproxy-fingerprinting SPOE agent. Pure Rust, no system dependencies, well-audited.

## Decision: GREASE Detection

**Decision**: Implement GREASE detection as `(v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)` for u16 values.

**Rationale**: This is the standard bitwise check per RFC 8701. Matches the existing C and Rust implementations in haproxy-fingerprinting. GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa.

## Decision: Extensible Architecture

**Decision**: Define an internal `FingerprintTechnique` trait with `name()`, `compute()`, and `output_variables()` methods. Each technique is a separate module. The plugin's `process()` iterates over enabled techniques and collects their output variables.

**Rationale**: Techniques share input parsing (binary field decoding, GREASE filtering) but differ in algorithm and output format. The trait abstraction allows adding JA4 (or others) later by implementing a new module without touching existing code. This satisfies SC-005.

## Decision: Technique Configuration

**Decision**: Each fingerprinting technique is enabled/disabled via a boolean plugin parameter (e.g., `ja3 = true`, `ja3n = false`). All techniques enabled by default.

**Rationale**: Operators may not need all fingerprint types. Disabling unused techniques saves computation. The hub's plugin config (`[plugins.params]` TOML table) supports boolean values natively, and the plugin can validate config via JSON Schema (`config_schema()`).

## Decision: Project Structure

**Decision**: Single Rust crate compiled as a cdylib shared library.

**Rationale**: The plugin is a self-contained `.so` file loaded by haproxy-spoa-hub. No need for multiple crates — the plugin is small and cohesive.

## Decision: Test Data

**Decision**: Use real ClientHello data from the existing haproxy-fingerprinting test suite (Chrome, Firefox, curl) as test vectors.

**Rationale**: These are proven reference values already validated against HAProxy Enterprise's JA3N output. The C test suite (`tests/test_ja3.c`) and Rust tests (`spoe-agent/src/main.rs`) contain the exact binary inputs and expected outputs.
