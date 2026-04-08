# Implementation Plan: JA4 TLS Fingerprinting

**Branch**: `002-ja4-fingerprinting` | **Date**: 2026-04-07 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/002-ja4-fingerprinting/spec.md`

## Summary

Add JA4 fingerprinting to the existing plugin crate, producing a structured 36-character `a_b_c` fingerprint alongside JA3/JA3N. JA4 uses SHA256 (truncated to 12 chars), includes human-readable metadata in section A (protocol, TLS version, SNI, counts, ALPN), and uses signature algorithms as a new input field. The SPOE message is extended with four additional arguments (`supported_versions`, `sigalgs`, `alpn`, `sni`). Server-negotiated ALPN is used as a best-effort approximation (documented limitation).

## Technical Context

**Language/Version**: Rust (edition 2024, minimum 1.86)
**Primary Dependencies**: `haproxy-spoa-hub-plugin-api` (abi_stable), `sha2` (SHA256), `md-5` (MD5, from feature 001)
**Storage**: N/A (stateless computation)
**Testing**: `cargo test` (unit tests with FoxIO JA4 reference values)
**Target Platform**: Linux (shared library, `.so`)
**Project Type**: Library (haproxy-spoa-hub plugin, cdylib)
**Performance Goals**: <1ms p99 latency per fingerprint computation
**Constraints**: Bounded memory per request, no accumulated state, FFI-safe via abi_stable
**Scale/Scope**: 10,000+ concurrent connections

## Constitution Check

| Principle | Status | Evidence |
|-----------|--------|----------|
| I. Code Quality | PASS | JA4 is a new `src/ja4/` module; shared parsing in `src/common/`; no modification to JA3 code |
| II. Testing Standards | PASS | TDD with FoxIO reference values; edge cases (empty fields, missing ALPN, count overflow) |
| III. User Experience Consistency | PASS | Same SPOE conventions; ALPN limitation documented; structured logging |
| IV. Performance Requirements | PASS | <1ms p99; stateless; SHA256 + sorting on small inputs; benchmarks planned |

No constitution violations. Gate passes.

## Project Structure

### Documentation (this feature)

```text
specs/002-ja4-fingerprinting/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── spoe-message-contract.md
└── tasks.md
```

### Source Code (changes to repository root)

```text
Cargo.toml                        # Add sha2 dependency

src/
├── common/
│   └── types.rs                  # Extend ClientHelloData with JA4 fields
├── ja4/                          # NEW module
│   ├── mod.rs                    # JA4 technique registration
│   ├── fingerprint.rs            # JA4 computation (sections A, B, C)
│   └── section_a.rs              # Section A metadata (version, SNI, ALPN)
├── config.rs                     # Add JA4-specific config params
├── plugin.rs                     # Extract new SPOE args, register JA4 technique
└── lib.rs                        # Add ja4 module declaration

tests/
├── ja4_test.rs                   # NEW: JA4 unit tests with FoxIO reference values
└── plugin_test.rs                # Extend with JA4 config tests

benches/
└── ja3_bench.rs                  # Add JA4 benchmarks (rename to fingerprint_bench.rs)

examples/
├── spoe-fingerprint.conf         # Update with JA4 SPOE args
└── hub.toml                      # Update with JA4 config example
```

**Structure Decision**: JA4 is added as `src/ja4/` alongside `src/ja3/`, following the extensible architecture. Shared types in `src/common/types.rs` are extended with optional JA4-specific fields. The `src/ja3/` module is not modified (SC-004).

## Complexity Tracking

No constitution violations to justify.
