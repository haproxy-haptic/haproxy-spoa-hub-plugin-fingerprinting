# Implementation Plan: JA4 TLS Fingerprinting

**Branch**: `002-ja4-fingerprinting` | **Date**: 2026-04-06 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/002-ja4-fingerprinting/spec.md`

## Summary

Add JA4 fingerprinting to the existing fingerprinting plugin, producing a structured 36-character `a_b_c` fingerprint alongside JA3/JA3N. JA4 uses SHA256 (truncated to 12 chars) instead of MD5, includes human-readable metadata (protocol, version, SNI, counts, ALPN) in section A, and handles signature algorithms as a new input field. The SPOE message is extended with three additional arguments (`supported_versions`, `sigalgs`, `alpn`).

## Technical Context

**Language/Version**: Rust (edition 2024, minimum 1.86)
**Primary Dependencies**: `haproxy-spoa-hub-plugin-api` (abi_stable plugin trait), `sha2` (SHA256), `md-5` (MD5, from feature 001)
**Storage**: N/A (stateless computation)
**Testing**: `cargo test` (unit tests with known ClientHello data from FoxIO reference repository)
**Target Platform**: Linux (shared library, `.so`)
**Project Type**: Library (haproxy-spoa-hub plugin)
**Performance Goals**: <1ms p99 latency per fingerprint computation
**Constraints**: Bounded memory per request, no accumulated state, FFI-safe via abi_stable
**Scale/Scope**: 10,000+ concurrent connections

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Evidence |
|-----------|--------|----------|
| I. Code Quality | PASS | JA4 module is isolated with single responsibility; shared parsing utilities (GREASE filter, binary decoding) are reused from feature 001; public API documented via SpoePlugin trait |
| II. Testing Standards | PASS | Unit tests with known reference values (Chrome, Firefox, curl) from FoxIO repository; edge cases covered (empty fields, missing args, GREASE-only ciphers, count overflow); TDD workflow planned |
| III. User Experience Consistency | PASS | SPOE config follows HAProxy conventions; output variables use consistent `ja4`/`ja4_r` naming; ALPN limitation documented; warnings logged on unusual inputs |
| IV. Performance Requirements | PASS | <1ms p99 target; stateless computation with bounded memory; SHA256 + sorting are O(n log n) on small inputs; benchmarks planned |

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

### Source Code (repository root)

```text
src/
├── lib.rs                  # Plugin entry point (define_plugin! macro, SpoePlugin impl)
├── common/
│   ├── mod.rs
│   ├── grease.rs           # GREASE detection (shared)
│   ├── parse.rs            # Binary field parsing (shared)
│   └── types.rs            # ClientHelloData struct (shared)
├── ja3/
│   ├── mod.rs
│   └── fingerprint.rs      # JA3/JA3N computation (from feature 001)
└── ja4/
    ├── mod.rs
    ├── fingerprint.rs       # JA4 computation (section A, B, C)
    └── section_a.rs         # Section A metadata builder (version, SNI, ALPN logic)

tests/
├── ja3_test.rs             # JA3/JA3N unit tests (from feature 001)
├── ja4_test.rs             # JA4 unit tests with FoxIO reference values
└── common_test.rs          # Shared parsing and GREASE filter tests

examples/
└── spoe-fingerprint.conf   # Example SPOE configuration
```

**Structure Decision**: Single Rust crate compiled as a shared library. JA4 is a new module (`src/ja4/`) alongside the existing JA3 module (`src/ja3/`), sharing common utilities (`src/common/`). This follows the extensible architecture from feature 001.

## Complexity Tracking

No constitution violations to justify.
