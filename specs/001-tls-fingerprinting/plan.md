# Implementation Plan: TLS Fingerprinting Plugin

**Branch**: `001-tls-fingerprinting` | **Date**: 2026-04-06 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/001-tls-fingerprinting/spec.md`

## Summary

Implement a haproxy-spoa-hub plugin that computes JA3 and JA3N TLS fingerprints from ClientHello data received via SPOE messages. The plugin uses a single parameterized algorithm (sort vs. unsorted extensions) to produce both variants, returns technique-prefixed session-scoped variables, supports enabling/disabling individual techniques via plugin params, and provides an extensible internal architecture for future fingerprinting methods.

## Technical Context

**Language/Version**: Rust (edition 2024, minimum 1.86)
**Primary Dependencies**: `haproxy-spoa-hub-plugin-api` (abi_stable plugin trait), `abi_stable` (FFI-safe types), `md-5` (MD5 hashing), `log` (structured logging)
**Storage**: N/A (stateless computation)
**Testing**: `cargo test` (unit tests with known ClientHello data from Chrome, Firefox, curl)
**Target Platform**: Linux (shared library, `.so`)
**Project Type**: Library (haproxy-spoa-hub plugin, cdylib)
**Performance Goals**: <1ms p99 latency per fingerprint computation
**Constraints**: Bounded memory per request, no accumulated state, FFI-safe via abi_stable
**Scale/Scope**: 10,000+ concurrent connections

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Evidence |
|-----------|--------|----------|
| I. Code Quality | PASS | Single-responsibility modules (common/, ja3/); shared GREASE/parse utilities; public API via SpoePlugin trait; no dead code |
| II. Testing Standards | PASS | TDD with reference values from haproxy-fingerprinting test suite (Chrome, Firefox, curl); edge cases (empty fields, GREASE-only, odd bytes); unit tests for algorithm, integration tests for plugin lifecycle |
| III. User Experience Consistency | PASS | SPOE config follows HAProxy conventions; technique-prefixed variables; structured logging (WARN on unusual inputs, ERROR on failures); config validation via JSON Schema |
| IV. Performance Requirements | PASS | <1ms p99 target; stateless O(n log n) computation; bounded memory; benchmarks for fingerprint computation |

No constitution violations. Gate passes.

## Project Structure

### Documentation (this feature)

```text
specs/001-tls-fingerprinting/
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
Cargo.toml                   # cdylib crate, deps: haproxy-spoa-hub-plugin-api, abi_stable, md-5, log

src/
├── lib.rs                   # Module declarations, public re-exports
├── plugin.rs                # define_plugin! macro invocation, SPOE message extraction
├── config.rs                # PluginConfig: parse [plugins.params], technique enable/disable
├── common/
│   ├── mod.rs
│   ├── grease.rs            # is_grease() function
│   ├── parse.rs             # Binary field parsing: chunks_exact(2) → Vec<u16>, u8 parsing
│   └── types.rs             # ClientHelloData struct
├── technique.rs             # FingerprintTechnique trait definition
└── ja3/
    ├── mod.rs               # Ja3Technique, Ja3nTechnique impls
    └── fingerprint.rs       # compute_ja3(data, sort_extensions) → (hash, raw)

tests/
├── ja3_test.rs              # Unit tests: Chrome, Firefox, curl reference values
├── grease_test.rs           # GREASE detection tests
├── parse_test.rs            # Binary parsing tests (odd lengths, empty, etc.)
└── plugin_test.rs           # Config parsing, process behavior, schema validation

benches/
└── ja3_bench.rs             # Criterion benchmarks: JA3/JA3N computation latency

examples/
├── spoe-fingerprint.conf    # Example SPOE configuration
└── hub.toml                 # Example hub configuration
```

**Structure Decision**: Single Rust crate compiled as a cdylib. Source organized by concern: `common/` for shared parsing utilities, `ja3/` for the JA3/JA3N algorithm, `technique.rs` for the extensibility trait. Future techniques (e.g., JA4) add a new directory (e.g., `ja4/`) without modifying existing modules.

## Complexity Tracking

No constitution violations to justify.
