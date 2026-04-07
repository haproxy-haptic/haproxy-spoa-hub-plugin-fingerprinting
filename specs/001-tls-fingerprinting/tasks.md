# Tasks: TLS Fingerprinting Plugin

**Input**: Design documents from `/specs/001-tls-fingerprinting/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Included per constitution Principle II (TDD mandatory).

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Single project**: `src/`, `tests/` at repository root

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization, dependencies, and shared utilities

- [x] T001 Initialize Rust crate with `Cargo.toml` (cdylib, edition 2024, dependencies: `haproxy-spoa-hub-plugin-api`, `md-5`, `abi_stable`)
- [x] T002 [P] Create `src/common/grease.rs` with `is_grease(v: u16) -> bool` function implementing `(v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)`
- [x] T003 [P] Create `src/common/parse.rs` with binary field parsing: `parse_u16_be(data: &[u8]) -> Vec<u16>` (chunks_exact(2), big-endian) and `parse_u8(data: &[u8]) -> Vec<u8>`, logging warning on odd byte lengths
- [x] T004 [P] Create `src/common/types.rs` with `ClientHelloData` struct (protocol_version: u16, cipher_suites: Vec<u16>, extensions: Vec<u16>, elliptic_curves: Vec<u16>, ec_point_formats: Vec<u8>)
- [x] T005 [P] Create `src/common/mod.rs` re-exporting grease, parse, and types modules
- [x] T006 [P] Create `tests/grease_test.rs` with tests: known GREASE values (0x0a0a, 0x1a1a, ..., 0xfafa) return true; non-GREASE values return false; boundary values
- [x] T007 [P] Create `tests/parse_test.rs` with tests: valid u16 BE pairs, empty input, odd byte length (trailing byte ignored + warning), single byte input

**Checkpoint**: Shared utilities built and tested. Ready for algorithm implementation.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Extensibility trait and technique registration infrastructure

- [x] T008 Create `src/technique.rs` with `FingerprintTechnique` trait: `fn name(&self) -> &str`, `fn compute(&self, data: &ClientHelloData) -> Vec<(String, String)>` returning (variable_name, variable_value) pairs

**Checkpoint**: Foundation ready — user story implementation can begin.

---

## Phase 3: User Story 1 — JA3/JA3N Fingerprint Computation (Priority: P1)

**Goal**: Compute correct JA3 and JA3N fingerprints from ClientHello data, matching reference implementations for Chrome, Firefox, and curl.

**Independent Test**: Load plugin, send SPOE message with known ClientHello, verify `ja3_hash`, `ja3_raw`, `ja3n_hash`, `ja3n_raw` match expected values.

### Tests for User Story 1

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [x] T009 [P] [US1] Create `tests/ja3_test.rs` with tests using Chrome reference data: 16 ciphers, 18 extensions with GREASE, expected hash and raw string. Test both JA3 (unsorted) and JA3N (sorted) output.
- [x] T010 [P] [US1] Add Firefox reference test to `tests/ja3_test.rs`: 17 ciphers, 14 extensions, no GREASE, expected hash and raw string for both variants
- [x] T011 [P] [US1] Add curl reference test to `tests/ja3_test.rs`: 30 ciphers, 12 extensions, 3 EC formats, expected hash and raw string for both variants
- [x] T012 [P] [US1] Add edge case tests to `tests/ja3_test.rs`: empty fields (all five empty), GREASE-only ciphers (empty after filtering), extension 41 exclusion, unsorted vs sorted extension order verification

### Implementation for User Story 1

- [x] T013 [US1] Create `src/ja3/fingerprint.rs` with `compute_ja3(data: &ClientHelloData, sort_extensions: bool) -> (String, String)` returning (md5_hash, raw_string). Implements: GREASE filtering, extension 41 exclusion, optional sorting, dash-separated field values, comma-separated sections, MD5 hashing.
- [x] T014 [US1] Create `src/ja3/mod.rs` implementing `FingerprintTechnique` for `Ja3Technique` (sort=false) and `Ja3nTechnique` (sort=true), each producing `ja3_hash`/`ja3_raw` or `ja3n_hash`/`ja3n_raw` variable pairs
- [x] T015 [US1] Verify all tests from T009-T012 pass

**Checkpoint**: JA3/JA3N algorithm produces correct fingerprints for all reference clients. Core value delivered.

---

## Phase 4: User Story 2 — Plugin Configuration and Integration (Priority: P2)

**Goal**: Full haproxy-spoa-hub plugin lifecycle: load, init with config, process SPOE messages, shutdown. Technique enable/disable via params.

**Independent Test**: Configure plugin in hub TOML, start hub, verify plugin loads and logs name/version. Send SPOE message, verify variables returned. Test with techniques selectively disabled.

### Tests for User Story 2

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [x] T016 [P] [US2] Create `tests/plugin_test.rs` with config parsing tests: default config (all enabled), ja3 disabled, ja3n disabled, both disabled (warning expected), unknown params rejected by JSON Schema
- [x] T017 [P] [US2] Add process tests to `tests/plugin_test.rs`: SPOE message with Chrome data returns correct variables; missing arguments produce valid empty-field fingerprints; unknown message name returns empty result; disabled technique produces no variables

### Implementation for User Story 2

- [x] T018 [US2] Create `src/config.rs` with `PluginConfig` struct: parse `ja3` and `ja3n` boolean params from `PluginContext`, default both to true. Include `config_schema()` returning JSON Schema for validation.
- [x] T019 [US2] Create `src/lib.rs` with `define_plugin!` macro invocation implementing `FingerprintingPlugin`: `init()` parses config and registers enabled techniques, `process()` extracts SPOE message args into `ClientHelloData` then runs each enabled technique collecting session-scoped `TxnVariable` results, `name()` returns `"fingerprinting"`, `version()` returns crate version, `shutdown()` is no-op. Log warning at init if all techniques disabled.
- [x] T020 [US2] Verify all tests from T016-T017 pass

**Checkpoint**: Plugin loads in haproxy-spoa-hub, processes messages, respects config. Production-ready integration.

---

## Phase 5: User Story 3 — Extensible Fingerprinting Architecture (Priority: P3)

**Goal**: Verify the architecture supports adding new techniques without modifying existing code.

**Independent Test**: Review code structure: ja3/ module is self-contained, FingerprintTechnique trait is generic, adding a new technique requires only a new module + registration.

- [x] T021 [US3] Verify extensibility: confirm `FingerprintTechnique` trait in `src/technique.rs` is generic (no JA3-specific types), `src/ja3/` module has no dependencies on `src/lib.rs` internals, and adding a new technique would require only: (1) new module implementing trait, (2) registration in `init()`. Document verification in a code comment in `src/technique.rs`.

**Checkpoint**: Architecture validated for extensibility. SC-005 satisfied.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Examples, documentation, and benchmarks

- [x] T022 [P] Create `examples/spoe-fingerprint.conf` with example SPOE configuration per contracts/spoe-message-contract.md
- [x] T023 [P] Create `examples/hub.toml` with example hub plugin configuration including params section
- [x] T024 [P] Create `benches/ja3_bench.rs` with criterion benchmarks for JA3/JA3N computation using Chrome and curl reference data. Verify <1ms p99 per SC-002.
- [x] T025 Run `cargo clippy` and `cargo fmt --check`, fix any warnings or formatting issues
- [x] T026 Run full test suite (`cargo test`) and verify all tests pass
- [x] T027 Run quickstart.md validation: verify build produces `target/release/libfingerprinting.so`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on T004 (ClientHelloData type) from Setup
- **User Story 1 (Phase 3)**: Depends on Phase 2 (FingerprintTechnique trait) and Phase 1 (common utilities)
- **User Story 2 (Phase 4)**: Depends on Phase 3 (JA3 techniques must exist to register)
- **User Story 3 (Phase 5)**: Depends on Phase 4 (full plugin must be implemented to verify extensibility)
- **Polish (Phase 6)**: Depends on all user stories being complete

### Within Each Phase

- Tests MUST be written and FAIL before implementation
- Implementation tasks are sequential within a story (models → services → integration)
- Tasks marked [P] can run in parallel

### Parallel Opportunities

Setup phase:
```
T002 (grease.rs) | T003 (parse.rs) | T004 (types.rs) | T005 (mod.rs)
T006 (grease tests) | T007 (parse tests)
```

User Story 1 tests:
```
T009 (Chrome) | T010 (Firefox) | T011 (curl) | T012 (edge cases)
```

User Story 2 tests:
```
T016 (config tests) | T017 (process tests)
```

Polish:
```
T022 (SPOE config) | T023 (hub config)
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (shared utilities + tests)
2. Complete Phase 2: Foundational (technique trait)
3. Complete Phase 3: User Story 1 (JA3/JA3N algorithm + tests)
4. **STOP and VALIDATE**: Verify fingerprints match reference values
5. Core value delivered — algorithm is correct

### Full Delivery

1. Setup + Foundational → infrastructure ready
2. User Story 1 → JA3/JA3N algorithm correct
3. User Story 2 → plugin loads in haproxy-spoa-hub, config works
4. User Story 3 → extensibility verified
5. Polish → examples, linting, final validation

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Tests are mandatory per constitution Principle II (TDD)
- Reference test data sourced from haproxy-fingerprinting project (tests/test_ja3.c and spoe-agent/src/main.rs)
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
