# Tasks: JA4 TLS Fingerprinting

**Input**: Design documents from `/specs/002-ja4-fingerprinting/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: Included per constitution Principle II (TDD mandatory).

**Organization**: Tasks are grouped by user story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2)
- Include exact file paths in descriptions

## Phase 1: Setup

**Purpose**: Add sha2 dependency, extend shared types, prepare JA4 module skeleton

- [x] T001 Add `sha2 = "0.10"` dependency to `Cargo.toml`
- [x] T002 Extend `ClientHelloData` in `src/common/types.rs` with optional JA4 fields: `supported_versions: Vec<u16>`, `signature_algorithms: Vec<u16>`, `alpn: Option<String>`, `sni_present: bool`
- [x] T003 Create `src/ja4/mod.rs` with module declaration and public re-exports
- [x] T004 Add `pub mod ja4;` to `src/lib.rs`

**Checkpoint**: Project compiles with new types and empty JA4 module.

---

## Phase 2: Foundational

**Purpose**: Extract JA4-specific SPOE arguments in the plugin process() path

- [x] T005 Extend `extract_client_hello()` in `src/plugin.rs` to parse additional SPOE args: `supported_versions` (binary u16), `sigalgs` (binary u16), `alpn` (string), `sni` (bool/int). Populate the new `ClientHelloData` fields. Existing JA3 fields unchanged.

**Checkpoint**: Plugin extracts all JA4 arguments from SPOE messages. JA3 behavior unaffected.

---

## Phase 3: User Story 1 — JA4 Fingerprint Computation (Priority: P1)

**Goal**: Compute correct JA4 fingerprints in `a_b_c` format with SHA256-truncated sections B and C.

**Independent Test**: Send SPOE message with known ClientHello fields, verify the returned `ja4` variable matches FoxIO reference values.

### Tests for User Story 1

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [x] T006 [P] [US1] Create `tests/ja4_test.rs` with section A tests: TLS version from supported_versions (highest wins), fallback to proto, SNI d/i, ALPN first+last char, cipher/extension counts zero-padded, count capped at 99. Use FoxIO reference pcap data for expected section A strings.
- [x] T007 [P] [US1] Add section B tests to `tests/ja4_test.rs`: ciphers as 4-char lowercase hex, sorted ascending, comma-joined, SHA256 truncated to 12 chars. Empty ciphers → `000000000000`.
- [x] T008 [P] [US1] Add section C tests to `tests/ja4_test.rs`: extensions as hex with SNI(0x0000) and ALPN(0x0010) removed, sorted, sigalgs in original order appended after underscore, SHA256 truncated to 12 chars. Missing sigalgs → no trailing underscore.
- [x] T009 [P] [US1] Add full JA4 integration tests to `tests/ja4_test.rs`: complete `a_b_c` output verified against FoxIO JA4 reference values for known clients.

### Implementation for User Story 1

- [x] T010 [US1] Create `src/ja4/section_a.rs` with functions: `tls_version(supported_versions: &[u16], proto: u16) -> &str`, `alpn_indicator(alpn: Option<&str>) -> String`, `build_section_a(proto, version, sni, cipher_count, ext_count, alpn) -> String`
- [x] T011 [US1] Create `src/ja4/fingerprint.rs` with `compute_ja4(data: &ClientHelloData) -> (String, String)` returning (ja4_hash, ja4_raw). Implements: section A metadata, section B (hex ciphers sorted, SHA256 truncated), section C (hex extensions minus SNI/ALPN sorted + sigalgs unsorted, SHA256 truncated). Empty sections → `000000000000`.
- [x] T012 [US1] Verify all tests from T006-T009 pass

**Checkpoint**: JA4 algorithm produces correct fingerprints for reference clients.

---

## Phase 4: User Story 2 — JA4 Raw Output Variant (Priority: P2)

**Goal**: Produce unhashed JA4_r variant alongside the hashed JA4.

**Independent Test**: Compare `ja4` and `ja4_r` output: section A identical, sections B/C of `ja4` are SHA256 truncations of corresponding raw lists in `ja4_r`.

### Tests for User Story 2

- [x] T013 [P] [US2] Add JA4_r tests to `tests/ja4_test.rs`: verify raw output contains section A + full sorted hex cipher list + full sorted hex extension list with original-order sigalgs, all underscore-separated. Verify hashing the raw lists produces the hashed sections.

### Implementation for User Story 2

- [x] T014 [US2] Update `compute_ja4()` in `src/ja4/fingerprint.rs` to return `(ja4, ja4_r)` — both hashed and raw variants in a single pass.
- [x] T015 [US2] Verify tests from T013 pass

**Checkpoint**: Both JA4 and JA4_r output are correct.

---

## Phase 5: Plugin Integration

**Purpose**: Wire JA4 into the plugin's process() path and register as a new technique.

- [x] T016 Add JA4 config params to `src/config.rs`: `ja4: bool` (default true) controlling whether JA4 is computed. Update config schema.
- [x] T017 Update `src/plugin.rs` process() to call `compute_ja4()` when enabled, producing `ja4` and `ja4_r` session-scoped variables alongside existing `hash`/`raw`.
- [x] T018 [P] Add JA4 config and integration tests to `tests/plugin_test.rs`: ja4 enabled/disabled, output variables present/absent, coexistence with JA3.
- [x] T019 Verify all tests pass (JA3 + JA4 combined)

**Checkpoint**: Plugin produces both JA3/JA3N and JA4 fingerprints. SC-004 satisfied (JA3 code unmodified).

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Examples, docs, benchmarks, linting

- [x] T020 [P] Update `examples/spoe-fingerprint.conf` with JA4 SPOE arguments per contracts/spoe-message-contract.md
- [x] T021 [P] Update `examples/hub.toml` with JA4 config example
- [x] T022 [P] Add JA4 benchmarks to `benches/ja3_bench.rs` (rename to `fingerprint_bench.rs`)
- [x] T023 Update `README.md` with JA4 documentation
- [x] T024 Run `cargo clippy` and `cargo fmt --check`, fix any issues
- [x] T025 Run full test suite (`cargo test`) and verify all tests pass
- [x] T026 Run `cargo build --release` and verify `.so` output

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies
- **Foundational (Phase 2)**: Depends on Phase 1 (types must exist)
- **User Story 1 (Phase 3)**: Depends on Phase 2 (SPOE extraction must work)
- **User Story 2 (Phase 4)**: Depends on Phase 3 (JA4 algorithm must exist)
- **Plugin Integration (Phase 5)**: Depends on Phase 4 (both variants must work)
- **Polish (Phase 6)**: Depends on Phase 5

### Within Each Phase

- Tests MUST be written and FAIL before implementation
- Tasks marked [P] can run in parallel

### Parallel Opportunities

User Story 1 tests:
```
T006 (section A) | T007 (section B) | T008 (section C) | T009 (full JA4)
```

Polish:
```
T020 (SPOE config) | T021 (hub config) | T022 (benchmarks)
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (SPOE arg extraction)
3. Complete Phase 3: User Story 1 (JA4 algorithm + tests)
4. **STOP and VALIDATE**: Verify fingerprints match FoxIO references

### Full Delivery

1. Setup + Foundational → infrastructure ready
2. User Story 1 → JA4 algorithm correct
3. User Story 2 → JA4_r raw variant
4. Plugin Integration → full plugin with JA3 + JA4
5. Polish → examples, docs, benchmarks

---

## Notes

- [P] tasks = different files, no dependencies
- Tests are mandatory per constitution Principle II (TDD)
- Test vectors from FoxIO JA4 repository (https://github.com/FoxIO-LLC/ja4)
- JA3 code must NOT be modified (SC-004 extensibility validation)
- Commit after each task or logical group
