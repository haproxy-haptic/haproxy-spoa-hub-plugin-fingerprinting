# Feature Specification: TLS Fingerprinting Plugin

**Feature Branch**: `001-tls-fingerprinting`
**Created**: 2026-04-06
**Status**: Draft
**Input**: User description: "Write a fingerprinting plugin for haproxy-spoa-hub that implements JA3(N) TLS fingerprinting, with extensibility for future fingerprinting techniques."

## Clarifications

### Session 2026-04-06

- Q: How should output variables be named when multiple fingerprinting techniques coexist? → A: Technique-prefixed from the start (`ja3n_hash`, `ja3n_raw`, `ja3_hash`, `ja3_raw`). JA3 is a single parameterizable algorithm that produces both JA3 (unsorted extensions) and JA3N (sorted extensions) variants based on configuration.
- Q: What variable scope should fingerprint output use? → A: Session scope. TLS fingerprints are per-connection, so session scope avoids redundant recomputation across requests on the same connection.
- Q: What observability should the plugin provide? → A: Log warnings on unusual inputs (odd byte lengths, missing fields) and errors on processing failures. No metrics or debug-level fingerprint logging.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - JA3/JA3N Fingerprint Computation (Priority: P1)

As a HAProxy operator, I configure the fingerprinting plugin in haproxy-spoa-hub so that every TLS connection receives JA3 and JA3N fingerprint hashes and raw strings, which I can use in HAProxy rules for bot detection, client classification, or logging.

**Why this priority**: JA3/JA3N fingerprinting is the core value proposition. Without it, the plugin has no purpose. This is the MVP that delivers immediate, actionable data to operators.

**Independent Test**: Can be fully tested by loading the plugin in haproxy-spoa-hub, sending a TLS request through HAProxy with SPOE configured to forward ClientHello data, and verifying the returned `ja3n_hash`, `ja3n_raw`, `ja3_hash`, and `ja3_raw` variables match expected values for known clients (Chrome, Firefox, curl).

**Acceptance Scenarios**:

1. **Given** a TLS connection from a Chrome browser, **When** the SPOE message with ClientHello fields is processed, **Then** the plugin returns technique-prefixed variables: `ja3n_hash` and `ja3n_raw` (with sorted extensions), and `ja3_hash` and `ja3_raw` (with original extension order). Each hash is a 32-char lowercase hex MD5; each raw string uses the `version,ciphers,extensions,curves,formats` format.
2. **Given** a ClientHello containing GREASE values in cipher suites, extensions, and elliptic curves, **When** the plugin computes the fingerprint, **Then** all GREASE values are filtered out before fingerprint construction for both JA3 and JA3N variants.
3. **Given** a ClientHello containing extension 41 (pre_shared_key), **When** the plugin computes the fingerprint, **Then** extension 41 is excluded from the extensions field in both variants to ensure fingerprint stability across sessions.
4. **Given** a ClientHello with extensions in arbitrary order, **When** the plugin computes the JA3N fingerprint, **Then** extensions are sorted numerically in ascending order (JA3N normalization), while the JA3 variant preserves original extension order.
5. **Given** a ClientHello with empty cipher suites or extensions, **When** the plugin computes the fingerprint, **Then** the plugin produces valid fingerprints with empty fields for both variants (no crash, no error).

---

### User Story 2 - Plugin Configuration and Integration (Priority: P2)

As a HAProxy operator, I install the fingerprinting plugin into haproxy-spoa-hub by placing the shared library in the plugin directory and adding a configuration entry, so that the plugin loads, initializes, and begins processing SPOE messages without additional setup.

**Why this priority**: Proper integration with the hub's plugin lifecycle (init, config validation, shutdown) is required for production use but builds on the core algorithm from US1.

**Independent Test**: Can be tested by configuring the plugin in haproxy-spoa-hub's TOML config, starting the hub, and verifying the plugin loads successfully with its name and version logged. Sending an SPOE message confirms end-to-end processing.

**Acceptance Scenarios**:

1. **Given** the plugin shared library is placed in the plugin directory and configured in the hub's TOML config, **When** haproxy-spoa-hub starts, **Then** the plugin loads, logs its name and version, and is ready to process messages.
2. **Given** the plugin is loaded and a `get-fingerprint` SPOE message arrives with binary TLS ClientHello fields (proto, ciphers, extensions, curves, formats), **When** the message is processed, **Then** the plugin returns technique-prefixed session-scoped variables (`ja3n_hash`, `ja3n_raw`, `ja3_hash`, `ja3_raw`) namespaced under the plugin name.
3. **Given** the hub shuts down, **When** the shutdown signal reaches the plugin, **Then** the plugin cleans up any resources gracefully without errors.
4. **Given** the plugin is configured with specific fingerprinting techniques disabled (e.g., `ja3 = false` in plugin params), **When** an SPOE message is processed, **Then** only the enabled techniques produce output variables. Disabled techniques are skipped entirely (no computation, no variables set).
5. **Given** no explicit technique configuration is provided, **When** the plugin initializes, **Then** all available fingerprinting techniques are enabled by default.

---

### User Story 3 - Extensible Fingerprinting Architecture (Priority: P3)

As a plugin maintainer, I can add new fingerprinting techniques (such as JA4, HTTP/2 fingerprinting, or custom methods) alongside JA3N without modifying the existing algorithm, so that the plugin grows in capability over time.

**Why this priority**: Extensibility is a design concern that enables future value but does not deliver user-facing functionality on its own. It should influence the internal architecture from the start but does not need to be fully exercised in the initial release.

**Independent Test**: Can be verified by reviewing the code structure: fingerprinting algorithms are isolated in separate modules behind a common internal interface. A new technique can be added by implementing that interface and registering it, without modifying the JA3N module.

**Acceptance Scenarios**:

1. **Given** the plugin's internal architecture, **When** a developer adds a new fingerprinting technique, **Then** they only need to implement the fingerprinting logic in a new module and register it — existing modules remain unchanged.
2. **Given** multiple fingerprinting techniques are registered, **When** an SPOE message is processed, **Then** each technique produces its own technique-prefixed output variables (e.g., `ja3n_hash`, `ja3n_raw` for JA3N; `ja3_hash`, `ja3_raw` for JA3; future techniques follow the same `<technique>_hash`, `<technique>_raw` pattern).

---

### Edge Cases

- What happens when the SPOE message is missing required fields (e.g., no `ciphers` argument)? The plugin treats missing fields as empty and produces a valid fingerprint with empty sections.
- How does the plugin handle a `proto` value of 0 or an unrecognized TLS version? The version value is included as-is in the fingerprint string — the plugin does not validate version semantics.
- What happens when binary field data has odd byte length (not aligned to u16 boundaries)? The trailing byte is ignored; only complete u16 pairs are parsed. A warning is logged.
- How does the plugin behave when all cipher suites are GREASE values? The ciphers field in the fingerprint string is empty, which is valid.
- What happens when the plugin receives a message name it does not handle? The plugin returns an empty `ProcessingResult` (no variables set).
- What happens when all fingerprinting techniques are disabled via configuration? The plugin initializes successfully but returns an empty `ProcessingResult` for every message. A warning is logged at startup.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The plugin MUST compute both JA3 and JA3N fingerprints from TLS ClientHello fields: protocol version (u16), cipher suites (binary u16 list), extensions (binary u16 list), elliptic curves (binary u16 list), and EC point formats (binary u8 list). JA3 and JA3N share a single parameterizable algorithm; JA3N sorts extensions while JA3 preserves original order.
- **FR-002**: The plugin MUST filter GREASE values (RFC 8701) from cipher suites, extensions, and elliptic curves before fingerprint construction.
- **FR-003**: The plugin MUST sort extensions numerically in ascending order (JA3N normalization).
- **FR-004**: The plugin MUST exclude extension 41 (pre_shared_key) from the extensions field by default.
- **FR-005**: The plugin MUST produce an MD5 hash (32-character lowercase hexadecimal) of the raw fingerprint string.
- **FR-006**: The plugin MUST produce a raw fingerprint string in the format `version,ciphers,extensions,curves,formats` with dash-separated values within each field.
- **FR-007**: The plugin MUST implement the `SpoePlugin` trait from `haproxy-spoa-hub-plugin-api`, including `init`, `process`, `name`, `version`, and `shutdown` methods.
- **FR-008**: The plugin MUST return fingerprint results as technique-prefixed session-scoped variables (`ja3n_hash`, `ja3n_raw`, `ja3_hash`, `ja3_raw`) via `ProcessingResult`. Session scope is used because TLS fingerprints are per-connection.
- **FR-009**: The plugin MUST handle missing or empty SPOE message arguments gracefully, producing a valid (possibly empty-fielded) fingerprint rather than returning an error.
- **FR-010**: The plugin MUST be compiled as a shared library (`.so`) loadable by haproxy-spoa-hub via the `abi_stable` mechanism.
- **FR-011**: The plugin MUST log warnings when it encounters unusual inputs (e.g., binary fields with odd byte lengths, missing expected message arguments) and errors on processing failures. The plugin MUST NOT log per-request debug output or computed fingerprint values in normal operation.
- **FR-012**: The plugin MUST support enabling and disabling individual fingerprinting techniques via plugin configuration parameters. Each technique (e.g., `ja3`, `ja3n`) MUST be independently controllable as a boolean parameter.
- **FR-013**: When no explicit technique configuration is provided, all available fingerprinting techniques MUST be enabled by default.

### Key Entities

- **JA3/JA3N Fingerprint**: Represents a computed fingerprint consisting of a raw string (the ClientHello fields) and an MD5 hash of that string. JA3 and JA3N are produced by the same parameterizable algorithm: JA3N sorts extensions numerically while JA3 preserves original order. Both filter GREASE values and exclude extension 41. Derived from five TLS ClientHello fields.
- **SPOE Message**: The input received from HAProxy via the hub, containing named binary arguments representing TLS ClientHello data.
- **Fingerprinting Technique**: An internal abstraction representing a specific fingerprinting algorithm (JA3N initially, others in the future). Each technique consumes TLS data and produces named output variables.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The plugin produces correct JA3 and JA3N fingerprints for known TLS clients (Chrome, Firefox, curl) matching reference implementations.
- **SC-002**: Fingerprint computation adds less than 1ms of processing time per request at the 99th percentile.
- **SC-003**: The plugin handles 10,000 concurrent connections without memory leaks or resource exhaustion.
- **SC-004**: The plugin loads and initializes in haproxy-spoa-hub within 1 second.
- **SC-005**: A new fingerprinting technique can be added without modifying any existing fingerprinting module code.

## Assumptions

- HAProxy is configured with `tune.ssl.capture-buffer-size` of at least 256 bytes, providing complete ClientHello data to the SPOE engine.
- The SPOE message format follows the same field naming and binary encoding conventions as the existing haproxy-fingerprinting project (`proto`, `ciphers`, `extensions`, `curves`, `formats`).
- The plugin targets the current haproxy-spoa-hub plugin API (using `abi_stable` for FFI safety and the `define_plugin!` macro).
- JA3N output must be compatible with standard JA3N implementations (sorted extensions, extension 41 excluded) for comparison and migration purposes.
- The Rust `md-5` crate is acceptable for MD5 hashing (same as used in the existing SPOE agent implementation).
