# Feature Specification: JA4 TLS Fingerprinting

**Feature Branch**: `002-ja4-fingerprinting`
**Created**: 2026-04-06
**Status**: Draft
**Input**: User description: "Also this plugin should support JA4 fingerprinting"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - JA4 Fingerprint Computation (Priority: P1)

As a HAProxy operator, I configure the fingerprinting plugin so that every TLS connection receives a JA4 fingerprint in the structured `a_b_c` format, giving me a human-readable and partially matchable fingerprint alongside the existing JA3/JA3N fingerprints.

**Why this priority**: JA4 is the successor to JA3, designed to survive TLS extension randomization (Chrome 110+, Firefox 114+). It is the core deliverable of this feature and provides immediate value for bot detection and client classification.

**Independent Test**: Can be fully tested by sending TLS requests from known clients (Chrome, Firefox, curl) through HAProxy with SPOE configured to forward ClientHello data, and verifying the returned JA4 fingerprint matches reference values from the FoxIO JA4 repository.

**Acceptance Scenarios**:

1. **Given** a TLS connection from a Chrome browser, **When** the SPOE message with ClientHello fields is processed, **Then** the plugin returns a `ja4` variable containing a 36-character fingerprint in `a_b_c` format (10-char metadata section, 12-char cipher hash, 12-char extension hash, separated by underscores).
2. **Given** a ClientHello, **When** section A is computed, **Then** it contains: protocol type (1 char: `t` for TLS), TLS version (2 chars from `supported_versions` extension if present, otherwise from protocol version field), SNI presence (1 char: `d` if SNI present, `i` if absent), cipher count (2 chars, zero-padded, excluding GREASE), extension count (2 chars, zero-padded, excluding GREASE but including SNI and ALPN), and ALPN indicator (2 chars: first and last alphanumeric character of first ALPN value, or `00` if absent).
3. **Given** a ClientHello with cipher suites, **When** section B is computed, **Then** cipher suites are converted to 4-char lowercase hex, GREASE values are removed, the list is sorted ascending, joined with commas, hashed with SHA256, and truncated to 12 characters.
4. **Given** a ClientHello with extensions and signature algorithms, **When** section C is computed, **Then** extensions are converted to 4-char lowercase hex, GREASE/SNI/ALPN values are removed, the remaining list is sorted ascending, signature algorithms (from extension 0x000d) are appended in original order after an underscore separator, the combined string is hashed with SHA256, and truncated to 12 characters.
5. **Given** a ClientHello containing GREASE values, **When** the plugin computes the JA4 fingerprint, **Then** GREASE values are excluded from cipher counts, extension counts, cipher lists, and extension lists.

---

### User Story 2 - JA4 Raw Output Variants (Priority: P2)

As a HAProxy operator, I can access the raw (unhashed) JA4 fingerprint data for detailed analysis and debugging, so that I can inspect the exact cipher suites, extensions, and signature algorithms that contributed to a fingerprint.

**Why this priority**: The raw variants are essential for debugging and forensic analysis but are secondary to the standard hashed fingerprint. Most operational use cases (ACLs, bot detection rules) use the hashed form.

**Independent Test**: Can be tested by sending a TLS request and verifying the `ja4_r` variable contains section A followed by full sorted comma-separated hex lists (ciphers, extensions, signature algorithms) without hashing.

**Acceptance Scenarios**:

1. **Given** a TLS connection, **When** the plugin computes the JA4 raw fingerprint, **Then** it returns a `ja4_r` variable containing section A (same 10-char metadata), followed by the full sorted comma-separated cipher hex list, followed by the full sorted extension hex list and original-order signature algorithm hex list — all separated by underscores, without hashing.
2. **Given** a TLS connection, **When** comparing `ja4` and `ja4_r` output, **Then** section A is identical in both, and sections B/C of `ja4` are the truncated SHA256 hashes of the corresponding raw lists in `ja4_r`.

---

### Edge Cases

- What happens when the `supported_versions` extension is absent? The TLS version is determined from the protocol version field in the ClientHello. If the version is unrecognized, `00` is used.
- What happens when no ALPN extension is present? The ALPN field in section A is `00`.
- What happens when all cipher suites are GREASE values? Section B becomes `000000000000` (literal value for empty sections, not the SHA256 of empty string).
- What happens when no signature algorithms extension (0x000d) is present? Section C is computed from extensions only, with no trailing underscore before hashing.
- What happens when cipher or extension count exceeds 99? The count is capped at `99` in section A (2-char zero-padded field).
- What happens when binary field data has odd byte length? The trailing byte is ignored; only complete pairs are parsed. A warning is logged.
- What happens when the server's ALPN selection differs from the client's first offered value? The JA4 ALPN field will reflect the server's choice, not the client's. This is a known limitation of HAProxy's `ssl_fc_alpn` fetch. In practice this rarely differs since servers typically respect client preference order.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The plugin MUST compute JA4 fingerprints producing a 36-character string in `a_b_c` format (10-char section A, 12-char section B, 12-char section C, separated by underscores).
- **FR-002**: Section A MUST contain: protocol type (`t` for TLS), TLS version (2 chars, preferring `supported_versions` extension over protocol version field), SNI presence (`d`/`i`), cipher count (2 chars zero-padded, excluding GREASE, max `99`), extension count (2 chars zero-padded, excluding GREASE, max `99`), and ALPN indicator (2 chars: first and last alphanumeric character of the server-negotiated ALPN value, or `00` if absent). See Assumptions for the known limitation regarding client-offered vs. negotiated ALPN.
- **FR-003**: Section B MUST be computed by converting cipher suites to 4-char lowercase hex, removing GREASE values, sorting ascending, joining with commas, hashing with SHA256, and truncating to 12 characters.
- **FR-004**: Section C MUST be computed by converting extensions to 4-char lowercase hex, removing GREASE/SNI (0x0000)/ALPN (0x0010) values, sorting ascending, appending signature algorithms (extension 0x000d) in original order after an underscore, hashing the combined string with SHA256, and truncating to 12 characters.
- **FR-005**: The plugin MUST filter GREASE values from all counts and lists (ciphers, extensions).
- **FR-006**: The plugin MUST produce a raw variant (`ja4_r`) containing section A and full sorted comma-separated hex lists without hashing.
- **FR-007**: The plugin MUST return JA4 results as session-scoped variables (`ja4` and `ja4_r`) via `ProcessingResult`, following the technique-prefixed naming convention established in feature 001.
- **FR-008**: The plugin MUST consume individual SPOE message arguments for each TLS field: `proto`, `ciphers`, `extensions`, `supported_versions`, `sigalgs`, `alpn`, and `sni` (via `ssl_fc_has_sni`). The `proto`, `ciphers`, and `extensions` arguments are shared with JA3/JA3N; the rest are JA4-specific additions to the SPOE configuration. The `_bin` fetches SHOULD be called with argument `(1)` to pre-filter GREASE values at the HAProxy level.
- **FR-009**: The plugin MUST handle missing or empty SPOE message arguments gracefully, producing valid fingerprints with appropriate defaults for missing data (e.g., `00` for missing ALPN, `000000000000` for empty sections).
- **FR-010**: The plugin MUST log warnings on unusual inputs (e.g., odd byte lengths, missing expected arguments) and errors on processing failures.
- **FR-011**: The plugin MUST integrate with the extensible fingerprinting architecture from feature 001, registering JA4 as a new fingerprinting technique without modifying the JA3/JA3N module.

### Key Entities

- **JA4 Fingerprint**: A structured 36-character string in `a_b_c` format. Section A is human-readable metadata (protocol, version, SNI, counts, ALPN). Sections B and C are truncated SHA256 hashes of sorted cipher and extension/signature algorithm lists respectively.
- **JA4 Raw Fingerprint (JA4_r)**: The unhashed variant containing section A and full sorted comma-separated hex lists, used for debugging and detailed analysis.
- **Signature Algorithms**: Values from TLS extension 0x000d, preserved in original (unsorted) order for section C computation. This is a new input field not used by JA3/JA3N.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The plugin produces correct JA4 fingerprints for known TLS clients (Chrome, Firefox, curl) matching reference values from the FoxIO JA4 repository when the server-negotiated ALPN equals the client's first offered ALPN (the common case).
- **SC-002**: JA4 fingerprint computation adds less than 1ms of processing time per request at the 99th percentile (same performance bar as JA3/JA3N).
- **SC-003**: JA4 fingerprints remain stable across repeated connections from the same client, including browsers with TLS extension randomization enabled.
- **SC-004**: The JA4 module integrates without modifying any existing JA3/JA3N code, validating the extensible architecture.

## Assumptions

- This feature builds on the extensible fingerprinting architecture established in feature 001 (`001-tls-fingerprinting`). The JA3/JA3N technique must be implemented first.
- The SPOE message uses individual arguments for each TLS field, sourced from HAProxy's `ssl_fc_*` sample fetch functions. JA4 extends the SPOE configuration with three additional arguments (`supported_versions`, `sigalgs`, `alpn`) beyond what JA3/JA3N requires.
- HAProxy's SSL capture buffer stores pre-parsed field arrays (not raw ClientHello bytes). It captures extension type IDs but not most extension payloads. However, it does specifically capture `supported_versions` (ext 43) and `signature_algorithms` (ext 13) payloads.
- **Known limitation (ALPN)**: HAProxy does not capture the client-offered ALPN list (extension 16 payload). The `ssl_fc_alpn` fetch returns the server-negotiated ALPN. The plugin uses this as a best-effort approximation for the JA4 ALPN field. In practice, servers almost always select the client's preferred protocol, so the field matches in the vast majority of cases. This is the same approach used by the FriendlyCaptcha ja4-haproxy Lua implementation (https://github.com/FriendlyCaptcha/ja4-haproxy). When the server overrides client preference, the ALPN field (and therefore section A and the full JA4 hash) will differ from reference implementations that have access to the raw ClientHello.
- HAProxy's `tune.ssl.capture-buffer-size` MUST be at least 256 bytes to capture sufficient ClientHello data.
- JA4 is licensed under BSD 3-Clause (same as JA3), making it freely usable. Other JA4+ variants (JA4S, JA4H, etc.) are out of scope and under different licensing.
- SHA256 hashing is available through standard cryptographic libraries.
