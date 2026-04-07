# Research: JA4 TLS Fingerprinting

**Feature**: 002-ja4-fingerprinting
**Date**: 2026-04-06

## Decision: SPOE Message Format

**Decision**: Use individual SPOE message arguments (one per TLS field), not raw ClientHello buffer parsing.

**Rationale**: HAProxy's SSL capture buffer (`ssl_capture` struct) stores pre-parsed field arrays, not raw ClientHello bytes. The buffer is populated by `ssl_sock_parse_clienthello()` which extracts specific fields into a packed `data[]` array with offset/length metadata. HAProxy exposes these fields through individual sample fetch functions, which are the natural SPOE argument sources.

**Alternatives considered**:
- Raw ClientHello buffer parsing in the plugin — rejected because HAProxy does not expose the raw ClientHello; the capture buffer is already pre-parsed.
- Custom HAProxy patch to capture raw ClientHello — rejected as out of scope and unnecessary.

**Impact on feature 001**: The `001-tls-fingerprinting` spec assumed raw buffer parsing. This must be corrected: JA3/JA3N will continue using individual SPOE arguments (`proto`, `ciphers`, `extensions`, `curves`, `formats`) as the existing haproxy-fingerprinting project does.

## Decision: SPOE Arguments for JA4

**Decision**: Extend the SPOE message with two additional arguments beyond what JA3/JA3N uses, plus one best-effort argument.

**Rationale**: JA4 requires three data sources not needed by JA3/JA3N:
1. **Supported versions** (extension 0x002b payload) — available via `ssl_fc_supported_versions_bin`
2. **Signature algorithms** (extension 0x000d payload) — available via `ssl_fc_sigalgs_bin`
3. **Client-offered ALPN** (extension 0x0010 payload) — NOT available from HAProxy's capture buffer

**Complete SPOE argument list**:

| Argument | HAProxy Fetch | Used by | Format |
|----------|---------------|---------|--------|
| `proto` | `ssl_fc_protocol_hello_id` | JA3, JA3N, JA4 | Integer (u16) |
| `ciphers` | `ssl_fc_cipherlist_bin` | JA3, JA3N, JA4 | Binary u16 BE pairs |
| `extensions` | `ssl_fc_extlist_bin` | JA3, JA3N, JA4 | Binary u16 BE pairs |
| `curves` | `ssl_fc_eclist_bin` | JA3, JA3N, JA4 | Binary u16 BE pairs |
| `formats` | `ssl_fc_ecformats_bin` | JA3, JA3N | Binary u8 values |
| `supported_versions` | `ssl_fc_supported_versions_bin` | JA4 | Binary u16 BE pairs |
| `sigalgs` | `ssl_fc_sigalgs_bin` | JA4 | Binary u16 BE pairs |
| `alpn` | `ssl_fc_alpn` | JA4 | String (negotiated) |

**Note on GREASE filtering**: The `_bin` fetch functions accept an optional argument `(1)` to pre-filter GREASE values. However, since the plugin performs its own GREASE filtering (and JA4 needs accurate counts of non-GREASE values), the SPOE config should pass these without the GREASE filter argument, letting the plugin handle GREASE filtering consistently across all techniques.

## Decision: ALPN Handling

**Decision**: Use `ssl_fc_alpn` (server-negotiated ALPN) as a best-effort approximation. Document the limitation.

**Rationale**: HAProxy's `ssl_sock_parse_clienthello()` does not parse extension 16 (ALPN) payload. The `ssl_fc_alpn` fetch returns the negotiated protocol (what the server selected), not the client's offered list. For JA4's section A, we need the first and last alphanumeric character of the FIRST value from the client's offered list.

In practice, the negotiated ALPN is usually the client's preferred protocol (servers typically respect client preference order or prefer `h2`). This produces correct JA4 fingerprints in the common case but may differ when the server overrides client preference.

**Alternatives considered**:
- Default to `00` (no ALPN) — rejected because it produces fingerprints that never match reference implementations, reducing utility.
- Patch HAProxy to capture extension 16 payload — viable future enhancement but out of scope for initial implementation.
- Parse raw TLS via a separate capture mechanism — overly complex for one field.

**Mitigation**: Document in the plugin README that the ALPN field uses the negotiated protocol as an approximation. If HAProxy adds a `ssl_fc_client_alpn` fetch in the future, the plugin can adopt it without architectural changes.

## Decision: SNI Detection

**Decision**: Detect SNI presence by checking if extension type 0x0000 (server_name) is present in the extensions list.

**Rationale**: The extensions binary data contains type IDs. Extension 0x0000 is the server_name extension. Its presence indicates SNI was offered (JA4 section A: `d` for domain). Its absence indicates no SNI (`i` for IP).

## Decision: TLS Version for JA4 Section A

**Decision**: Use `supported_versions` data (if present) to determine the highest non-GREASE version. Fall back to `proto` (ClientHello protocol version field) if `supported_versions` is empty or absent.

**Rationale**: Per the JA4 specification, `supported_versions` (extension 0x002b) takes priority because TLS 1.3 clients set the ClientHello protocol version to 0x0303 (TLS 1.2) for backward compatibility, while advertising TLS 1.3 support via `supported_versions`.

**Version mapping**:
- 0x0304 → `13` (TLS 1.3)
- 0x0303 → `12` (TLS 1.2)
- 0x0302 → `11` (TLS 1.1)
- 0x0301 → `10` (TLS 1.0)
- 0x0300 → `s3` (SSL 3.0)
- Unknown → `00`

## Decision: Rust Crate for SHA256

**Decision**: Use the `sha2` crate for SHA256 hashing.

**Rationale**: The `sha2` crate is the standard pure-Rust SHA-2 implementation from the RustCrypto project. It is widely used, well-audited, and has no system dependencies (unlike OpenSSL bindings). The existing haproxy-fingerprinting SPOE agent uses `md-5` from the same RustCrypto project family.

## Decision: Project Structure

**Decision**: The JA4 module is added to the existing fingerprinting plugin crate as a new module, following the extensible architecture from feature 001.

**Rationale**: JA4 shares input data parsing (GREASE filtering, binary field decoding) with JA3/JA3N. Keeping it in the same crate avoids duplication and aligns with the plugin's single-library deployment model.
