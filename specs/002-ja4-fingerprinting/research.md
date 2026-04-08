# Research: JA4 TLS Fingerprinting

**Feature**: 002-ja4-fingerprinting
**Date**: 2026-04-07

## Decision: SPOE Message Format

**Decision**: Extend the existing SPOE message with additional arguments for JA4-specific fields. Reuse `proto`, `ciphers`, `extensions` from JA3/JA3N; add `supported_versions`, `sigalgs`, `alpn`, and `sni`.

**Rationale**: HAProxy's SSL capture buffer stores pre-parsed field arrays with dedicated fetch functions for each. The FriendlyCaptcha and O-X-L JA4 Lua implementations both use the same individual-fetch approach.

**SPOE argument list for JA4**:

| Argument | HAProxy Fetch | Format | Shared with JA3 |
|----------|---------------|--------|-----------------|
| `proto` | `ssl_fc_protocol_hello_id` | Integer | Yes |
| `ciphers` | `ssl_fc_cipherlist_bin(1)` | Binary u16 BE, GREASE pre-filtered | Yes |
| `extensions` | `ssl_fc_extlist_bin(1)` | Binary u16 BE, GREASE pre-filtered | Yes |
| `supported_versions` | `ssl_fc_supported_versions_bin(1)` | Binary u16 BE, GREASE pre-filtered | No |
| `sigalgs` | `ssl_fc_sigalgs_bin(1)` | Binary u16 BE, GREASE pre-filtered | No |
| `alpn` | `ssl_fc_alpn` | String (negotiated) | No |
| `sni` | `ssl_fc_has_sni` | Boolean/Integer | No |

## Decision: ALPN Handling

**Decision**: Use `ssl_fc_alpn` (server-negotiated ALPN) as best-effort approximation.

**Rationale**: HAProxy does not capture the client-offered ALPN list (extension 16 payload). Both existing HAProxy JA4 implementations (FriendlyCaptcha Lua, O-X-L Lua) use the negotiated ALPN and document it as a known limitation. In practice, servers almost always select the client's preferred protocol.

**Alternatives considered**:
- Default to `00` — rejected because fingerprints would never match reference databases.
- Patch HAProxy to capture extension 16 — out of scope.

## Decision: TLS Version for Section A

**Decision**: Use `supported_versions` binary data to find the highest non-GREASE version. Fall back to `proto` if absent.

**Rationale**: TLS 1.3 clients set the ClientHello version to 0x0303 (TLS 1.2) for backward compatibility, advertising actual support via `supported_versions`. Both reference Lua implementations use this logic.

**Version mapping**: 0x0304→`13`, 0x0303→`12`, 0x0302→`11`, 0x0301→`10`, 0x0300→`s3`, unknown→`00`.

## Decision: SNI Detection

**Decision**: Use `ssl_fc_has_sni` as a dedicated SPOE argument.

**Rationale**: Both reference Lua implementations use this fetch. Cleaner than scanning extensions binary for type 0x0000.

## Decision: Empty Section Handling

**Decision**: Return literal `000000000000` for empty sections (not SHA256 of empty string).

**Rationale**: FoxIO reference implementation and both Lua implementations return this literal value. The actual SHA256 of empty string truncated to 12 chars would be `e3b0c4429802`, which would be misleading.

## Decision: GREASE Filtering

**Decision**: Use HAProxy's `(1)` argument to `_bin` fetches for GREASE pre-filtering. No additional plugin-side GREASE filtering for JA4.

**Rationale**: Both reference Lua implementations rely entirely on HAProxy's pre-filtering. The `(1)` argument is well-established across HAProxy 2.8+.

## Decision: SHA256 Crate

**Decision**: Use the `sha2` crate from the RustCrypto project.

**Rationale**: Same family as `md-5` already used for JA3. Pure Rust, no system dependencies.

## Decision: Project Structure

**Decision**: Add JA4 as a new `src/ja4/` module alongside the existing `src/ja3/` module.

**Rationale**: JA4 shares some infrastructure (binary parsing, types) with JA3 but has fundamentally different computation (SHA256 vs MD5, hex encoding, section A metadata). Separate module keeps concerns isolated and validates the extensible architecture (SC-004).

## Cross-Reference: Existing HAProxy JA4 Implementations

Two Lua implementations were analyzed for correctness validation:

1. **FriendlyCaptcha/ja4-haproxy** — Correct implementation per FoxIO spec. Documents the negotiated-ALPN limitation.
2. **O-X-L/haproxy-ja4-fingerprint** — Mostly correct but has deviations:
   - JA4_r format splits section A into individual underscore-separated fields (non-standard)
   - ALPN non-alphanumeric handling uses hex encoding instead of scanning for alphanumeric chars

Our implementation follows the FoxIO spec and avoids both O-X-L deviations.
