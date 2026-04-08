# Data Model: JA4 TLS Fingerprinting

**Feature**: 002-ja4-fingerprinting
**Date**: 2026-04-06

## Entities

### ClientHelloData (shared with JA3/JA3N)

Parsed representation of TLS ClientHello fields received via SPOE message arguments.

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| protocol_version | u16 | `proto` arg | TLS version from ClientHello header |
| cipher_suites | Vec<u16> | `ciphers` arg | Offered cipher suite IDs (big-endian pairs) |
| extensions | Vec<u16> | `extensions` arg | Extension type IDs (big-endian pairs) |
| elliptic_curves | Vec<u16> | `curves` arg | Supported group IDs (big-endian pairs) |
| ec_point_formats | Vec<u8> | `formats` arg | EC point format IDs |
| supported_versions | Vec<u16> | `supported_versions` arg | Supported TLS versions (JA4-specific) |
| signature_algorithms | Vec<u16> | `sigalgs` arg | Signature algorithm IDs (JA4-specific) |
| alpn | Option<String> | `alpn` arg | Negotiated ALPN protocol (best-effort, JA4-specific) |
| sni_present | bool | `sni` arg | Whether SNI extension was present in ClientHello (JA4-specific) |

**Validation rules**:
- Binary fields with odd byte length: trailing byte ignored, warning logged
- GREASE values filtered from all u16 lists during parsing
- Missing arguments treated as empty (not an error)

### Ja4Fingerprint

Computed JA4 fingerprint output.

| Field | Type | Description |
|-------|------|-------------|
| fingerprint | String (36 chars) | `a_b_c` format: section A + section B hash + section C hash |
| raw | String (variable) | `a_b_c` format: section A + raw cipher list + raw ext/sigalg list |

**Sections**:

| Section | Length | Content |
|---------|--------|---------|
| A | 10 chars | `{proto}{version}{sni}{cipher_count}{ext_count}{alpn}` |
| B | 12 chars (hashed) / variable (raw) | SHA256 truncated hash of sorted cipher hex list |
| C | 12 chars (hashed) / variable (raw) | SHA256 truncated hash of sorted ext hex + original-order sigalg hex |

### Ja3Fingerprint (from feature 001, for reference)

| Field | Type | Description |
|-------|------|-------------|
| hash | String (32 chars) | MD5 hex digest of raw fingerprint |
| raw | String (variable) | `version,ciphers,extensions,curves,formats` format |

## Relationships

```
ClientHelloData ──produces──> Ja3Fingerprint (via JA3 technique, sort_ext=false)
ClientHelloData ──produces──> Ja3nFingerprint (via JA3 technique, sort_ext=true)
ClientHelloData ──produces──> Ja4Fingerprint (via JA4 technique)
ClientHelloData ──produces──> Ja4RawFingerprint (via JA4 technique)
```

## State Transitions

None — fingerprint computation is stateless. Each SPOE message produces output independently.

## Scale Assumptions

- Each fingerprint computation is O(n log n) where n is the number of extensions (sorting step)
- Memory per computation: bounded by ClientHello size (~2KB max for realistic clients)
- No accumulated state between requests
