# Contract: SPOE Message Format

**Feature**: 002-ja4-fingerprinting
**Date**: 2026-04-06

## SPOE Message: `get-fingerprint`

### Arguments (HAProxy → Plugin)

| Argument | HAProxy Fetch | Type | Format | Required by |
|----------|---------------|------|--------|-------------|
| `proto` | `ssl_fc_protocol_hello_id` | Integer | u16 TLS version | JA3, JA3N, JA4 |
| `ciphers` | `ssl_fc_cipherlist_bin` | Binary | Big-endian u16 pairs | JA3, JA3N, JA4 |
| `extensions` | `ssl_fc_extlist_bin` | Binary | Big-endian u16 pairs | JA3, JA3N, JA4 |
| `curves` | `ssl_fc_eclist_bin` | Binary | Big-endian u16 pairs | JA3, JA3N |
| `formats` | `ssl_fc_ecformats_bin` | Binary | u8 values | JA3, JA3N |
| `supported_versions` | `ssl_fc_supported_versions_bin` | Binary | Big-endian u16 pairs | JA4 |
| `sigalgs` | `ssl_fc_sigalgs_bin` | Binary | Big-endian u16 pairs | JA4 |
| `alpn` | `ssl_fc_alpn` | String | Negotiated ALPN protocol | JA4 (best-effort) |

**Note**: The `_bin` fetch functions are called WITHOUT the GREASE filter argument `(1)`. GREASE filtering is performed by the plugin to ensure consistent handling across all fingerprinting techniques.

### Response Variables (Plugin → HAProxy)

All variables are session-scoped and namespaced under the plugin name by the hub.

| Variable | Type | Format | Description |
|----------|------|--------|-------------|
| `ja3_hash` | String | 32-char lowercase hex | JA3 MD5 hash (unsorted extensions) |
| `ja3_raw` | String | Variable length | JA3 raw fingerprint string |
| `ja3n_hash` | String | 32-char lowercase hex | JA3N MD5 hash (sorted extensions) |
| `ja3n_raw` | String | Variable length | JA3N raw fingerprint string |
| `ja4` | String | 36 chars (`a_b_c`) | JA4 fingerprint (hashed sections) |
| `ja4_r` | String | Variable length | JA4 raw fingerprint (unhashed sections) |

### Example SPOE Configuration

```
[get-fingerprint]
spoe-message get-fingerprint
    args proto=ssl_fc_protocol_hello_id ciphers=ssl_fc_cipherlist_bin extensions=ssl_fc_extlist_bin curves=ssl_fc_eclist_bin formats=ssl_fc_ecformats_bin supported_versions=ssl_fc_supported_versions_bin sigalgs=ssl_fc_sigalgs_bin alpn=ssl_fc_alpn
    event on-client-session
```

### Error Handling

- Missing arguments: treated as empty/absent. JA3/JA3N produce fingerprints with empty fields. JA4 uses defaults (`00` for missing ALPN/version, `000000000000` for empty hash sections).
- Odd byte length in binary arguments: trailing byte ignored, warning logged.
- Unknown message name: empty `ProcessingResult` returned (no variables set).

### Known Limitations

- The `alpn` argument provides the server-negotiated ALPN protocol, not the client's offered ALPN list. This may cause JA4 section A's ALPN indicator to differ from reference implementations when the server's ALPN preference differs from the client's first offered value.
- SNI presence is inferred from the `extensions` list (checking for type 0x0000) rather than a dedicated argument.
