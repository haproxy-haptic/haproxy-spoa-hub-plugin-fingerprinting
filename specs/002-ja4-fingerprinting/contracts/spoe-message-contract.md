# Contract: SPOE Message Format

**Feature**: 002-ja4-fingerprinting
**Date**: 2026-04-07

## SPOE Message: `get-fingerprint`

### Arguments (HAProxy → Plugin)

| Argument | HAProxy Fetch | Type | Format | Required by |
|----------|---------------|------|--------|-------------|
| `proto` | `ssl_fc_protocol_hello_id` | Integer | u16 TLS version | JA3, JA3N, JA4 |
| `ciphers` | `ssl_fc_cipherlist_bin(1)` | Binary | Big-endian u16 pairs, GREASE pre-filtered | JA3, JA3N, JA4 |
| `extensions` | `ssl_fc_extlist_bin(1)` | Binary | Big-endian u16 pairs, GREASE pre-filtered | JA3, JA3N, JA4 |
| `curves` | `ssl_fc_eclist_bin(1)` | Binary | Big-endian u16 pairs, GREASE pre-filtered | JA3, JA3N |
| `formats` | `ssl_fc_ecformats_bin` | Binary | u8 values | JA3, JA3N |
| `supported_versions` | `ssl_fc_supported_versions_bin(1)` | Binary | Big-endian u16 pairs, GREASE pre-filtered | JA4 |
| `sigalgs` | `ssl_fc_sigalgs_bin(1)` | Binary | Big-endian u16 pairs, GREASE pre-filtered | JA4 |
| `alpn` | `ssl_fc_alpn` | String | Negotiated ALPN protocol | JA4 (best-effort) |
| `sni` | `ssl_fc_has_sni` | Boolean/Integer | SNI presence flag | JA4 |

### Response Variables (Plugin → HAProxy)

All variables are session-scoped and namespaced under the plugin name by the hub.

| Variable | Type | Format | Description |
|----------|------|--------|-------------|
| `hash` | String | 32-char lowercase hex | JA3/JA3N MD5 hash |
| `raw` | String | Variable length | JA3/JA3N raw fingerprint string |
| `ja4` | String | 36 chars (`a_b_c`) | JA4 fingerprint (hashed sections) |
| `ja4_r` | String | Variable length | JA4 raw fingerprint (unhashed sections) |

### Example SPOE Configuration

```
[fingerprinting]
spoe-agent fingerprinting-agent
    messages get-fingerprint
    option var-prefix spoe
    option continue-on-error
    timeout hello      2s
    timeout idle       5m
    timeout processing 50ms
    use-backend spoa-hub-backend

spoe-message get-fingerprint
    args proto=ssl_fc_protocol_hello_id ciphers=ssl_fc_cipherlist_bin(1) extensions=ssl_fc_extlist_bin(1) curves=ssl_fc_eclist_bin(1) formats=ssl_fc_ecformats_bin supported_versions=ssl_fc_supported_versions_bin(1) sigalgs=ssl_fc_sigalgs_bin(1) alpn=ssl_fc_alpn sni=ssl_fc_has_sni
    event on-frontend-http-request if !{ var(sess.spoe.fingerprinting.hash) -m found }
```

### Error Handling

- Missing arguments: treated as empty/absent. JA3/JA3N produce fingerprints with empty fields. JA4 uses defaults (`00` for missing ALPN/version, `000000000000` for empty hash sections).
- Odd byte length in binary arguments: trailing byte ignored, warning logged.
- Unknown message name: empty `ProcessingResult` returned.

### Known Limitations

- The `alpn` argument provides the server-negotiated ALPN protocol, not the client's offered ALPN list. JA4 section A's ALPN indicator may differ from reference implementations when the server overrides client ALPN preference.
