# Contract: SPOE Message Format

**Feature**: 001-tls-fingerprinting
**Date**: 2026-04-06

## SPOE Message: `get-fingerprint`

### Arguments (HAProxy → Plugin)

| Argument | HAProxy Fetch | Type | Format |
|----------|---------------|------|--------|
| `proto` | `ssl_fc_protocol_hello_id` | Integer | u16 TLS version |
| `ciphers` | `ssl_fc_cipherlist_bin` | Binary | Big-endian u16 pairs |
| `extensions` | `ssl_fc_extlist_bin` | Binary | Big-endian u16 pairs |
| `curves` | `ssl_fc_eclist_bin` | Binary | Big-endian u16 pairs |
| `formats` | `ssl_fc_ecformats_bin` | Binary | u8 values |

**Note**: The `_bin` fetch functions are called WITHOUT the GREASE filter argument. The plugin handles GREASE filtering internally.

### Response Variables (Plugin → HAProxy)

All variables are session-scoped and namespaced under the plugin name by the hub (e.g., `fingerprinting.ja3n_hash`).

| Variable | Type | Format | Condition |
|----------|------|--------|-----------|
| `ja3_hash` | String | 32-char lowercase hex | `ja3` enabled (default: true) |
| `ja3_raw` | String | Variable length | `ja3` enabled (default: true) |
| `ja3n_hash` | String | 32-char lowercase hex | `ja3n` enabled (default: true) |
| `ja3n_raw` | String | Variable length | `ja3n` enabled (default: true) |

### Plugin Configuration Parameters

```json
{
  "type": "object",
  "properties": {
    "ja3":  { "type": "boolean", "default": true },
    "ja3n": { "type": "boolean", "default": true }
  },
  "additionalProperties": false
}
```

### Example SPOE Configuration

```
[get-fingerprint]
spoe-message get-fingerprint
    args proto=ssl_fc_protocol_hello_id ciphers=ssl_fc_cipherlist_bin extensions=ssl_fc_extlist_bin curves=ssl_fc_eclist_bin formats=ssl_fc_ecformats_bin
    event on-client-session
```

### Example Hub Configuration

```toml
[[plugins]]
name = "fingerprinting"
library = "libfingerprinting.so"
messages = ["get-fingerprint"]

[plugins.params]
ja3 = true
ja3n = true
```

### Error Handling

- Missing arguments: treated as empty. Plugin produces fingerprints with empty fields.
- Odd byte length in binary arguments: trailing byte ignored, warning logged.
- Unknown message name: empty `ProcessingResult` returned.
- All techniques disabled: empty `ProcessingResult` returned. Warning logged at startup.
