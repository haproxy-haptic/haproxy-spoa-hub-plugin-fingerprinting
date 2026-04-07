# Data Model: TLS Fingerprinting Plugin

**Feature**: 001-tls-fingerprinting
**Date**: 2026-04-06

## Entities

### ClientHelloData

Parsed representation of TLS ClientHello fields received via SPOE message arguments.

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| protocol_version | u16 | `proto` arg | TLS version from ClientHello header (e.g., 771 for TLS 1.2) |
| cipher_suites | Vec<u16> | `ciphers` arg | Offered cipher suite IDs, big-endian u16 pairs |
| extensions | Vec<u16> | `extensions` arg | Extension type IDs, big-endian u16 pairs |
| elliptic_curves | Vec<u16> | `curves` arg | Supported group IDs, big-endian u16 pairs |
| ec_point_formats | Vec<u8> | `formats` arg | EC point format IDs |

**Validation rules**:
- Binary fields with odd byte length: trailing byte ignored, warning logged
- GREASE values filtered during parsing: `(v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)`
- Extension 41 (pre_shared_key) excluded from extensions list
- Missing arguments treated as empty (not an error)

### Ja3Fingerprint

Computed JA3 or JA3N fingerprint output.

| Field | Type | Description |
|-------|------|-------------|
| hash | String (32 chars) | MD5 hex digest (lowercase) of raw fingerprint |
| raw | String (variable) | Fingerprint string: `version,ciphers,extensions,curves,formats` |

**Raw string format**:
- Fields separated by commas
- Values within fields separated by dashes
- Empty fields produce empty strings between commas (e.g., `771,,,,`)

**JA3 vs JA3N difference**:
- JA3: extensions in original ClientHello order
- JA3N: extensions sorted numerically ascending

### PluginConfig

Configuration parsed from hub's `[plugins.params]` TOML table during init.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| ja3 | bool | true | Enable JA3 fingerprint computation |
| ja3n | bool | true | Enable JA3N fingerprint computation |

### FingerprintTechnique (trait)

Internal abstraction for fingerprinting algorithms.

| Method | Returns | Description |
|--------|---------|-------------|
| name() | &str | Technique identifier used as variable prefix |
| compute(data: &ClientHelloData) | Vec<TxnVariable> | Produces output variables from parsed ClientHello |

## Relationships

```
SpoeMessage ──parsed into──> ClientHelloData
ClientHelloData ──fed to──> FingerprintTechnique (JA3, sort=false)
ClientHelloData ──fed to──> FingerprintTechnique (JA3N, sort=true)
FingerprintTechnique ──produces──> Vec<TxnVariable>
PluginConfig ──controls──> which techniques are active
```

## State Transitions

None — fingerprint computation is stateless. Each SPOE message is processed independently. Plugin configuration is immutable after init.

## Scale Assumptions

- Each fingerprint computation is O(n log n) where n is the number of extensions (sorting step for JA3N)
- Memory per computation: bounded by ClientHello size (~2KB max for realistic clients)
- No accumulated state between requests
- Techniques iterate sequentially per message (2 techniques, <1ms total)
