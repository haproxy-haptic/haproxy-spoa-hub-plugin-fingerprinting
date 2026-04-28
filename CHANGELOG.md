# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-04-28

### Added

- Release artifacts (`${LIB_NAME}-<arch>-glibc<version>.so`) published to
  the GitLab Generic Package Registry under
  `packages/generic/fingerprinting/<tag>/` with stable URLs
- Per-file `<artifact>.sha256` sidecars and a combined `SHA256SUMS` for
  batch verification with `sha256sum -c SHA256SUMS`
- Cosign keyless signatures (`<artifact>.cosign.bundle`) for every release
  artifact, signed via the GitLab OIDC id token (Sigstore Fulcio + Rekor)
- `make verify-release VERSION=vX.Y.Z` target plus `scripts/verify-release.sh`
  for end-to-end consumer verification (downloads `SHA256SUMS`, checks all
  hashes, runs `cosign verify-blob` against the project's tag identity)
- Unsigned SLSA v0.2 provenance metadata emitted next to build artifacts
  via `RUNNER_GENERATE_ARTIFACTS_METADATA` (free SLSA-L1)

### Changed

- Release builds now use `cargo auditable build --release`, embedding a
  compressed `Cargo.lock`-equivalent in the `.so` file so SBOM tools can
  enumerate Rust dependencies without source access

## [0.1.0] - 2026-04-08

### Added

- JA3 and JA3N TLS fingerprinting from ClientHello data via SPOE
- JA4 TLS fingerprinting with structured `a_b_c` format (SHA256-truncated sections)
- Configurable `sort_extensions` parameter to choose between JA3 (unsorted) and JA3N (sorted) behavior
- Configurable `exclude_extensions` parameter supporting multiple extension IDs (default: `[41]` for pre_shared_key)
- Configurable `ja4` parameter to enable/disable JA4 output
- Session-scoped output variables: `hash`, `raw` (JA3/JA3N), `ja4`, `ja4_r` (JA4)
- JA4 section A metadata: protocol type, TLS version (from supported_versions), SNI presence, cipher/extension counts, ALPN indicator
- JA4 raw variant (`ja4_r`) with full sorted hex lists for debugging
- Unit tests validated against authoritative external sources: open-ch/ja3 and Wireshark (JA3), FoxIO JA4 repository (JA4)
- Criterion microbenchmarks (JA3N: ~1.6us, JA4: ~4.8us per fingerprint)
- Kind-based e2e benchmarks with fortio (HAProxy 3.3, mode spop)
- Docker Compose integration tests with HAProxy
- Example SPOE and hub configurations
- GitLab CI pipeline (fmt, clippy, test, bench, build)
- Release builds use LTO and single codegen unit for optimal performance

### Known Limitations

- JA4 ALPN field uses the server-negotiated protocol (`ssl_fc_alpn`) since HAProxy does not expose the client-offered ALPN list. This matches the approach used by other HAProxy JA4 implementations (FriendlyCaptcha, O-X-L).
