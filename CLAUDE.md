# haproxy-spoa-hub-plugin-fingerprinting Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-04-06

## Active Technologies
- Rust (edition 2024, minimum 1.86) + `haproxy-spoa-hub-plugin-api` (abi_stable plugin trait), `md-5` (MD5 hashing) (001-tls-fingerprinting)
- N/A (stateless computation) (001-tls-fingerprinting)

- Rust (edition 2024, minimum 1.86) + `haproxy-spoa-hub-plugin-api` (abi_stable plugin trait), `sha2` (SHA256), `md-5` (MD5, from feature 001) (002-ja4-fingerprinting)

## Project Structure

```text
src/
tests/
```

## Commands

cargo test [ONLY COMMANDS FOR ACTIVE TECHNOLOGIES][ONLY COMMANDS FOR ACTIVE TECHNOLOGIES] cargo clippy

## Code Style

Rust (edition 2024, minimum 1.86): Follow standard conventions

## Recent Changes
- 001-tls-fingerprinting: Added Rust (edition 2024, minimum 1.86) + `haproxy-spoa-hub-plugin-api` (abi_stable plugin trait), `md-5` (MD5 hashing)

- 002-ja4-fingerprinting: Added Rust (edition 2024, minimum 1.86) + `haproxy-spoa-hub-plugin-api` (abi_stable plugin trait), `sha2` (SHA256), `md-5` (MD5, from feature 001)

<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
