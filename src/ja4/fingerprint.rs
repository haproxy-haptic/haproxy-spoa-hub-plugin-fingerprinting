use sha2::{Digest, Sha256};

use crate::common::types::ClientHelloData;

use super::section_a::build_section_a;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Compute JA4 fingerprint from parsed ClientHello data.
///
/// Returns `(ja4, ja4_r)` where:
/// - `ja4` is the 36-character hashed fingerprint in `a_b_c` format
/// - `ja4_r` is the raw fingerprint with full sorted hex lists
pub fn compute_ja4(data: &ClientHelloData) -> (String, String) {
    // Section A: metadata
    let cipher_count = data.cipher_suites.len();
    let ext_count = data.extensions.len();
    let section_a = build_section_a(
        data.sni_present,
        &data.supported_versions,
        data.protocol_version,
        cipher_count,
        ext_count,
        data.alpn.as_deref(),
    );

    // Section B: sorted ciphers as 4-char hex
    let mut ciphers_hex: Vec<String> = data
        .cipher_suites
        .iter()
        .map(|&v| format!("{v:04x}"))
        .collect();
    ciphers_hex.sort();
    let ciphers_raw = ciphers_hex.join(",");
    let section_b = if ciphers_raw.is_empty() {
        "000000000000".to_string()
    } else {
        truncated_sha256(&ciphers_raw)
    };

    // Section C: sorted extensions (minus SNI 0x0000 and ALPN 0x0010) + sigalgs
    let mut exts_hex: Vec<String> = data
        .extensions
        .iter()
        .filter(|&&v| v != 0x0000 && v != 0x0010)
        .map(|&v| format!("{v:04x}"))
        .collect();
    exts_hex.sort();
    let exts_raw = exts_hex.join(",");

    let sigalgs_raw: String = data
        .signature_algorithms
        .iter()
        .map(|&v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",");

    let section_c_input = if sigalgs_raw.is_empty() {
        exts_raw.clone()
    } else {
        let mut s = exts_raw.clone();
        s.push('_');
        s.push_str(&sigalgs_raw);
        s
    };

    let section_c = if section_c_input.is_empty() {
        "000000000000".to_string()
    } else {
        truncated_sha256(&section_c_input)
    };

    // Build JA4 (hashed)
    let mut ja4 = String::with_capacity(36);
    ja4.push_str(&section_a);
    ja4.push('_');
    ja4.push_str(&section_b);
    ja4.push('_');
    ja4.push_str(&section_c);

    // Build JA4_r (raw)
    let mut ja4_r = String::with_capacity(256);
    ja4_r.push_str(&section_a);
    ja4_r.push('_');
    ja4_r.push_str(&ciphers_raw);
    ja4_r.push('_');
    ja4_r.push_str(&exts_raw);
    if !sigalgs_raw.is_empty() {
        ja4_r.push('_');
        ja4_r.push_str(&sigalgs_raw);
    }

    (ja4, ja4_r)
}

fn truncated_sha256(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut hex = String::with_capacity(12);
    for &b in &digest[..6] {
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0x0f) as usize] as char);
    }
    hex
}
