use std::fmt::Write;

use md5::{Digest, Md5};

use crate::common::grease::is_grease;
use crate::common::types::ClientHelloData;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Computes a JA3/JA3N fingerprint from parsed ClientHello data.
///
/// Returns `(md5_hash, raw_string)` where:
/// - `raw_string` is in the format `version,ciphers,extensions,curves,formats`
///   with dash-separated values within each field
/// - `md5_hash` is the 32-character lowercase hex MD5 digest of the raw string
///
/// `sort_extensions`: true for JA3N (sorted ascending), false for JA3 (original order).
/// `exclude_ext`: extension ID to exclude (-1 for none). Default is 41 (pre_shared_key).
pub fn compute_ja3(
    data: &ClientHelloData,
    sort_extensions: bool,
    exclude_ext: i32,
) -> (String, String) {
    let mut raw = String::with_capacity(256);

    // Version
    let _ = write!(raw, "{}", data.protocol_version);

    // Ciphers (GREASE filtered)
    raw.push(',');
    write_filtered_u16(&mut raw, &data.cipher_suites, |v| !is_grease(v));

    // Extensions (GREASE filtered, exclude_ext filtered, optionally sorted)
    raw.push(',');
    if sort_extensions {
        let mut exts: Vec<u16> = data
            .extensions
            .iter()
            .copied()
            .filter(|&v| !is_grease(v) && (exclude_ext < 0 || v != exclude_ext as u16))
            .collect();
        exts.sort_unstable();
        write_u16_joined(&mut raw, &exts);
    } else {
        write_filtered_u16(&mut raw, &data.extensions, |v| {
            !is_grease(v) && (exclude_ext < 0 || v != exclude_ext as u16)
        });
    }

    // Curves (GREASE filtered)
    raw.push(',');
    write_filtered_u16(&mut raw, &data.elliptic_curves, |v| !is_grease(v));

    // EC point formats (no filtering)
    raw.push(',');
    write_u8_joined(&mut raw, &data.ec_point_formats);

    // MD5 hash
    let mut hasher = Md5::new();
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    let mut hash = String::with_capacity(32);
    for &b in digest.iter() {
        hash.push(HEX[(b >> 4) as usize] as char);
        hash.push(HEX[(b & 0x0f) as usize] as char);
    }

    (hash, raw)
}

fn write_filtered_u16(buf: &mut String, values: &[u16], filter: impl Fn(u16) -> bool) {
    let mut first = true;
    for &v in values {
        if filter(v) {
            if !first {
                buf.push('-');
            }
            let _ = write!(buf, "{v}");
            first = false;
        }
    }
}

fn write_u16_joined(buf: &mut String, values: &[u16]) {
    for (i, &v) in values.iter().enumerate() {
        if i > 0 {
            buf.push('-');
        }
        let _ = write!(buf, "{v}");
    }
}

fn write_u8_joined(buf: &mut String, values: &[u8]) {
    for (i, &v) in values.iter().enumerate() {
        if i > 0 {
            buf.push('-');
        }
        let _ = write!(buf, "{v}");
    }
}
