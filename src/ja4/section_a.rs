use std::fmt::Write;

/// Map a u16 TLS version to the 2-char JA4 representation.
fn version_str(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

/// Determine the TLS version string for JA4 section A.
/// Prefers the highest value from supported_versions; falls back to proto.
pub fn tls_version(supported_versions: &[u16], proto: u16) -> &'static str {
    if let Some(&max_ver) = supported_versions.iter().max() {
        let s = version_str(max_ver);
        if s != "00" {
            return s;
        }
    }
    version_str(proto)
}

/// Extract the ALPN indicator (2 chars) from the negotiated ALPN string.
/// Returns the first and last alphanumeric characters, or "00" if absent.
pub fn alpn_indicator(alpn: Option<&str>) -> String {
    let Some(value) = alpn else {
        return "00".to_string();
    };
    if value.is_empty() {
        return "00".to_string();
    }

    let first = value.chars().find(|c| c.is_ascii_alphanumeric());
    let last = value.chars().rev().find(|c| c.is_ascii_alphanumeric());

    match (first, last) {
        (Some(f), Some(l)) => {
            let mut s = String::with_capacity(2);
            s.push(f);
            s.push(l);
            s
        }
        _ => "00".to_string(),
    }
}

/// Build the 10-character section A string.
pub fn build_section_a(
    sni_present: bool,
    supported_versions: &[u16],
    proto: u16,
    cipher_count: usize,
    ext_count: usize,
    alpn: Option<&str>,
) -> String {
    let mut a = String::with_capacity(10);
    a.push('t'); // protocol type: TLS
    a.push_str(tls_version(supported_versions, proto));
    a.push(if sni_present { 'd' } else { 'i' });
    let _ = write!(a, "{:02}", cipher_count.min(99));
    let _ = write!(a, "{:02}", ext_count.min(99));
    a.push_str(&alpn_indicator(alpn));
    a
}
