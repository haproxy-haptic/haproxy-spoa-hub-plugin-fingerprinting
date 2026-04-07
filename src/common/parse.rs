use log::warn;

/// Parses a byte slice into a vector of big-endian u16 values.
///
/// If the input has an odd number of bytes, the trailing byte is ignored
/// and a warning is logged.
pub fn parse_u16_be(data: &[u8]) -> Vec<u16> {
    if data.len() % 2 != 0 {
        warn!(
            "Binary field has odd byte length ({}), trailing byte ignored",
            data.len()
        );
    }
    let mut result = Vec::with_capacity(data.len() / 2);
    for c in data.chunks_exact(2) {
        result.push(u16::from_be_bytes([c[0], c[1]]));
    }
    result
}

/// Parses a byte slice into a vector of u8 values (identity operation).
pub fn parse_u8(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}
