/// Detects GREASE (RFC 8701) values in TLS ClientHello fields.
///
/// GREASE values follow the pattern: both bytes are identical and match 0x?a
/// where ? is any nibble. Examples: 0x0a0a, 0x1a1a, ..., 0xfafa.
pub fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}
