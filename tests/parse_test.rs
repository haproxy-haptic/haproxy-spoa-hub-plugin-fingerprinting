use fingerprinting_plugin::common::parse::{parse_u8, parse_u16_be};

#[test]
fn parse_valid_u16_be_pairs() {
    let data = [0x13, 0x01, 0x00, 0x2f];
    let result = parse_u16_be(&data);
    assert_eq!(result, vec![0x1301, 0x002f]);
}

#[test]
fn parse_empty_input() {
    assert_eq!(parse_u16_be(&[]), Vec::<u16>::new());
    assert_eq!(parse_u8(&[]), Vec::<u8>::new());
}

#[test]
fn parse_odd_byte_length_ignores_trailing() {
    let data = [0x13, 0x01, 0x00]; // 3 bytes, trailing 0x00 ignored
    let result = parse_u16_be(&data);
    assert_eq!(result, vec![0x1301]);
}

#[test]
fn parse_single_byte_input() {
    let data = [0xff];
    let result = parse_u16_be(&data);
    assert_eq!(result, Vec::<u16>::new()); // no complete pair
}

#[test]
fn parse_u8_identity() {
    let data = [0x00, 0x01, 0x02];
    assert_eq!(parse_u8(&data), vec![0, 1, 2]);
}
