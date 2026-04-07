use fingerprinting_plugin::common::grease::is_grease;

#[test]
fn known_grease_values_return_true() {
    let grease_values: Vec<u16> = (0..16).map(|i| 0x0a0a + (i * 0x1010)).collect();
    for v in &grease_values {
        assert!(is_grease(*v), "Expected 0x{v:04x} to be GREASE");
    }
}

#[test]
fn non_grease_values_return_false() {
    let non_grease = [0x0001, 0x1234, 0x0000, 0xffff, 0x0a0b, 0x1a2a, 47, 4865];
    for v in &non_grease {
        assert!(!is_grease(*v), "Expected 0x{v:04x} to NOT be GREASE");
    }
}

#[test]
fn boundary_values() {
    assert!(is_grease(0x0a0a));
    assert!(is_grease(0xfafa));
    assert!(!is_grease(0x0a0b));
    assert!(!is_grease(0x0b0a));
}
