use fingerprinting_plugin::common::types::ClientHelloData;
use fingerprinting_plugin::ja3::compute_ja3;

fn make_data(
    version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    curves: &[u16],
    formats: &[u8],
) -> ClientHelloData {
    ClientHelloData {
        protocol_version: version,
        cipher_suites: ciphers.to_vec(),
        extensions: extensions.to_vec(),
        elliptic_curves: curves.to_vec(),
        ec_point_formats: formats.to_vec(),
    }
}

// =============================================================================
// Authoritative JA3 test vectors from independent implementations.
//
// These use sort_extensions=false, exclude_ext=-1 (standard JA3) so the
// expected hashes can be verified against published values. Each hash was
// independently confirmed via Python hashlib.md5 against the raw string.
// =============================================================================

// Source: open-ch/ja3 (https://github.com/open-ch/ja3) ja3_test.go
// Chrome to www.google.ch, TLS 1.2 — parsed from raw ClientHello bytes
#[test]
fn open_ch_chrome_tls12() {
    let data = make_data(
        771,
        &[
            49200, 49196, 49199, 49195, 49172, 49162, 49171, 49161, 159, 158, 57, 51, 157, 156, 53,
            47, 10, 255,
        ],
        &[0, 11, 10, 35, 13, 5, 15, 13172],
        &[23, 25, 28, 27, 24, 26, 22, 14, 13, 11, 12, 9, 10],
        &[0, 1, 2],
    );
    let (hash, raw) = compute_ja3(&data, false, -1);
    assert_eq!(
        raw,
        "771,49200-49196-49199-49195-49172-49162-49171-49161-159-158-57-51-157-156-53-47-10-255,\
         0-11-10-35-13-5-15-13172,23-25-28-27-24-26-22-14-13-11-12-9-10,0-1-2"
    );
    assert_eq!(hash, "5e647d60a56d199388ae462b75b3cdad");
}

// Source: open-ch/ja3 ja3_test.go
// GREASE value 0x2a2a in ciphers must be stripped
#[test]
fn open_ch_grease_filtering() {
    let data = make_data(768, &[0x2a2a], &[0], &[], &[]);
    let (hash, raw) = compute_ja3(&data, false, -1);
    assert_eq!(raw, "768,,0,,");
    assert_eq!(hash, "633682cdbaaa3594417b8a6514f56ac7");
}

// Source: Wireshark issue #17942 (https://gitlab.com/wireshark/wireshark/-/issues/17942)
// Chrome with GREASE values in ciphers, extensions, and curves
#[test]
fn wireshark_chrome_grease() {
    let data = make_data(
        771,
        &[
            0x1a1a, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156,
            157, 47, 53,
        ],
        &[
            0x0a0a, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21,
        ],
        &[0x4a4a, 29, 23, 24],
        &[0],
    );
    let (hash, raw) = compute_ja3(&data, false, -1);
    assert_eq!(
        raw,
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,\
         0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
    );
    assert_eq!(hash, "cd08e31494f9531f560d64c695473da9");
}

// =============================================================================
// JA3N tests (sorted extensions, exclude ext 41).
//
// No published reference hashes exist for JA3N — it is HAProxy-specific.
// These verify sorting and exclusion logic by building on the authoritative
// JA3 vectors above where the unsorted raw string and hash are known-good.
// =============================================================================

// Same Chrome+GREASE data as wireshark_chrome_grease, but with sorted extensions.
// The JA3 hash is verified above; this confirms sorting produces a different hash.
#[test]
fn ja3n_chrome_sorted_extensions() {
    let data = make_data(
        771,
        &[
            0x1a1a, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156,
            157, 47, 53,
        ],
        &[
            0x0a0a, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21,
        ],
        &[0x4a4a, 29, 23, 24],
        &[0],
    );
    let (hash_ja3, _) = compute_ja3(&data, false, -1);
    let (hash_ja3n, raw_ja3n) = compute_ja3(&data, true, -1);

    // Extensions are numerically sorted
    assert_eq!(
        raw_ja3n,
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,\
         0-5-10-11-13-16-18-21-23-27-35-43-45-51-17513-65281,29-23-24,0"
    );
    // Ciphers, curves, formats unchanged — only extension order differs
    assert_ne!(hash_ja3, hash_ja3n);
}

// Extension 41 exclusion
#[test]
fn ja3n_excludes_ext_41() {
    let data = make_data(771, &[], &[0, 41, 23, 10], &[], &[]);

    // No exclusion keeps 41
    let (_, raw) = compute_ja3(&data, true, -1);
    assert_eq!(raw, "771,,0-10-23-41,,");

    // Exclude 41
    let (_, raw) = compute_ja3(&data, true, 41);
    assert_eq!(raw, "771,,0-10-23,,");
}

// =============================================================================
// Edge cases
// =============================================================================

#[test]
fn empty_fields() {
    let data = make_data(771, &[], &[], &[], &[]);
    let (hash, raw) = compute_ja3(&data, false, -1);
    assert_eq!(raw, "771,,,,");
    assert_eq!(hash.len(), 32);
    assert!(
        hash.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
    );
}

#[test]
fn all_grease_ciphers_produce_empty_field() {
    let data = make_data(771, &[0x0a0a, 0x1a1a, 0x2a2a], &[], &[], &[]);
    let (_, raw) = compute_ja3(&data, false, -1);
    assert_eq!(raw, "771,,,,");
}

#[test]
fn unsorted_vs_sorted_extensions() {
    let data = make_data(771, &[], &[51, 27, 0, 16], &[], &[]);

    let (_, unsorted) = compute_ja3(&data, false, -1);
    assert_eq!(unsorted, "771,,51-27-0-16,,");

    let (_, sorted) = compute_ja3(&data, true, -1);
    assert_eq!(sorted, "771,,0-16-27-51,,");
}

#[test]
fn custom_exclusion() {
    let data = make_data(771, &[], &[0, 16, 23], &[], &[]);
    let (_, raw) = compute_ja3(&data, true, 16);
    assert_eq!(raw, "771,,0-23,,");
}

#[test]
fn grease_filtered_from_all_fields() {
    let data = make_data(771, &[0x0a0a, 47], &[0x1a1a, 23], &[0x2a2a, 29], &[0]);
    let (_, raw) = compute_ja3(&data, false, -1);
    assert_eq!(raw, "771,47,23,29,0");
}
