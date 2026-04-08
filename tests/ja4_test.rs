use fingerprinting_plugin::common::types::ClientHelloData;
use fingerprinting_plugin::ja4::compute_ja4;

fn make_ja4_data(
    proto: u16,
    ciphers: &[u16],
    extensions: &[u16],
    supported_versions: &[u16],
    sigalgs: &[u16],
    alpn: Option<&str>,
    sni_present: bool,
) -> ClientHelloData {
    ClientHelloData {
        protocol_version: proto,
        cipher_suites: ciphers.to_vec(),
        extensions: extensions.to_vec(),
        elliptic_curves: vec![],
        ec_point_formats: vec![],
        supported_versions: supported_versions.to_vec(),
        signature_algorithms: sigalgs.to_vec(),
        alpn: alpn.map(String::from),
        sni_present,
    }
}

// =============================================================================
// Authoritative JA4 test vectors from FoxIO JA4 repository.
// Source: https://github.com/FoxIO-LLC/ja4
//   - technical_details/JA4.md (worked example)
//   - python/test/testdata/*.json (pcap-derived test data)
// =============================================================================

// FoxIO JA4.md canonical example: Chrome-like, TLS 1.3, ALPN=h2
#[test]
fn foxio_chrome_tls13_h2() {
    let data = make_ja4_data(
        0x0303,
        &[
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ],
        &[
            0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
            0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
        ],
        &[0x0304, 0x0303],
        &[
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ],
        Some("h2"),
        true,
    );

    let (ja4, ja4_r) = compute_ja4(&data);

    assert_eq!(ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
    assert_eq!(
        ja4_r,
        "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9\
         _0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01\
         _0403,0804,0401,0503,0805,0501,0806,0601"
    );
}

// Same as above but ALPN=http/1.1 -> indicator "h1"
#[test]
fn foxio_chrome_tls13_h1() {
    let data = make_ja4_data(
        0x0303,
        &[
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ],
        &[
            0x000d, 0x0033, 0x0000, 0xff01, 0x002b, 0x0023, 0x002d, 0x0005, 0x0012, 0x000b, 0x0017,
            0x4469, 0x0010, 0x001b, 0x000a, 0x0015,
        ],
        &[0x0304, 0x0303],
        &[
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ],
        Some("http/1.1"),
        true,
    );

    let (ja4, _) = compute_ja4(&data);

    // Only ALPN differs from h2 test — b and c hashes are the same
    assert_eq!(ja4, "t13d1516h1_8daaf6152771_e5627efa2ab1");
}

// TLS 1.2 (no supported_versions), 46 ciphers, ALPN=h2
#[test]
fn foxio_tls12_46_ciphers_h2() {
    let data = make_ja4_data(
        0x0303, // TLS 1.2 via protocol version
        &[
            0xc030, 0xc02c, 0xc028, 0xc024, 0xc014, 0xc00a, 0x009f, 0x006b, 0x0039, 0xcca9, 0xcca8,
            0xccaa, 0xff85, 0x00c4, 0x0088, 0x0081, 0x009d, 0x003d, 0x0035, 0x00c0, 0x0084, 0xc02f,
            0xc02b, 0xc027, 0xc023, 0xc013, 0xc009, 0x009e, 0x0067, 0x0033, 0x00be, 0x0045, 0x009c,
            0x003c, 0x002f, 0x00ba, 0x0041, 0xc011, 0xc007, 0x0005, 0x0004, 0xc012, 0xc008, 0x0016,
            0x000a, 0x00ff,
        ],
        &[0x0000, 0x000b, 0x000a, 0x000d, 0x0010],
        &[], // no supported_versions → fallback to proto
        &[
            0x0601, 0x0603, 0xefef, 0x0501, 0x0503, 0x0401, 0x0403, 0xeeee, 0xeded, 0x0301, 0x0303,
            0x0201, 0x0203,
        ],
        Some("h2"),
        true,
    );

    let (ja4, ja4_r) = compute_ja4(&data);

    assert_eq!(ja4, "t12d4605h2_85626a9a5f7f_aaf95bb78ec9");
    assert_eq!(
        ja4_r,
        "t12d4605h2_0004,0005,000a,0016,002f,0033,0035,0039,003c,003d,0041,0045,0067,006b,\
         0081,0084,0088,009c,009d,009e,009f,00ba,00be,00c0,00c4,00ff,c007,c008,c009,c00a,\
         c011,c012,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9,ccaa,ff85\
         _000a,000b,000d\
         _0601,0603,efef,0501,0503,0401,0403,eeee,eded,0301,0303,0201,0203"
    );
}

// TLS 1.3, 16 ciphers (badcurveball.pcap)
#[test]
fn foxio_badcurveball() {
    let data = make_ja4_data(
        0x0303,
        &[
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
        ],
        &[
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033,
            0x002d, 0x002b, 0x001b, 0x0015,
        ],
        &[0x0304, 0x0303],
        &[
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
        ],
        Some("h2"),
        true,
    );

    let (ja4, _) = compute_ja4(&data);
    assert_eq!(ja4, "t13d1615h2_46e7e9700bed_45f260be83e2");
}

// TLS 1.2, no ALPN → "00"
#[test]
fn foxio_tls12_no_alpn() {
    let data = make_ja4_data(
        0x0303,
        &[
            0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc027, 0xc00a, 0xc009, 0xc014,
            0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x000a,
        ],
        &[
            0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0023, 0x0017, 0xff01,
        ],
        &[],
        &[
            0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601,
            0x0603,
        ],
        None,
        true,
    );

    let (ja4, _) = compute_ja4(&data);
    assert_eq!(ja4, "t12d190800_d83cc789557e_7af1ed941c26");
}

// TLS 1.3, Firefox-like (tls12.pcap)
#[test]
fn foxio_firefox_tls13() {
    let data = make_ja4_data(
        0x0303,
        &[
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009,
            0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ],
        &[
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0022, 0x0033, 0x002b,
            0x000d, 0x002d, 0x001c, 0x0015,
        ],
        &[0x0304, 0x0303],
        &[
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
        ],
        Some("h2"),
        true,
    );

    let (ja4, _) = compute_ja4(&data);
    assert_eq!(ja4, "t13d1715h2_5b57614c22b0_3d5424432f57");
}

// TLS 1.3, different extension set with 0029 (tls3.pcapng stream 9)
#[test]
fn foxio_ext_0029() {
    let data = make_ja4_data(
        0x0303,
        &[
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ],
        &[
            0x0033, 0x000a, 0x0005, 0x000d, 0x0012, 0x0000, 0x0010, 0x002b, 0x0023, 0x001b, 0x0017,
            0x002d, 0xff01, 0x4469, 0x000b, 0x0029,
        ],
        &[0x0304, 0x0303],
        &[
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ],
        Some("h2"),
        true,
    );

    let (ja4, _) = compute_ja4(&data);
    assert_eq!(ja4, "t13d1516h2_8daaf6152771_9b887d9acb53");
}

// =============================================================================
// Edge cases
// =============================================================================

#[test]
fn empty_fields() {
    let data = make_ja4_data(0x0303, &[], &[], &[], &[], None, false);
    let (ja4, _) = compute_ja4(&data);
    // t12i0000 00 _ 000000000000 _ 000000000000
    assert!(ja4.starts_with("t12i000000_000000000000_000000000000"));
}

#[test]
fn sni_absent_produces_i() {
    let data = make_ja4_data(0x0303, &[0x1301], &[], &[0x0304], &[], Some("h2"), false);
    let (ja4, _) = compute_ja4(&data);
    assert!(ja4.starts_with("t13i"));
}

#[test]
fn version_from_supported_versions_prefers_highest() {
    let data = make_ja4_data(
        0x0301, // TLS 1.0 in proto
        &[0x1301],
        &[],
        &[0x0303, 0x0304, 0x0302], // highest is 0x0304 = TLS 1.3
        &[],
        None,
        true,
    );
    let (ja4, _) = compute_ja4(&data);
    assert!(ja4.starts_with("t13d"));
}

#[test]
fn cipher_count_capped_at_99() {
    let ciphers: Vec<u16> = (1..=120).collect();
    let data = make_ja4_data(0x0303, &ciphers, &[], &[], &[], None, true);
    let (ja4, _) = compute_ja4(&data);
    // Section A should have "99" for cipher count, not "120"
    assert!(ja4.contains("d9900"));
}

#[test]
fn no_sigalgs_means_no_trailing_underscore_in_section_c() {
    let data = make_ja4_data(
        0x0303,
        &[0x1301],
        &[0x000d, 0x0033], // no SNI, no ALPN to remove
        &[0x0304],
        &[],
        None,
        true,
    );
    let (_, ja4_r) = compute_ja4(&data);
    // Raw should end with sorted extensions, no trailing underscore
    assert!(ja4_r.ends_with("000d,0033"));
}
