use criterion::{Criterion, criterion_group, criterion_main};
use fingerprinting_plugin::common::types::ClientHelloData;
use fingerprinting_plugin::ja3::compute_ja3;
use fingerprinting_plugin::ja4::compute_ja4;

fn chrome_ja3_data() -> ClientHelloData {
    ClientHelloData {
        protocol_version: 771,
        cipher_suites: vec![
            0x1a1a, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156,
            157, 47, 53,
        ],
        extensions: vec![
            0x0a0a, 51, 27, 0, 16, 17513, 65281, 23, 65037, 11, 45, 43, 5, 35, 10, 18, 13, 41,
        ],
        elliptic_curves: vec![0x4a4a, 29, 23, 24],
        ec_point_formats: vec![0],
        supported_versions: vec![],
        signature_algorithms: vec![],
        alpn: None,
        sni_present: false,
    }
}

fn chrome_ja4_data() -> ClientHelloData {
    ClientHelloData {
        protocol_version: 0x0303,
        cipher_suites: vec![
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ],
        extensions: vec![
            0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
            0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
        ],
        elliptic_curves: vec![],
        ec_point_formats: vec![],
        supported_versions: vec![0x0304, 0x0303],
        signature_algorithms: vec![
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ],
        alpn: Some("h2".to_string()),
        sni_present: true,
    }
}

fn bench_fingerprints(c: &mut Criterion) {
    let ja3_data = chrome_ja3_data();
    let ja4_data = chrome_ja4_data();

    c.bench_function("ja3n_chrome", |b| {
        b.iter(|| compute_ja3(&ja3_data, true, &[41]));
    });

    c.bench_function("ja4_chrome", |b| {
        b.iter(|| compute_ja4(&ja4_data));
    });

    c.bench_function("ja3n+ja4_chrome", |b| {
        b.iter(|| {
            compute_ja3(&ja4_data, true, &[41]);
            compute_ja4(&ja4_data);
        });
    });
}

criterion_group!(benches, bench_fingerprints);
criterion_main!(benches);
