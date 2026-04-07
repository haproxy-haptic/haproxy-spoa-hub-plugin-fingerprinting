use criterion::{Criterion, criterion_group, criterion_main};
use fingerprinting_plugin::common::types::ClientHelloData;
use fingerprinting_plugin::ja3::compute_ja3;

fn chrome_data() -> ClientHelloData {
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
    }
}

fn curl_data() -> ClientHelloData {
    ClientHelloData {
        protocol_version: 771,
        cipher_suites: vec![
            4866, 4867, 4865, 49196, 49200, 159, 52393, 52392, 49195, 49199, 158, 49188, 49192,
            107, 49187, 49191, 103, 49162, 49172, 57, 49161, 49171, 51, 157, 156, 61, 60, 53, 47,
            255,
        ],
        extensions: vec![11, 10, 35, 22, 23, 13, 43, 45, 51, 0, 16, 17],
        elliptic_curves: vec![29, 23, 24, 25, 256],
        ec_point_formats: vec![0, 1, 2],
    }
}

fn bench_ja3(c: &mut Criterion) {
    let chrome = chrome_data();
    let curl = curl_data();

    c.bench_function("ja3_chrome", |b| {
        b.iter(|| compute_ja3(&chrome, false, 41));
    });

    c.bench_function("ja3n_chrome", |b| {
        b.iter(|| compute_ja3(&chrome, true, 41));
    });

    c.bench_function("ja3n_curl", |b| {
        b.iter(|| compute_ja3(&curl, true, 41));
    });
}

criterion_group!(benches, bench_ja3);
criterion_main!(benches);
