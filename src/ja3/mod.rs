mod fingerprint;

use crate::common::types::ClientHelloData;
use crate::technique::FingerprintTechnique;

pub use fingerprint::compute_ja3;

/// JA3 fingerprinting technique (extensions in original order, exclude ext 41).
#[derive(Debug)]
pub struct Ja3Technique;

impl FingerprintTechnique for Ja3Technique {
    fn name(&self) -> &str {
        "ja3"
    }

    fn compute(&self, data: &ClientHelloData) -> Vec<(String, String)> {
        let (hash, raw) = compute_ja3(data, false, 41);
        vec![("ja3_hash".to_string(), hash), ("ja3_raw".to_string(), raw)]
    }
}

/// JA3N fingerprinting technique (extensions sorted numerically, exclude ext 41).
#[derive(Debug)]
pub struct Ja3nTechnique;

impl FingerprintTechnique for Ja3nTechnique {
    fn name(&self) -> &str {
        "ja3n"
    }

    fn compute(&self, data: &ClientHelloData) -> Vec<(String, String)> {
        let (hash, raw) = compute_ja3(data, true, 41);
        vec![
            ("ja3n_hash".to_string(), hash),
            ("ja3n_raw".to_string(), raw),
        ]
    }
}
