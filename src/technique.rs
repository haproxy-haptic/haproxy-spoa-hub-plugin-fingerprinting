use crate::common::types::ClientHelloData;

/// Trait for fingerprinting techniques.
///
/// Each technique receives parsed ClientHello data and produces
/// a set of named output variables (variable_name, variable_value).
///
/// To add a new fingerprinting technique:
/// 1. Create a new module (e.g., `src/ja4/`) implementing this trait
/// 2. Register the technique in `plugin::FingerprintingPlugin::init()`
///
/// The trait is intentionally generic — it uses `ClientHelloData` which
/// contains only parsed TLS fields, not JA3-specific types.
pub trait FingerprintTechnique: Send + Sync {
    /// Technique identifier used as variable name prefix.
    fn name(&self) -> &str;

    /// Compute fingerprint variables from parsed ClientHello data.
    ///
    /// Returns pairs of `(variable_name, variable_value)` where:
    /// - `variable_name` is technique-prefixed (e.g., `ja3n_hash`, `ja3_raw`)
    /// - `variable_value` is the computed fingerprint string (hash or raw)
    fn compute(&self, data: &ClientHelloData) -> Vec<(String, String)>;
}
