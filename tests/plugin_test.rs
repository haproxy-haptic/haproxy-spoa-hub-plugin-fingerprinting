use haproxy_spoa_hub_plugin_api::{ConfigValue, PluginContext, RHashMap, RString, RVec};

use fingerprinting_plugin::config::PluginConfig;

// --- Config parsing tests ---

#[test]
fn default_config() {
    let context = make_context(&[]);
    let config = PluginConfig::from_context(&context);
    assert!(config.sort_extensions);
    assert_eq!(config.exclude_extensions, vec![41]);
}

#[test]
fn sort_extensions_false() {
    let context = make_context(&[("sort_extensions", ConfigValue::Bool(false))]);
    let config = PluginConfig::from_context(&context);
    assert!(!config.sort_extensions);
    assert_eq!(config.exclude_extensions, vec![41]);
}

#[test]
fn custom_exclude_extensions() {
    let context = make_context(&[(
        "exclude_extensions",
        ConfigValue::Array(RVec::from(vec![
            ConfigValue::Integer(41),
            ConfigValue::Integer(43),
        ])),
    )]);
    let config = PluginConfig::from_context(&context);
    assert_eq!(config.exclude_extensions, vec![41, 43]);
}

#[test]
fn no_exclusions() {
    let context = make_context(&[("exclude_extensions", ConfigValue::Array(RVec::from(vec![])))]);
    let config = PluginConfig::from_context(&context);
    assert!(config.exclude_extensions.is_empty());
}

#[test]
fn config_schema_is_valid_json() {
    let schema = PluginConfig::config_schema();
    let parsed: serde_json::Value =
        serde_json::from_str(schema).expect("Schema must be valid JSON");
    assert_eq!(parsed["type"], "object");
    assert!(parsed["properties"]["sort_extensions"]["type"] == "boolean");
    assert!(parsed["properties"]["exclude_extensions"]["type"] == "array");
    assert!(parsed["properties"]["ja4"]["type"] == "boolean");
    assert_eq!(parsed["additionalProperties"], false);
}

#[test]
fn ja4_enabled_by_default() {
    let context = make_context(&[]);
    let config = PluginConfig::from_context(&context);
    assert!(config.ja4);
}

#[test]
fn ja4_disabled() {
    let context = make_context(&[("ja4", ConfigValue::Bool(false))]);
    let config = PluginConfig::from_context(&context);
    assert!(!config.ja4);
}

// --- Compute tests ---

use fingerprinting_plugin::common::types::ClientHelloData;
use fingerprinting_plugin::ja3::compute_ja3;

#[test]
fn chrome_data_produces_correct_fingerprint() {
    let data = ClientHelloData {
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
    };

    let (ja3_hash, _) = compute_ja3(&data, false, &[41]);
    let (ja3n_hash, _) = compute_ja3(&data, true, &[41]);

    // JA3 and JA3N hashes differ (different extension order)
    assert_ne!(ja3_hash, ja3n_hash);
    assert_eq!(ja3_hash.len(), 32);
    assert_eq!(ja3n_hash.len(), 32);
}

#[test]
fn missing_arguments_produce_empty_field_fingerprints() {
    let data = ClientHelloData {
        protocol_version: 0,
        cipher_suites: vec![],
        extensions: vec![],
        elliptic_curves: vec![],
        ec_point_formats: vec![],
        supported_versions: vec![],
        signature_algorithms: vec![],
        alpn: None,
        sni_present: false,
    };

    let (hash, raw) = compute_ja3(&data, true, &[41]);
    assert_eq!(raw, "0,,,,");
    assert_eq!(hash.len(), 32);
}

// --- Helpers ---

fn make_context(params: &[(&str, ConfigValue)]) -> PluginContext {
    let mut config = RHashMap::new();
    for (key, value) in params {
        config.insert(RString::from(*key), value.clone());
    }
    PluginContext {
        name: RString::from("fingerprinting"),
        config,
    }
}
