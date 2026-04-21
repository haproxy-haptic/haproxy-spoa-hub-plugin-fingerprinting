use std::sync::OnceLock;

use haproxy_spoa_hub_plugin_api::{
    ProcessingResult, SpoeMessage, SpoeValue, TxnVariable, define_plugin,
};

use crate::common::parse::parse_u16_be;
use crate::common::types::ClientHelloData;
use crate::config::PluginConfig;
use crate::ja3::compute_ja3;
use crate::ja4::compute_ja4;

static CONFIG: OnceLock<PluginConfig> = OnceLock::new();

#[derive(Debug)]
struct FingerprintingPlugin;

define_plugin!(FingerprintingPlugin, {
    fn new() -> Self {
        FingerprintingPlugin
    }

    fn init(
        &mut self,
        context: &PluginContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = PluginConfig::from_context(context);
        CONFIG.set(config).ok();
        Ok(())
    }

    fn name(&self) -> &str {
        "fingerprinting"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn process(
        &self,
        message: &SpoeMessage,
    ) -> Result<ProcessingResult, Box<dyn std::error::Error + Send + Sync>> {
        let default_config = PluginConfig::default();
        let config = CONFIG.get().unwrap_or(&default_config);
        let data = extract_client_hello(message);

        let mut vars = Vec::with_capacity(4);

        // JA3/JA3N
        let (hash, raw) = compute_ja3(&data, config.sort_extensions, &config.exclude_extensions);
        vars.push(TxnVariable::session("hash", SpoeValue::String(hash.into())));
        vars.push(TxnVariable::session("raw", SpoeValue::String(raw.into())));

        // JA4
        if config.ja4 {
            let (ja4, ja4_r) = compute_ja4(&data);
            vars.push(TxnVariable::session("ja4", SpoeValue::String(ja4.into())));
            vars.push(TxnVariable::session(
                "ja4_r",
                SpoeValue::String(ja4_r.into()),
            ));
        }

        Ok(ProcessingResult::from_vars(vars))
    }

    fn config_schema(&self) -> Option<&str> {
        Some(PluginConfig::config_schema())
    }
});

fn extract_client_hello(message: &SpoeMessage) -> ClientHelloData {
    let proto = message.get_int("proto").unwrap_or(0) as u16;
    let ciphers = message.get_binary("ciphers").unwrap_or(&[]);
    let extensions = message.get_binary("extensions").unwrap_or(&[]);
    let curves = message.get_binary("curves").unwrap_or(&[]);
    let formats = message.get_binary("formats").unwrap_or(&[]);
    let supported_versions = message.get_binary("supported_versions").unwrap_or(&[]);
    let sigalgs = message.get_binary("sigalgs").unwrap_or(&[]);

    let alpn = message
        .get_string("alpn")
        .filter(|s| !s.is_empty())
        .map(String::from);

    let sni_present = match message.get("sni") {
        Some(SpoeValue::Bool(b)) => *b,
        Some(SpoeValue::Int32(n)) => *n != 0,
        Some(SpoeValue::Uint32(n)) => *n != 0,
        _ => false,
    };

    ClientHelloData {
        protocol_version: proto,
        cipher_suites: parse_u16_be(ciphers),
        extensions: parse_u16_be(extensions),
        elliptic_curves: parse_u16_be(curves),
        ec_point_formats: formats.to_vec(),
        supported_versions: parse_u16_be(supported_versions),
        signature_algorithms: parse_u16_be(sigalgs),
        alpn,
        sni_present,
    }
}
