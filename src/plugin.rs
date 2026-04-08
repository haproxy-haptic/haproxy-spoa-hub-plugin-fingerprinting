use std::sync::OnceLock;

use abi_stable::std_types::{RString, RVec, Tuple2};
use haproxy_spoa_hub_plugin_api::{
    ProcessingResult, SpoeMessage, SpoeValue, TxnVariable, VarScope, define_plugin,
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

        let mut variables = RVec::with_capacity(4);

        // JA3/JA3N
        let (hash, raw) = compute_ja3(&data, config.sort_extensions, &config.exclude_extensions);
        variables.push(make_var("hash", hash));
        variables.push(make_var("raw", raw));

        // JA4
        if config.ja4 {
            let (ja4, ja4_r) = compute_ja4(&data);
            variables.push(make_var("ja4", ja4));
            variables.push(make_var("ja4_r", ja4_r));
        }

        Ok(ProcessingResult { variables })
    }

    fn config_schema(&self) -> Option<&str> {
        Some(PluginConfig::config_schema())
    }
});

fn make_var(name: &str, value: String) -> TxnVariable {
    TxnVariable {
        scope: VarScope::Session,
        name: RString::from(name),
        value: SpoeValue::String(RString::from(value)),
    }
}

fn extract_client_hello(message: &SpoeMessage) -> ClientHelloData {
    let mut proto = 0u16;
    let mut ciphers: &[u8] = &[];
    let mut extensions: &[u8] = &[];
    let mut curves: &[u8] = &[];
    let mut formats: &[u8] = &[];
    let mut supported_versions: &[u8] = &[];
    let mut sigalgs: &[u8] = &[];
    let mut alpn: Option<String> = None;
    let mut sni_present = false;

    for Tuple2(k, v) in message.args.iter() {
        match k.as_str() {
            "proto" => {
                proto = match v {
                    SpoeValue::Int32(n) => *n as u16,
                    SpoeValue::Uint32(n) => *n as u16,
                    SpoeValue::Int64(n) => *n as u16,
                    SpoeValue::Uint64(n) => *n as u16,
                    _ => 0,
                }
            }
            "ciphers" => {
                if let SpoeValue::Binary(b) = v {
                    ciphers = b.as_slice();
                }
            }
            "extensions" => {
                if let SpoeValue::Binary(b) = v {
                    extensions = b.as_slice();
                }
            }
            "curves" => {
                if let SpoeValue::Binary(b) = v {
                    curves = b.as_slice();
                }
            }
            "formats" => {
                if let SpoeValue::Binary(b) = v {
                    formats = b.as_slice();
                }
            }
            "supported_versions" => {
                if let SpoeValue::Binary(b) = v {
                    supported_versions = b.as_slice();
                }
            }
            "sigalgs" => {
                if let SpoeValue::Binary(b) = v {
                    sigalgs = b.as_slice();
                }
            }
            "alpn" => {
                if let SpoeValue::String(s) = v {
                    let val = s.as_str().to_string();
                    if !val.is_empty() {
                        alpn = Some(val);
                    }
                }
            }
            "sni" => {
                sni_present = match v {
                    SpoeValue::Bool(b) => *b,
                    SpoeValue::Int32(n) => *n != 0,
                    SpoeValue::Uint32(n) => *n != 0,
                    _ => false,
                };
            }
            _ => {}
        }
    }

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
