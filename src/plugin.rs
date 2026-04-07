use std::sync::OnceLock;

use abi_stable::std_types::{RVec, Tuple2};
use haproxy_spoa_hub_plugin_api::{
    ProcessingResult, SpoeMessage, SpoeValue, TxnVariable, VarScope, define_plugin,
};

use crate::common::parse::parse_u16_be;
use crate::common::types::ClientHelloData;
use crate::config::PluginConfig;
use crate::ja3::compute_ja3;

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
        let config = CONFIG.get().unwrap_or(&PluginConfig::DEFAULT);
        let data = extract_client_hello(message);

        let (hash, raw) = compute_ja3(&data, config.sort_extensions, config.exclude_extension);

        let mut variables = RVec::with_capacity(2);
        variables.push(TxnVariable {
            scope: VarScope::Session,
            name: RString::from("hash"),
            value: SpoeValue::String(RString::from(hash)),
        });
        variables.push(TxnVariable {
            scope: VarScope::Session,
            name: RString::from("raw"),
            value: SpoeValue::String(RString::from(raw)),
        });

        Ok(ProcessingResult { variables })
    }

    fn config_schema(&self) -> Option<&str> {
        Some(PluginConfig::config_schema())
    }
});

fn extract_client_hello(message: &SpoeMessage) -> ClientHelloData {
    let mut proto = 0u16;
    let mut ciphers: &[u8] = &[];
    let mut extensions: &[u8] = &[];
    let mut curves: &[u8] = &[];
    let mut formats: &[u8] = &[];

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
            _ => {}
        }
    }

    ClientHelloData {
        protocol_version: proto,
        cipher_suites: parse_u16_be(ciphers),
        extensions: parse_u16_be(extensions),
        elliptic_curves: parse_u16_be(curves),
        ec_point_formats: formats.to_vec(),
    }
}
