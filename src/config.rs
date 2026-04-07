use haproxy_spoa_hub_plugin_api::PluginContext;

/// Plugin configuration parsed from hub's `[plugins.params]` TOML table.
#[derive(Debug)]
pub struct PluginConfig {
    pub sort_extensions: bool,
    pub exclude_extensions: Vec<u16>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        PluginConfig {
            sort_extensions: true,
            exclude_extensions: vec![41],
        }
    }
}

impl PluginConfig {
    pub fn from_context(context: &PluginContext) -> Self {
        let sort_extensions = context
            .config
            .get("sort_extensions")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let exclude_extensions = context
            .config
            .get("exclude_extensions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_integer().map(|n| n as u16))
                    .collect()
            })
            .unwrap_or_else(|| vec![41]);

        PluginConfig {
            sort_extensions,
            exclude_extensions,
        }
    }

    pub fn config_schema() -> &'static str {
        r#"{
            "type": "object",
            "properties": {
                "sort_extensions": { "type": "boolean", "default": true },
                "exclude_extensions": {
                    "type": "array",
                    "items": { "type": "integer", "minimum": 0, "maximum": 65535 },
                    "default": [41]
                }
            },
            "additionalProperties": false
        }"#
    }
}
