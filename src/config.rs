use haproxy_spoa_hub_plugin_api::PluginContext;

/// Plugin configuration parsed from hub's `[plugins.params]` TOML table.
#[derive(Debug)]
pub struct PluginConfig {
    pub sort_extensions: bool,
    pub exclude_extension: i32,
}

impl PluginConfig {
    pub const DEFAULT: PluginConfig = PluginConfig {
        sort_extensions: true,
        exclude_extension: 41,
    };

    pub fn from_context(context: &PluginContext) -> Self {
        let sort_extensions = context
            .config
            .get("sort_extensions")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let exclude_extension = context
            .config
            .get("exclude_extension")
            .and_then(|v| v.as_integer())
            .map(|v| v as i32)
            .unwrap_or(41);
        PluginConfig {
            sort_extensions,
            exclude_extension,
        }
    }

    pub fn config_schema() -> &'static str {
        r#"{
            "type": "object",
            "properties": {
                "sort_extensions":    { "type": "boolean", "default": true },
                "exclude_extension":  { "type": "integer", "default": 41 }
            },
            "additionalProperties": false
        }"#
    }
}
