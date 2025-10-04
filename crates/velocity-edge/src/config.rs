use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct EdgeConfig {
    #[serde(default)]
    pub templates_dir: Option<String>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub waf: Option<WafConfig>,
}

#[derive(Debug, Deserialize)]
pub struct RouteConfig {
    pub path: String,
    #[serde(default = "default_methods")]
    pub methods: Vec<String>,
    #[serde(flatten)]
    pub handler: HandlerConfig,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HandlerConfig {
    Json {
        #[serde(default)]
        status: Option<u16>,
        body: serde_json::Value,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    Text {
        #[serde(default)]
        status: Option<u16>,
        body: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    Template {
        name: String,
        #[serde(default)]
        context: serde_json::Value,
        #[serde(default)]
        status: Option<u16>,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    StaticFile {
        path: String,
        #[serde(default)]
        status: Option<u16>,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
}

#[derive(Debug, Deserialize)]
pub struct RateLimitConfig {
    pub limit: usize,
    pub window: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct WafConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<String>,
}

fn default_methods() -> Vec<String> {
    vec!["GET".to_string()]
}

fn default_true() -> bool {
    true
}
