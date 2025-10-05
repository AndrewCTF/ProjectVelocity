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

#[derive(Debug, Deserialize, Default)]
pub struct ServeConfig {
    #[serde(default)]
    pub hosts: Vec<ServeHostConfig>,
    #[serde(default)]
    pub default_host: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ServeHostConfig {
    pub hostname: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default)]
    pub routes: Vec<HostRouteConfig>,
}

#[derive(Debug, Deserialize)]
pub struct HostRouteConfig {
    #[serde(default = "default_prefix")]
    pub path_prefix: String,
    #[serde(default = "default_methods")]
    pub methods: Vec<String>,
    #[serde(flatten)]
    pub target: HostTargetConfig,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostTargetConfig {
    Static(StaticTargetConfig),
    Proxy(ProxyTargetConfig),
    Edge { config: EdgeConfig },
}

#[derive(Debug, Deserialize)]
pub struct StaticTargetConfig {
    #[serde(default)]
    pub root: Option<String>,
    #[serde(default = "default_index")]
    pub index: String,
    #[serde(default)]
    pub listings: bool,
}

#[derive(Debug, Deserialize)]
pub struct ProxyTargetConfig {
    pub origin: String,
    #[serde(default)]
    pub preserve_host: bool,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: String,
    #[serde(default = "default_response_timeout")]
    pub response_timeout: String,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: String,
    #[serde(default = "default_tcp_keepalive")]
    pub tcp_keepalive: String,
    #[serde(default)]
    pub streaming: bool,
}

fn default_prefix() -> String {
    "/".to_string()
}

fn default_index() -> String {
    "index.html".to_string()
}

fn default_connect_timeout() -> String {
    "10s".to_string()
}

fn default_response_timeout() -> String {
    "30s".to_string()
}

fn default_idle_timeout() -> String {
    "90s".to_string()
}

fn default_tcp_keepalive() -> String {
    "60s".to_string()
}
