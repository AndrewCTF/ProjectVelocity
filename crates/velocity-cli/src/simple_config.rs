use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use velocity_edge::{
    HostRouteConfig, HostTargetConfig, ProxyTargetConfig, ServeConfig, ServeHostConfig,
    StaticTargetConfig,
};

use crate::{Profile, ServeArgs};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigOverrides {
    pub listen: Option<SocketAddr>,
    pub alpn: Option<Vec<String>>,
    pub fallback_alpn: Option<String>,
    pub fallback_host: Option<String>,
    pub fallback_port: Option<u16>,
    pub profile: Option<Profile>,
    pub publish_kem: Option<bool>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub self_signed: Option<bool>,
    pub domain: Option<String>,
    pub email: Option<String>,
    pub accept_tos: Option<bool>,
    pub root: Option<PathBuf>,
    pub index: Option<String>,
    pub listings: Option<bool>,
    pub max_sessions: Option<usize>,
    pub metrics_listen: Option<SocketAddr>,
    pub serve_https: Option<bool>,
    pub https_listen: Option<SocketAddr>,
}

impl ConfigOverrides {
    pub fn is_empty(&self) -> bool {
        self.listen.is_none()
            && self.alpn.is_none()
            && self.fallback_alpn.is_none()
            && self.fallback_host.is_none()
            && self.fallback_port.is_none()
            && self.profile.is_none()
            && self.publish_kem.is_none()
            && self.cert.is_none()
            && self.key.is_none()
            && self.self_signed.is_none()
            && self.domain.is_none()
            && self.email.is_none()
            && self.accept_tos.is_none()
            && self.root.is_none()
            && self.index.is_none()
            && self.listings.is_none()
            && self.max_sessions.is_none()
            && self.metrics_listen.is_none()
            && self.serve_https.is_none()
            && self.https_listen.is_none()
    }

    pub fn apply(&self, args: &mut ServeArgs) {
        if let Some(listen) = self.listen {
            args.listen = listen;
        }
        if let Some(alpn) = self.alpn.clone() {
            args.alpn = alpn;
        }
        if let Some(fallback_alpn) = self.fallback_alpn.clone() {
            args.fallback_alpn = fallback_alpn;
        }
        if let Some(fallback_host) = self.fallback_host.clone() {
            args.fallback_host = Some(fallback_host);
        }
        if let Some(fallback_port) = self.fallback_port {
            args.fallback_port = fallback_port;
        }
        if let Some(profile) = self.profile {
            args.profile = profile;
        }
        if let Some(publish_kem) = self.publish_kem {
            args.publish_kem = publish_kem;
        }
        if let Some(cert) = self.cert.clone() {
            args.cert = Some(cert);
        }
        if let Some(key) = self.key.clone() {
            args.key = Some(key);
        }
        if let Some(self_signed) = self.self_signed {
            args.self_signed = self_signed;
        }
        if let Some(domain) = self.domain.clone() {
            args.domain = domain;
        }
        if let Some(email) = self.email.clone() {
            args.email = Some(email);
        }
        if let Some(accept_tos) = self.accept_tos {
            args.accept_tos = accept_tos;
        }
        if let Some(root) = self.root.clone() {
            args.root = root;
        }
        if let Some(index) = self.index.clone() {
            args.index = index;
        }
        if let Some(listings) = self.listings {
            args.listings = listings;
        }
        if let Some(max_sessions) = self.max_sessions {
            args.max_sessions = Some(max_sessions);
        }
        if let Some(metrics_listen) = self.metrics_listen {
            args.metrics_listen = Some(metrics_listen);
        }
        if let Some(serve_https) = self.serve_https {
            args.serve_https = serve_https;
        }
        if let Some(https_listen) = self.https_listen {
            args.https_listen = https_listen;
        }
    }
}

#[derive(Debug)]
pub struct CombinedServeConfig {
    pub router: ServeConfig,
    pub overrides: Option<ConfigOverrides>,
}

pub async fn load_combined_config(path: &Path) -> Result<CombinedServeConfig> {
    let source = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read serve config {}", path.display()))?;
    parse_combined_config(&source, path)
}

fn parse_combined_config(source: &str, path: &Path) -> Result<CombinedServeConfig> {
    let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    let parse_simple = |input: &str| -> Result<SimpleServeFile> {
        if ext.eq_ignore_ascii_case("json") {
            serde_json::from_str(input)
                .with_context(|| format!("serve config {} is not valid JSON", path.display()))
        } else {
            serde_yaml::from_str(input)
                .with_context(|| format!("serve config {} is not valid YAML", path.display()))
        }
    };

    let simple = parse_simple(source)?;
    if simple.is_meaningful() {
        return simple.into_combined(path);
    }

    let router: ServeConfig = if ext.eq_ignore_ascii_case("json") {
        serde_json::from_str(source)
            .with_context(|| format!("serve config {} is not valid JSON", path.display()))?
    } else {
        serde_yaml::from_str(source)
            .with_context(|| format!("serve config {} is not valid YAML", path.display()))?
    };

    Ok(CombinedServeConfig {
        router,
        overrides: None,
    })
}

#[derive(Debug, Deserialize, Default)]
struct SimpleServeFile {
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    alpn: Option<Vec<String>>,
    #[serde(default)]
    fallback_alpn: Option<String>,
    #[serde(default)]
    fallback_host: Option<String>,
    #[serde(default)]
    fallback_port: Option<u16>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    publish_kem: Option<bool>,
    #[serde(default)]
    tls: Option<SimpleTls>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    accept_tos: Option<bool>,
    #[serde(default)]
    root: Option<PathBuf>,
    #[serde(default)]
    index: Option<String>,
    #[serde(default)]
    listings: Option<bool>,
    #[serde(default)]
    max_sessions: Option<usize>,
    #[serde(default)]
    metrics_listen: Option<String>,
    #[serde(default)]
    serve_https: Option<bool>,
    #[serde(default)]
    https_listen: Option<String>,
    #[serde(default)]
    default_host: Option<String>,
    #[serde(default)]
    hosts: Vec<SimpleHost>,
}

impl SimpleServeFile {
    fn is_meaningful(&self) -> bool {
        !self.hosts.is_empty()
            || self.listen.is_some()
            || self.tls.is_some()
            || self.root.is_some()
            || self.metrics_listen.is_some()
    }

    fn into_combined(self, path: &Path) -> Result<CombinedServeConfig> {
        if self.hosts.is_empty() {
            bail!(
                "serve config {} must define at least one host entry",
                path.display()
            );
        }

        let overrides = build_overrides(&self)?;
        let router = build_router(self, path)?;

        Ok(CombinedServeConfig {
            router,
            overrides: if overrides.is_empty() {
                None
            } else {
                Some(overrides)
            },
        })
    }
}

fn build_overrides(simple: &SimpleServeFile) -> Result<ConfigOverrides> {
    let mut overrides = ConfigOverrides::default();

    if let Some(listen) = simple.listen.as_deref() {
        overrides.listen = Some(parse_socket(listen, "listen")?);
    }

    if let Some(metrics) = simple.metrics_listen.as_deref() {
        overrides.metrics_listen = Some(parse_socket(metrics, "metrics_listen")?);
    }

    if let Some(https_listen) = simple.https_listen.as_deref() {
        overrides.https_listen = Some(parse_socket(https_listen, "https_listen")?);
    }

    if let Some(alpn) = &simple.alpn {
        overrides.alpn = Some(alpn.clone());
    }

    if let Some(fallback_alpn) = &simple.fallback_alpn {
        overrides.fallback_alpn = Some(fallback_alpn.clone());
    }

    if let Some(fallback_host) = &simple.fallback_host {
        overrides.fallback_host = Some(fallback_host.clone());
    }

    if let Some(fallback_port) = simple.fallback_port {
        overrides.fallback_port = Some(fallback_port);
    }

    if let Some(profile) = simple.profile.as_deref() {
        overrides.profile = Some(parse_profile(profile)?);
    }

    if let Some(publish_kem) = simple.publish_kem {
        overrides.publish_kem = Some(publish_kem);
    }

    if let Some(tls) = &simple.tls {
        match (&tls.cert, &tls.key, tls.self_signed) {
            (Some(cert), Some(key), _) => {
                overrides.cert = Some(cert.clone());
                overrides.key = Some(key.clone());
            }
            (None, None, Some(self_signed)) if self_signed => {
                overrides.self_signed = Some(true);
            }
            (None, None, _) => {}
            (Some(_), None, _) | (None, Some(_), _) => {
                bail!("TLS configuration must provide both cert and key");
            }
        }
        if let Some(domain) = tls.domain.clone() {
            overrides.domain = Some(domain);
        }
    }

    if let Some(email) = &simple.email {
        overrides.email = Some(email.clone());
    }

    if let Some(accept_tos) = simple.accept_tos {
        overrides.accept_tos = Some(accept_tos);
    }

    if let Some(root) = &simple.root {
        overrides.root = Some(root.clone());
    }

    if let Some(index) = &simple.index {
        overrides.index = Some(index.clone());
    }

    if let Some(listings) = simple.listings {
        overrides.listings = Some(listings);
    }

    if let Some(max_sessions) = simple.max_sessions {
        overrides.max_sessions = Some(max_sessions);
    }

    if let Some(serve_https) = simple.serve_https {
        overrides.serve_https = Some(serve_https);
    }

    Ok(overrides)
}

fn build_router(mut simple: SimpleServeFile, path: &Path) -> Result<ServeConfig> {
    let mut hosts = Vec::with_capacity(simple.hosts.len());
    let mut seen_hosts = HashSet::new();
    for host in simple.hosts.drain(..) {
        if !seen_hosts.insert(host.host.clone()) {
            bail!(
                "serve config {} defines the host '{}' more than once",
                path.display(),
                host.host
            );
        }
        hosts.push(host.into_host_config(path)?);
    }

    Ok(ServeConfig {
        hosts,
        default_host: simple.default_host,
    })
}

#[derive(Debug, Deserialize)]
struct SimpleTls {
    #[serde(default)]
    cert: Option<PathBuf>,
    #[serde(default)]
    key: Option<PathBuf>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    self_signed: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SimpleHost {
    host: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    proxy: Option<SimpleProxyDef>,
    #[serde(default)]
    routes: Vec<SimpleRoute>,
    #[serde(default)]
    static_dir: Option<PathBuf>,
    #[serde(default)]
    static_index: Option<String>,
    #[serde(default)]
    static_listings: Option<bool>,
    #[serde(default)]
    root: Option<String>,
}

impl SimpleHost {
    fn into_host_config(self, path: &Path) -> Result<ServeHostConfig> {
        let mut routes = Vec::new();

        if let Some(proxy) = self.proxy {
            routes.push(proxy.into_route("/", None)?);
        }

        for route in self.routes {
            routes.push(route.into_host_route(path)?);
        }

        if let Some(static_dir) = self.static_dir {
            routes.push(static_route("/", static_dir, self.static_index.clone(), self.static_listings));
        }

        if routes.is_empty() {
            bail!(
                "host '{}' has no handlers configured in serve config {}",
                self.host,
                path.display()
            );
        }

        Ok(ServeHostConfig {
            hostname: self.host,
            aliases: self.aliases,
            root: self.root,
            routes,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SimpleRoute {
    Proxy(SimpleProxyRoute),
    Static(SimpleStaticRoute),
}

impl SimpleRoute {
    fn into_host_route(self, path: &Path) -> Result<HostRouteConfig> {
        match self {
            SimpleRoute::Proxy(proxy) => proxy.into_host_route(),
            SimpleRoute::Static(route) => route.into_host_route(path),
        }
    }
}

#[derive(Debug, Deserialize)]
struct SimpleProxyRoute {
    #[serde(default = "default_prefix")]
    path: String,
    #[serde(flatten)]
    settings: SimpleProxySettings,
}

impl SimpleProxyRoute {
    fn into_host_route(self) -> Result<HostRouteConfig> {
        Ok(HostRouteConfig {
            path_prefix: self.path,
            methods: self.settings.methods.clone().unwrap_or_else(default_methods),
            target: HostTargetConfig::Proxy(self.settings.into_proxy_target()?),
        })
    }
}

#[derive(Debug, Deserialize)]
struct SimpleStaticRoute {
    #[serde(default = "default_prefix")]
    path: String,
    #[serde(default)]
    dir: Option<PathBuf>,
    #[serde(default)]
    index: Option<String>,
    #[serde(default)]
    listings: Option<bool>,
}

impl SimpleStaticRoute {
    fn into_host_route(self, path: &Path) -> Result<HostRouteConfig> {
        let dir = self.dir.unwrap_or_else(|| PathBuf::from("."));
        if dir.as_os_str().is_empty() {
            bail!(
                "static route in {} for path '{}' must specify a non-empty dir",
                path.display(),
                self.path
            );
        }
        Ok(static_route(
            &self.path,
            dir,
            self.index.clone(),
            self.listings,
        ))
    }
}

fn static_route(
    prefix: &str,
    dir: PathBuf,
    index: Option<String>,
    listings: Option<bool>,
) -> HostRouteConfig {
    HostRouteConfig {
        path_prefix: prefix.to_string(),
        methods: default_methods(),
        target: HostTargetConfig::Static(StaticTargetConfig {
            root: Some(dir.to_string_lossy().to_string()),
            index: index.unwrap_or_else(default_index),
            listings: listings.unwrap_or(false),
        }),
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SimpleProxyDef {
    Url(String),
    Settings(SimpleProxySettings),
}

impl SimpleProxyDef {
    fn into_route(self, path: &str, methods: Option<Vec<String>>) -> Result<HostRouteConfig> {
        let methods_override = methods.clone();
        let mut settings = match self {
            SimpleProxyDef::Url(url) => SimpleProxySettings {
                upstream: url,
                preserve_host: false,
                methods,
                connect_timeout: None,
                response_timeout: None,
                idle_timeout: None,
                tcp_keepalive: None,
                streaming: None,
            },
            SimpleProxyDef::Settings(settings) => settings,
        };
        if let Some(methods) = methods_override {
            if settings.methods.is_none() {
                settings.methods = Some(methods);
            }
        }
        Ok(HostRouteConfig {
            path_prefix: path.to_string(),
            methods: settings.methods.clone().unwrap_or_else(default_methods),
            target: HostTargetConfig::Proxy(settings.into_proxy_target()?),
        })
    }
}

#[derive(Debug, Deserialize, Clone)]
struct SimpleProxySettings {
    #[serde(alias = "to", alias = "upstream", alias = "origin")]
    upstream: String,
    #[serde(default)]
    preserve_host: bool,
    #[serde(default)]
    methods: Option<Vec<String>>,
    #[serde(default)]
    connect_timeout: Option<String>,
    #[serde(default)]
    response_timeout: Option<String>,
    #[serde(default)]
    idle_timeout: Option<String>,
    #[serde(default)]
    tcp_keepalive: Option<String>,
    #[serde(default)]
    streaming: Option<bool>,
}

impl SimpleProxySettings {
    fn into_proxy_target(self) -> Result<ProxyTargetConfig> {
        if self.upstream.is_empty() {
            bail!("proxy upstream must not be empty");
        }
        Ok(ProxyTargetConfig {
            origin: self.upstream,
            preserve_host: self.preserve_host,
            connect_timeout: self.connect_timeout.unwrap_or_else(default_connect_timeout),
            response_timeout: self.response_timeout.unwrap_or_else(default_response_timeout),
            idle_timeout: self.idle_timeout.unwrap_or_else(default_idle_timeout),
            tcp_keepalive: self.tcp_keepalive.unwrap_or_else(default_tcp_keepalive),
            streaming: self.streaming.unwrap_or(false),
        })
    }
}

fn parse_socket(value: &str, field: &str) -> Result<SocketAddr> {
    value
        .parse::<SocketAddr>()
        .with_context(|| format!("failed to parse {field} socket address"))
}

fn parse_profile(value: &str) -> Result<Profile> {
    match value.to_ascii_lowercase().as_str() {
        "turbo" => Ok(Profile::Turbo),
        "balanced" => Ok(Profile::Balanced),
        "fortress" => Ok(Profile::Fortress),
        other => bail!("unknown security profile '{other}'"),
    }
}

fn default_prefix() -> String {
    "/".to_string()
}

fn default_methods() -> Vec<String> {
    vec!["GET".to_string()]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parses_simple_proxy_config() {
        let config = r#"
listen: 0.0.0.0:443
publish_kem: true
hosts:
  - host: projectvelocity.org
    proxy: http://127.0.0.1:3000/
    aliases: [www.projectvelocity.org]
  - host: docs.projectvelocity.org
    proxy:
      to: http://127.0.0.1:3000/docs
      preserve_host: true
  - host: get.projectvelocity.org
    routes:
      - path: /
        proxy:
          to: http://127.0.0.1:3000/get
          preserve_host: true
"#;

        let combined = parse_combined_config(config, Path::new("serve.yaml")).unwrap();
        assert!(combined.overrides.is_some());
        let overrides = combined.overrides.unwrap();
        assert_eq!(overrides.listen.unwrap(), "0.0.0.0:443".parse().unwrap());
        assert_eq!(overrides.publish_kem, Some(true));

        assert_eq!(combined.router.hosts.len(), 3);
        let first = &combined.router.hosts[0];
        assert_eq!(first.hostname, "projectvelocity.org");
        assert_eq!(first.aliases, vec!["www.projectvelocity.org".to_string()]);
        assert_eq!(first.routes.len(), 1);
        match &first.routes[0].target {
            HostTargetConfig::Proxy(proxy) => {
                assert_eq!(proxy.origin, "http://127.0.0.1:3000/");
                assert!(!proxy.preserve_host);
            }
            _ => panic!("expected proxy target"),
        }
    }
}
