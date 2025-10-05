use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use http::Method;
use tokio::sync::watch;

use crate::app::EdgeApp;
use crate::config::{
    HostRouteConfig, HostTargetConfig, ServeConfig, ServeHostConfig, StaticTargetConfig,
};
use crate::error::{EdgeError, EdgeResult};
use crate::request::EdgeRequest;
use crate::response::EdgeResponse;
use crate::utils::{normalize_prefix_path, parse_methods};

use crate::proxy::ProxyHandler;
use crate::static_site::StaticSiteHandler;

#[async_trait]
pub trait ServeHandler: Send + Sync {
    async fn handle(&self, request: EdgeRequest) -> EdgeResult<EdgeResponse>;
}

pub struct ServeRouter {
    hosts: Vec<HostEntry>,
    lookup: HashMap<String, usize>,
    default: Option<usize>,
}

impl ServeRouter {
    pub fn from_config(config: ServeConfig, base_root: &Path) -> EdgeResult<Self> {
        let mut hosts = Vec::new();
        let mut lookup = HashMap::new();

        for host_cfg in config.hosts {
            let entry = HostEntry::build(host_cfg, base_root)?;
            let index = hosts.len();
            for name in &entry.names {
                if lookup.insert(name.clone(), index).is_some() {
                    return Err(EdgeError::Config(format!(
                        "duplicate host entry for '{name}' in serve configuration"
                    )));
                }
            }
            hosts.push(entry);
        }

        let default = if let Some(name) = config.default_host {
            let key = normalize_host(&name);
            lookup.get(&key).copied()
        } else {
            None
        };

        Ok(Self {
            hosts,
            lookup,
            default,
        })
    }

    pub fn resolve(&self, host: Option<&str>, method: &Method, path: &str) -> Option<RouteMatch> {
        let host_key = host.map(normalize_host);
        let index = host_key
            .as_ref()
            .and_then(|name| self.lookup.get(name).copied())
            .or(self.default);
        let host_entry = index.and_then(|idx| self.hosts.get(idx))?;
        host_entry.resolve(method, path)
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

pub struct RouteMatch {
    pub handler: Arc<dyn ServeHandler>,
    pub prefix: String,
}

#[derive(Clone)]
pub struct ServeRouterHandle {
    receiver: watch::Receiver<Arc<ServeRouter>>,
}

impl ServeRouterHandle {
    pub fn current(&self) -> Arc<ServeRouter> {
        self.receiver.borrow().clone()
    }
}

#[derive(Clone)]
pub struct ServeRouterController {
    sender: watch::Sender<Arc<ServeRouter>>,
}

impl ServeRouterController {
    pub fn new(initial: Arc<ServeRouter>) -> (Self, ServeRouterHandle) {
        let (sender, receiver) = watch::channel(initial);
        (Self { sender }, ServeRouterHandle { receiver })
    }

    pub fn update(&self, router: Arc<ServeRouter>) -> EdgeResult<()> {
        self.sender
            .send(router)
            .map_err(|_| EdgeError::Internal("router subscribers dropped".into()))
    }
}

struct HostEntry {
    names: Vec<String>,
    routes: Vec<RouteEntry>,
}

impl HostEntry {
    fn build(config: ServeHostConfig, base_root: &Path) -> EdgeResult<Self> {
        let mut names = Vec::new();
        names.push(normalize_host(&config.hostname));
        for alias in config.aliases {
            names.push(normalize_host(&alias));
        }

        let host_root = if let Some(rel) = config.root {
            sanitize_root(base_root.join(rel))?
        } else {
            sanitize_root(base_root.to_path_buf())?
        };

        let mut routes = Vec::new();
        for route in config.routes {
            routes.push(RouteEntry::build(route, &host_root)?);
        }

        if routes.is_empty() {
            routes.push(RouteEntry::static_fallback(&host_root)?);
        }

        Ok(Self { names, routes })
    }

    fn resolve(&self, method: &Method, path: &str) -> Option<RouteMatch> {
        let mut best: Option<(&RouteEntry, usize)> = None;
        for route in &self.routes {
            if route.matches(method, path) {
                let len = route.prefix_len;
                if best.as_ref().map_or(true, |(_, best_len)| len > *best_len) {
                    best = Some((route, len));
                }
            }
        }
        best.map(|(route, _)| RouteMatch {
            handler: Arc::clone(&route.handler),
            prefix: route.prefix.clone(),
        })
    }
}

struct RouteEntry {
    prefix: String,
    prefix_slash: String,
    prefix_len: usize,
    methods: Vec<Method>,
    handler: Arc<dyn ServeHandler>,
}

impl RouteEntry {
    fn build(config: HostRouteConfig, host_root: &Path) -> EdgeResult<Self> {
        let prefix = normalize_prefix_path(&config.path_prefix);
        let prefix_slash = if prefix == "/" {
            String::from("/")
        } else {
            format!("{}/", prefix.trim_end_matches('/'))
        };
        let prefix_len = prefix.len();
        let methods = parse_methods(&config.methods)?;
        let handler = match config.target {
            HostTargetConfig::Static(static_cfg) => {
                let root = static_root(host_root, &static_cfg)?;
                Arc::new(StaticSiteHandler::new(
                    root,
                    static_cfg.index.clone(),
                    static_cfg.listings,
                )?) as Arc<dyn ServeHandler>
            }
            HostTargetConfig::Proxy(proxy_cfg) => {
                Arc::new(ProxyHandler::new(&proxy_cfg)?) as Arc<dyn ServeHandler>
            }
            HostTargetConfig::Edge { config } => {
                let app = EdgeApp::from_config(config, host_root)?;
                Arc::new(EdgeAppHandler { app: Arc::new(app) }) as Arc<dyn ServeHandler>
            }
        };
        Ok(Self {
            prefix,
            prefix_slash,
            prefix_len,
            methods,
            handler,
        })
    }

    fn static_fallback(host_root: &Path) -> EdgeResult<Self> {
        let handler =
            StaticSiteHandler::new(host_root.to_path_buf(), "index.html".to_string(), false)?;
        Ok(Self {
            prefix: "/".to_string(),
            prefix_slash: "/".to_string(),
            prefix_len: 1,
            methods: Vec::new(),
            handler: Arc::new(handler),
        })
    }

    fn matches(&self, method: &Method, path: &str) -> bool {
        if !self.methods.is_empty() && !self.methods.iter().any(|m| m == method) {
            return false;
        }
        if self.prefix == "/" {
            return true;
        }
        if path == self.prefix {
            return true;
        }
        path.starts_with(&self.prefix_slash)
    }
}

struct EdgeAppHandler {
    app: Arc<EdgeApp>,
}

#[async_trait]
impl ServeHandler for EdgeAppHandler {
    async fn handle(&self, request: EdgeRequest) -> EdgeResult<EdgeResponse> {
        self.app.dispatch(request).await
    }
}

fn static_root(host_root: &Path, config: &StaticTargetConfig) -> EdgeResult<PathBuf> {
    let mut root = host_root.to_path_buf();
    if let Some(rel) = &config.root {
        root.push(rel);
    }
    sanitize_root(root)
}

fn sanitize_root(path: PathBuf) -> EdgeResult<PathBuf> {
    std::fs::canonicalize(&path).map_err(|err| {
        EdgeError::Config(format!(
            "failed to resolve directory {}: {err}",
            path.display()
        ))
    })
}

fn normalize_host(host: &str) -> String {
    let mut value = host.trim().to_ascii_lowercase();
    if let Some(idx) = value.find(':') {
        value.truncate(idx);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use tempfile::tempdir;

    #[test]
    fn router_matches_host_and_prefix() {
        let temp = tempdir().expect("tempdir");
        let base = temp.path();
        std::fs::write(base.join("index.html"), b"hello").expect("write index");

        let host_config = ServeHostConfig {
            hostname: "example.com".into(),
            aliases: vec!["www.example.com".into()],
            root: None,
            routes: vec![
                HostRouteConfig {
                    path_prefix: "/api".into(),
                    methods: vec!["GET".into()],
                    target: HostTargetConfig::Static(StaticTargetConfig {
                        root: None,
                        index: "index.html".into(),
                        listings: false,
                    }),
                },
                HostRouteConfig {
                    path_prefix: "/".into(),
                    methods: vec!["GET".into()],
                    target: HostTargetConfig::Static(StaticTargetConfig {
                        root: None,
                        index: "index.html".into(),
                        listings: false,
                    }),
                },
            ],
        };

        let config = ServeConfig {
            hosts: vec![host_config],
            default_host: None,
        };

        let router = ServeRouter::from_config(config, base).expect("router builds");

        let root = router
            .resolve(Some("example.com"), &Method::GET, "/")
            .expect("root match");
        assert_eq!(root.prefix, "/");

        let api = router
            .resolve(Some("www.example.com"), &Method::GET, "/api/users")
            .expect("api match");
        assert_eq!(api.prefix, "/api");

        assert!(router
            .resolve(Some("example.com"), &Method::POST, "/")
            .is_none());
        assert!(router
            .resolve(Some("unknown.com"), &Method::GET, "/")
            .is_none());
    }
}
