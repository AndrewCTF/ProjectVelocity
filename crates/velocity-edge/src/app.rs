use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http::{header::CONTENT_TYPE, HeaderName, HeaderValue, Method, StatusCode};
use mime_guess::mime;
use regex::Regex;
use reqwest::Client;
use tera::{Context as TeraContext, Tera};
use tokio::fs;

use crate::config::{EdgeConfig, HandlerConfig, RateLimitConfig, RouteConfig, WafConfig};
use crate::error::{EdgeError, EdgeResult};
use crate::middleware::{EdgeMiddleware, SecurityHeadersMiddleware};
use crate::rate_limit::RateLimitMiddleware;
use crate::request::EdgeRequest;
use crate::response::EdgeResponse;
use crate::router::{EdgeRouter, PathPattern, RouteMatch};
use crate::utils::{normalize_prefix_path, parse_methods};
use crate::waf::WafMiddleware;

pub type DynHandler = Arc<dyn EdgeHandler>;

#[async_trait]
pub trait EdgeHandler: Send + Sync {
    async fn call(&self, ctx: EdgeContext, request: EdgeRequest) -> EdgeResult<EdgeResponse>;
}

#[async_trait]
impl<F, Fut> EdgeHandler for F
where
    F: Send + Sync + 'static + Fn(EdgeContext, EdgeRequest) -> Fut,
    Fut: Future<Output = EdgeResult<EdgeResponse>> + Send,
{
    async fn call(&self, ctx: EdgeContext, request: EdgeRequest) -> EdgeResult<EdgeResponse> {
        (self)(ctx, request).await
    }
}

#[derive(Clone)]
pub struct EdgeContext {
    inner: Arc<AppState>,
}

struct AppState {
    http_client: Client,
    templates: Option<Arc<Tera>>,
    static_dir: Option<PathBuf>,
}

impl EdgeContext {
    fn new(state: AppState) -> Self {
        Self {
            inner: Arc::new(state),
        }
    }

    pub fn http_client(&self) -> &Client {
        &self.inner.http_client
    }

    pub fn template_engine(&self) -> Option<Arc<Tera>> {
        self.inner.templates.clone()
    }

    pub fn static_dir(&self) -> Option<&Path> {
        self.inner.static_dir.as_deref()
    }
}

struct RouteDefinition {
    methods: Vec<Method>,
    path: String,
    handler: DynHandler,
}

pub struct EdgeAppBuilder {
    routes: Vec<RouteDefinition>,
    middlewares: Vec<Arc<dyn EdgeMiddleware>>,
    templates_dir: Option<PathBuf>,
    static_dir: Option<PathBuf>,
}

impl EdgeAppBuilder {
    pub fn new() -> Self {
        let mut middlewares: Vec<Arc<dyn EdgeMiddleware>> = Vec::new();
        middlewares.push(Arc::new(SecurityHeadersMiddleware::new()));
        Self {
            routes: Vec::new(),
            middlewares,
            templates_dir: None,
            static_dir: None,
        }
    }

    pub fn static_dir<P: Into<PathBuf>>(&mut self, path: P) -> &mut Self {
        self.static_dir = Some(path.into());
        self
    }

    pub fn templates_dir<P: Into<PathBuf>>(&mut self, path: P) -> &mut Self {
        self.templates_dir = Some(path.into());
        self
    }

    pub fn add_middleware<M>(&mut self, middleware: M) -> &mut Self
    where
        M: EdgeMiddleware + 'static,
    {
        self.middlewares.push(Arc::new(middleware));
        self
    }

    pub fn with_rate_limit(&mut self, limit: usize, window: Duration) -> &mut Self {
        self.middlewares
            .push(Arc::new(RateLimitMiddleware::new(limit, window)));
        self
    }

    pub fn with_waf(&mut self, patterns: Vec<Regex>) -> &mut Self {
        self.middlewares
            .push(Arc::new(WafMiddleware::new(patterns)));
        self
    }

    pub fn route<H, Fut>(&mut self, methods: Vec<Method>, path: &str, handler: H) -> &mut Self
    where
        H: Send + Sync + 'static + Fn(EdgeContext, EdgeRequest) -> Fut,
        Fut: Future<Output = EdgeResult<EdgeResponse>> + Send,
    {
        let normalized = normalize_prefix_path(path);
        self.routes.push(RouteDefinition {
            methods,
            path: normalized,
            handler: Arc::new(handler),
        });
        self
    }

    pub fn get<H, Fut>(&mut self, path: &str, handler: H) -> &mut Self
    where
        H: Send + Sync + 'static + Fn(EdgeContext, EdgeRequest) -> Fut,
        Fut: Future<Output = EdgeResult<EdgeResponse>> + Send,
    {
        self.route(vec![Method::GET], path, handler)
    }

    pub fn post<H, Fut>(&mut self, path: &str, handler: H) -> &mut Self
    where
        H: Send + Sync + 'static + Fn(EdgeContext, EdgeRequest) -> Fut,
        Fut: Future<Output = EdgeResult<EdgeResponse>> + Send,
    {
        self.route(vec![Method::POST], path, handler)
    }

    pub fn put<H, Fut>(&mut self, path: &str, handler: H) -> &mut Self
    where
        H: Send + Sync + 'static + Fn(EdgeContext, EdgeRequest) -> Fut,
        Fut: Future<Output = EdgeResult<EdgeResponse>> + Send,
    {
        self.route(vec![Method::PUT], path, handler)
    }

    pub fn delete<H, Fut>(&mut self, path: &str, handler: H) -> &mut Self
    where
        H: Send + Sync + 'static + Fn(EdgeContext, EdgeRequest) -> Fut,
        Fut: Future<Output = EdgeResult<EdgeResponse>> + Send,
    {
        self.route(vec![Method::DELETE], path, handler)
    }

    pub fn build(self) -> EdgeResult<EdgeApp> {
        let mut router = EdgeRouter::new();
        let mut handlers = Vec::new();
        for (idx, route) in self.routes.into_iter().enumerate() {
            let pattern = PathPattern::parse(&route.path)?;
            router.add_route(route.methods, pattern, idx);
            handlers.push(route.handler);
        }

        let http_client = Client::builder()
            .build()
            .map_err(|err| EdgeError::Config(format!("failed to build http client: {err}")))?;

        let templates = if let Some(dir) = self.templates_dir {
            if dir.exists() {
                let glob = format!("{}/**/*", dir.display());
                Some(Arc::new(Tera::new(&glob)?))
            } else {
                None
            }
        } else {
            None
        };

        let state = AppState {
            http_client,
            templates,
            static_dir: self.static_dir,
        };

        Ok(EdgeApp {
            router,
            handlers,
            middlewares: self.middlewares,
            context: EdgeContext::new(state),
        })
    }
}

pub struct EdgeApp {
    router: EdgeRouter,
    handlers: Vec<DynHandler>,
    middlewares: Vec<Arc<dyn EdgeMiddleware>>,
    context: EdgeContext,
}

impl EdgeApp {
    pub fn builder() -> EdgeAppBuilder {
        EdgeAppBuilder::new()
    }

    pub fn context(&self) -> EdgeContext {
        self.context.clone()
    }

    pub async fn handle(
        &self,
        request: pqq_server::Request,
    ) -> Result<pqq_server::Response, EdgeError> {
        let edge_request = EdgeRequest::from_pqq(request)?;
        let response = self.dispatch(edge_request).await?;
        Ok(response.into_transport_response())
    }

    async fn dispatch(&self, request: EdgeRequest) -> EdgeResult<EdgeResponse> {
        let match_result = self
            .router
            .resolve(request.method(), request.path())
            .ok_or_else(|| EdgeError::NotFound {
                method: request.method().to_string(),
                path: request.path().to_string(),
            })?;

        let handler = self
            .handlers
            .get(match_result.handler_index)
            .cloned()
            .ok_or_else(|| EdgeError::Internal("handler index out of bounds".into()))?;

        self.execute_pipeline(request, match_result, handler).await
    }

    async fn execute_pipeline(
        &self,
        request: EdgeRequest,
        route: RouteMatch,
        handler: DynHandler,
    ) -> EdgeResult<EdgeResponse> {
        let request = request.with_path_params(route.params);
        for middleware in &self.middlewares {
            middleware.before(&request).await?;
        }
        let mut response = handler.call(self.context.clone(), request.clone()).await?;
        for middleware in self.middlewares.iter().rev() {
            middleware.after(&request, &mut response).await?;
        }
        Ok(response)
    }

    pub fn from_config(config: EdgeConfig, root: &Path) -> EdgeResult<Self> {
        let mut builder = EdgeApp::builder();
        builder.static_dir(root.to_path_buf());

        if let Some(dir) = &config.templates_dir {
            builder.templates_dir(root.join(dir));
        }

        if let Some(rate) = config.rate_limit {
            let window = parse_window(&rate)?;
            builder.with_rate_limit(rate.limit, window);
        }

        if let Some(waf) = config.waf {
            if waf.enabled {
                builder.with_waf(compile_rules(&waf)?);
            }
        } else {
            builder.with_waf(Vec::new());
        }

        for route in config.routes {
            add_route_from_config(&mut builder, route)?;
        }

        builder.build()
    }
}

fn parse_window(cfg: &RateLimitConfig) -> EdgeResult<Duration> {
    humantime::parse_duration(&cfg.window).map_err(|err| {
        EdgeError::Config(format!("invalid rate limit window '{}': {err}", cfg.window))
    })
}

fn compile_rules(config: &WafConfig) -> EdgeResult<Vec<Regex>> {
    let mut rules = Vec::new();
    for pattern in &config.rules {
        let compiled = Regex::new(pattern)
            .map_err(|err| EdgeError::Config(format!("invalid WAF pattern '{pattern}': {err}")))?;
        rules.push(compiled);
    }
    Ok(rules)
}

fn add_route_from_config(builder: &mut EdgeAppBuilder, route: RouteConfig) -> EdgeResult<()> {
    let methods = parse_methods(&route.methods)?;
    match route.handler {
        HandlerConfig::Json {
            status,
            body,
            headers,
        } => {
            let status = status
                .map(StatusCode::from_u16)
                .transpose()
                .map_err(|err| EdgeError::Config(err.to_string()))?
                .unwrap_or(StatusCode::OK);
            builder.route(methods, &route.path, move |_ctx, _req| {
                let body = body.clone();
                let headers = headers.clone();
                async move {
                    let mut response = EdgeResponse::json(&body)?;
                    response = response.with_status(status);
                    apply_headers(&mut response, &headers);
                    Ok(response)
                }
            });
        }
        HandlerConfig::Text {
            status,
            body,
            headers,
        } => {
            let status = status
                .map(StatusCode::from_u16)
                .transpose()
                .map_err(|err| EdgeError::Config(err.to_string()))?
                .unwrap_or(StatusCode::OK);
            builder.route(methods, &route.path, move |_ctx, _req| {
                let body = body.clone();
                let headers = headers.clone();
                async move {
                    let mut response = EdgeResponse::text(body.clone());
                    response = response.with_status(status);
                    apply_headers(&mut response, &headers);
                    Ok(response)
                }
            });
        }
        HandlerConfig::Template {
            name,
            context,
            status,
            headers,
        } => {
            let template_name = name.clone();
            let template_context = context.clone();
            let status = status
                .map(StatusCode::from_u16)
                .transpose()
                .map_err(|err| EdgeError::Config(err.to_string()))?
                .unwrap_or(StatusCode::OK);
            builder.route(methods, &route.path, move |ctx, _req| {
                let template_name = template_name.clone();
                let template_context = template_context.clone();
                let headers = headers.clone();
                async move {
                    let engine = ctx.template_engine().ok_or_else(|| {
                        EdgeError::Config("template engine not configured".into())
                    })?;
                    let mut tera_context = TeraContext::new();
                    if let Some(obj) = template_context.as_object() {
                        for (key, value) in obj {
                            tera_context.insert(key, value);
                        }
                    }
                    let rendered = engine.render(&template_name, &tera_context)?;
                    let mut response = EdgeResponse::html(rendered);
                    response = response.with_status(status);
                    apply_headers(&mut response, &headers);
                    Ok(response)
                }
            });
        }
        HandlerConfig::StaticFile {
            path,
            status,
            headers,
        } => {
            let file_path = PathBuf::from(path);
            let headers = headers.clone();
            let status = status
                .map(StatusCode::from_u16)
                .transpose()
                .map_err(|err| EdgeError::Config(err.to_string()))?
                .unwrap_or(StatusCode::OK);
            builder.route(methods, &route.path, move |ctx, _req| {
                let file_path = file_path.clone();
                let headers = headers.clone();
                async move {
                    let base = ctx.static_dir().ok_or_else(|| {
                        EdgeError::Config("static directory not configured".into())
                    })?;
                    let mut full = base.to_path_buf();
                    full.push(&file_path);
                    let canonical = fs::canonicalize(&full).await?;
                    if !canonical.starts_with(base) {
                        return Err(EdgeError::Forbidden(
                            "static file outside of configured root".into(),
                        ));
                    }
                    let bytes = fs::read(&canonical).await?;
                    let mut response = EdgeResponse::new(status);
                    if !headers.contains_key("content-type") {
                        let mime = mime_guess::from_path(&canonical)
                            .first()
                            .unwrap_or(mime::APPLICATION_OCTET_STREAM);
                        response.set_header(
                            CONTENT_TYPE,
                            HeaderValue::from_str(mime.essence_str()).unwrap(),
                        );
                    }
                    apply_headers(&mut response, &headers);
                    response = response.with_body(bytes);
                    Ok(response)
                }
            });
        }
    }
    Ok(())
}

fn apply_headers(response: &mut EdgeResponse, headers: &HashMap<String, String>) {
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            response.set_header(name, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use serde_json::{json, Value};
    use std::net::SocketAddr;

    #[tokio::test]
    async fn builder_supports_path_params() {
        let mut builder = EdgeApp::builder();
        builder.get("/hello/{name}", |_, req| async move {
            let name = req.param("name").unwrap().to_string();
            let mut response =
                EdgeResponse::json(&json!({ "greeting": format!("Hello, {name}!") }))?;
            response = response.with_status(StatusCode::OK);
            Ok(response)
        });
        let app = builder.build().unwrap();
        let peer: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let req = EdgeRequest::testing(Method::GET, "/hello/velocity", peer);
        let response = app.dispatch(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(value["greeting"], "Hello, velocity!");
    }

    #[tokio::test]
    async fn config_loader_builds_runtime() {
        let mut headers = HashMap::new();
        headers.insert("x-test".to_string(), "edge".to_string());
        let config = EdgeConfig {
            templates_dir: None,
            routes: vec![RouteConfig {
                path: "/api/ping".to_string(),
                methods: vec!["GET".to_string()],
                handler: HandlerConfig::Json {
                    status: Some(201),
                    body: json!({ "pong": true }),
                    headers,
                },
            }],
            rate_limit: Some(RateLimitConfig {
                limit: 10,
                window: "1s".into(),
            }),
            waf: Some(WafConfig {
                enabled: true,
                rules: Vec::new(),
            }),
        };

        let app = EdgeApp::from_config(config, Path::new(".")).expect("edge config should build");
        let peer: SocketAddr = "127.0.0.1:4001".parse().unwrap();
        let req = EdgeRequest::testing(Method::GET, "/api/ping", peer);
        let response = app.dispatch(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response
                .headers()
                .get("x-test")
                .and_then(|h| h.to_str().ok()),
            Some("edge")
        );
        let payload: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(payload["pong"], true);
    }
}
