use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};

use parking_lot::Mutex;
use pqq_core::HandshakeResponse;
use pqq_server::{
    HandshakeTelemetryCollector, HandshakeTelemetryEvent, Request, Response, Server, ServerConfig,
};
use pqq_tls::SecurityProfile;
use serde_json::Value;
use tokio::{
    runtime::{Builder, Runtime},
    sync::oneshot,
    task::JoinHandle,
};

use crate::{
    error::EasyError,
    util::{
        cache_dir_override, default_cache_dir, encode_base64_key, profile_from_str,
        store_cached_key,
    },
};

fn cache_label(addr: &SocketAddr) -> String {
    let ip = addr.ip().to_string().replace(':', "_");
    format!("{}-{}", ip, addr.port())
}

#[derive(Clone)]
pub struct EasyResponse {
    pub status: u16,
    pub reason: String,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
}

impl EasyResponse {
    pub fn text(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            reason: "OK".to_string(),
            body: body.into().into_bytes(),
            content_type: Some("text/plain; charset=utf-8".to_string()),
        }
    }

    pub fn json(body: &Value) -> Self {
        Self {
            status: 200,
            reason: "OK".to_string(),
            body: body.to_string().into_bytes(),
            content_type: Some("application/json".to_string()),
        }
    }

    pub fn html(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            reason: "OK".to_string(),
            body: body.into().into_bytes(),
            content_type: Some("text/html; charset=utf-8".to_string()),
        }
    }

    pub fn with_status(mut self, status: u16, reason: impl Into<String>) -> Self {
        self.status = status;
        self.reason = reason.into();
        self
    }

    fn into_response(self) -> Response {
        let content_type = self
            .content_type
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let header = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n",
            self.status,
            self.reason,
            content_type,
            self.body.len()
        );
        let mut payload = header.into_bytes();
        payload.extend_from_slice(&self.body);
        Response::from_bytes(payload)
    }
}

#[derive(Clone)]
pub struct EasyRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub body: Vec<u8>,
    pub handshake: HandshakeResponse,
    pub early: bool,
}

impl From<Request> for EasyRequest {
    fn from(req: Request) -> Self {
        let line = req.http_request_line();
        let (method, path, version) = line
            .map(|l| {
                (
                    l.method.to_string(),
                    l.target.to_string(),
                    l.version.to_string(),
                )
            })
            .unwrap_or_else(|| ("GET".into(), "/".into(), "HTTP/1.1".into()));
        Self {
            method,
            path,
            version,
            body: req.payload().to_vec(),
            handshake: req.handshake().clone(),
            early: req.is_early_data(),
        }
    }
}

pub type EasyHandlerFuture = Pin<Box<dyn Future<Output = EasyResponse> + Send>>;
pub type EasyAsyncHandler = Arc<dyn Fn(EasyRequest) -> EasyHandlerFuture + Send + Sync + 'static>;
pub type EasySyncHandler = Arc<dyn Fn(EasyRequest) -> EasyResponse + Send + Sync + 'static>;
pub type EasyRequestHook = Arc<dyn Fn(&EasyRequest) + Send + Sync + 'static>;
pub type EasyTelemetryHook = Arc<dyn Fn(&HandshakeTelemetryEvent) + Send + Sync + 'static>;
pub type EasyHandler = EasySyncHandler;

fn wrap_sync_handler(handler: EasySyncHandler) -> EasyAsyncHandler {
    Arc::new(move |req: EasyRequest| {
        let handler = Arc::clone(&handler);
        Box::pin(async move { handler(req) })
    })
}

pub struct EasyServerBuilder {
    bind_addr: SocketAddr,
    profile: SecurityProfile,
    handler: Option<EasyAsyncHandler>,
    alpns: Vec<String>,
    cache_public_key: bool,
    request_hook: Option<EasyRequestHook>,
    telemetry_hook: Option<EasyTelemetryHook>,
}

impl Default for EasyServerBuilder {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:0".parse().expect("loopback"),
            profile: SecurityProfile::Balanced,
            handler: None,
            alpns: vec!["pqq/1".to_string(), "h3".to_string()],
            cache_public_key: true,
            request_hook: None,
            telemetry_hook: None,
        }
    }
}

impl EasyServerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind_addr(mut self, addr: impl AsRef<str>) -> Result<Self, EasyError> {
        self.bind_addr = addr.as_ref().parse()?;
        Ok(self)
    }

    pub fn security_profile(mut self, profile: SecurityProfile) -> Self {
        self.profile = profile;
        self
    }

    pub fn security_profile_str(self, label: impl AsRef<str>) -> Result<Self, EasyError> {
        let profile = profile_from_str(label.as_ref())?;
        Ok(self.security_profile(profile))
    }

    pub fn static_text(mut self, body: impl Into<String>) -> Self {
        let response = EasyResponse::text(body);
        let handler: EasySyncHandler = Arc::new(move |_req| response.clone());
        self.handler = Some(wrap_sync_handler(handler));
        self
    }

    pub fn static_json(mut self, body: Value) -> Self {
        let response = EasyResponse::json(&body);
        let handler: EasySyncHandler = Arc::new(move |_req| response.clone());
        self.handler = Some(wrap_sync_handler(handler));
        self
    }

    pub fn handler(mut self, handler: EasySyncHandler) -> Self {
        self.handler = Some(wrap_sync_handler(handler));
        self
    }

    pub fn handler_fn<F>(self, handler: F) -> Self
    where
        F: Fn(EasyRequest) -> EasyResponse + Send + Sync + 'static,
    {
        let handler: EasySyncHandler = Arc::new(handler);
        self.handler(handler)
    }

    pub fn async_handler(mut self, handler: EasyAsyncHandler) -> Self {
        self.handler = Some(handler);
        self
    }

    pub fn async_handler_fn<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(EasyRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = EasyResponse> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let async_handler: EasyAsyncHandler = Arc::new(move |req: EasyRequest| {
            let handler = Arc::clone(&handler);
            Box::pin(handler(req))
        });
        self.handler = Some(async_handler);
        self
    }

    pub fn on_request<F>(mut self, hook: F) -> Self
    where
        F: Fn(&EasyRequest) + Send + Sync + 'static,
    {
        self.request_hook = Some(Arc::new(hook));
        self
    }

    pub fn on_handshake<F>(mut self, hook: F) -> Self
    where
        F: Fn(&HandshakeTelemetryEvent) + Send + Sync + 'static,
    {
        self.telemetry_hook = Some(Arc::new(hook));
        self
    }

    pub fn alpns<I, S>(mut self, alpns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.alpns = alpns.into_iter().map(Into::into).collect();
        self
    }

    pub fn cache_public_key(mut self, cache: bool) -> Self {
        self.cache_public_key = cache;
        self
    }

    pub fn build(self) -> Result<EasyServerHandle, EasyError> {
        let handler = self
            .handler
            .unwrap_or_else(|| wrap_sync_handler(Arc::new(|_| EasyResponse::text("ok"))));
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .thread_name("velocity-easy-server")
            .build()
            .map_err(EasyError::runtime)?;

        let mut server_config = ServerConfig::default()
            .with_security_profile(self.profile)
            .with_alpn(self.alpns.clone());
        if let Some(hook) = self.telemetry_hook.clone() {
            let collector = TelemetryBridge::new(hook);
            server_config = server_config.with_telemetry(Arc::new(collector));
        }
        let server = runtime
            .block_on(Server::bind(self.bind_addr, server_config))
            .map_err(EasyError::request)?;
        let addr = server.local_addr().map_err(EasyError::request)?;
        let kem_public = server.kem_public_key().to_vec();
        let server = Arc::new(server);

        if self.cache_public_key {
            let dir = cache_dir_override().unwrap_or_else(default_cache_dir);
            let label = cache_label(&addr);
            let _ = store_cached_key(&label, &kem_public, Some(dir.as_path()));
        }

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handler_arc = Arc::clone(&handler);
        let request_hook = self.request_hook.clone();
        let server_task = {
            let server = Arc::clone(&server);
            runtime.spawn(async move {
                let mut shutdown_rx = shutdown_rx;
                let serve_future = server.serve(move |req: Request| {
                    let handler = Arc::clone(&handler_arc);
                    let request_hook = request_hook.clone();
                    async move {
                        let easy_req = EasyRequest::from(req);
                        if let Some(hook) = request_hook.as_ref() {
                            hook(&easy_req);
                        }
                        let response = handler(easy_req).await;
                        response.into_response()
                    }
                });
                tokio::select! {
                    res = serve_future => {
                        if let Err(err) = res {
                            tracing::error!(target: "pqq-easy::server", error = ?err, "server loop error");
                        }
                    }
                    _ = &mut shutdown_rx => {
                        tracing::info!(target: "pqq-easy::server", "shutdown signal received");
                    }
                }
            })
        };

        Ok(EasyServerHandle {
            runtime: Some(runtime),
            _server: server,
            shutdown: Mutex::new(Some(shutdown_tx)),
            task: Mutex::new(Some(server_task)),
            addr,
            kem_public,
        })
    }
}

#[derive(Clone)]
struct TelemetryBridge {
    hook: EasyTelemetryHook,
}

impl TelemetryBridge {
    fn new(hook: EasyTelemetryHook) -> Self {
        Self { hook }
    }
}

impl std::fmt::Debug for TelemetryBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetryBridge").finish()
    }
}

impl HandshakeTelemetryCollector for TelemetryBridge {
    fn record(&self, event: &HandshakeTelemetryEvent) {
        (self.hook)(event);
    }
}

pub struct EasyServerHandle {
    runtime: Option<Runtime>,
    _server: Arc<Server>,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
    task: Mutex<Option<JoinHandle<()>>>,
    addr: SocketAddr,
    kem_public: Vec<u8>,
}

impl EasyServerHandle {
    pub fn address(&self) -> SocketAddr {
        self.addr
    }

    pub fn kem_public_key(&self) -> &[u8] {
        &self.kem_public
    }

    pub fn kem_public_key_base64(&self) -> String {
        encode_base64_key(&self.kem_public)
    }

    pub fn shutdown(&self) {
        if let Some(tx) = self.shutdown.lock().take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.lock().take() {
            let _ = self.runtime().block_on(async { task.await.ok() });
        }
    }

    fn runtime(&self) -> &Runtime {
        self.runtime
            .as_ref()
            .expect("EasyServerHandle runtime should be available")
    }
}

impl Drop for EasyServerHandle {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_label_is_filesystem_safe() {
        let addr: SocketAddr = "[::1]:443".parse().unwrap();
        let label = cache_label(&addr);
        assert_eq!(label, "__1-443");
        assert!(!label.contains(':'));
    }
}
