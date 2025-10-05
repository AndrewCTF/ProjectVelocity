use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use prometheus::{self, Encoder, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

#[derive(Clone, Debug)]
pub struct TelemetrySettings {
    pub namespace: String,
    pub listen: Option<SocketAddr>,
}

impl Default for TelemetrySettings {
    fn default() -> Self {
        Self {
            namespace: "velocity".to_string(),
            listen: None,
        }
    }
}

#[derive(Clone, Default)]
pub struct TelemetryHandle {
    inner: Option<Arc<TelemetryInner>>,
}

impl TelemetryHandle {
    pub async fn initialize(settings: TelemetrySettings) -> Result<Self> {
        if settings.listen.is_none() {
            return Ok(Self { inner: None });
        }

        let namespace = settings.namespace;
        let registry = Arc::new(Registry::new());

        let http_opts = Opts::new(
            "http_requests_total",
            "Velocity HTTP responses grouped by method and status",
        )
        .namespace(namespace.clone());
        let http_requests = IntCounterVec::new(http_opts, &["method", "status"])?;
        registry.register(Box::new(http_requests.clone()))?;

        let bytes_opts = Opts::new(
            "http_response_bytes_total",
            "Bytes served to HTTP clients grouped by method and status",
        )
        .namespace(namespace.clone());
        let http_response_bytes = IntCounterVec::new(bytes_opts, &["method", "status"])?;
        registry.register(Box::new(http_response_bytes.clone()))?;

        let handshake_opts = Opts::new(
            "handshake_requests_total",
            "Velocity handshake-backed requests handled",
        )
        .namespace(namespace.clone());
        let handshake_total = IntCounter::with_opts(handshake_opts)?;
        registry.register(Box::new(handshake_total.clone()))?;

        let active_opts =
            Opts::new("active_requests", "In-flight Velocity HTTP requests").namespace(namespace);
        let active_requests = IntGauge::with_opts(active_opts)?;
        registry.register(Box::new(active_requests.clone()))?;

        let exporter = if let Some(addr) = settings.listen {
            Some(spawn_metrics_server(addr, Arc::clone(&registry)).await?)
        } else {
            None
        };

        let inner = TelemetryInner {
            http_requests,
            http_response_bytes,
            handshake_total,
            active_requests,
            exporter: Mutex::new(exporter),
        };

        Ok(Self {
            inner: Some(Arc::new(inner)),
        })
    }

    pub fn disabled() -> Self {
        Self { inner: None }
    }

    pub fn request_started(&self) {
        if let Some(inner) = self.inner.as_ref() {
            inner.handshake_total.inc();
            inner.active_requests.inc();
        }
    }

    pub fn request_finished(&self) {
        if let Some(inner) = self.inner.as_ref() {
            inner.active_requests.dec();
        }
    }

    pub fn observe_http(&self, method: &str, status: &str, bytes: usize) {
        if let Some(inner) = self.inner.as_ref() {
            inner
                .http_requests
                .with_label_values(&[method, status])
                .inc();
            inner
                .http_response_bytes
                .with_label_values(&[method, status])
                .inc_by(bytes as u64);
        }
    }

    pub fn metrics_addr(&self) -> Option<SocketAddr> {
        self.inner.as_ref().and_then(|inner| inner.metrics_addr())
    }

    pub async fn shutdown(&self) -> Result<()> {
        if let Some(inner) = self.inner.as_ref() {
            inner.shutdown().await?;
        }
        Ok(())
    }
}

struct TelemetryInner {
    http_requests: IntCounterVec,
    http_response_bytes: IntCounterVec,
    handshake_total: IntCounter,
    active_requests: IntGauge,
    exporter: Mutex<Option<MetricsServer>>,
}

impl TelemetryInner {
    async fn shutdown(&self) -> Result<()> {
        let server = self.exporter.lock().unwrap().take();

        if let Some(mut server) = server {
            server.shutdown().await?;
        }
        Ok(())
    }

    fn metrics_addr(&self) -> Option<SocketAddr> {
        self.exporter
            .lock()
            .unwrap()
            .as_ref()
            .map(|server| server.addr)
    }
}

struct MetricsServer {
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<Result<()>>>,
    addr: SocketAddr,
}

impl MetricsServer {
    async fn shutdown(&mut self) -> Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.join.take() {
            handle.await??;
        }
        Ok(())
    }
}

async fn spawn_metrics_server(addr: SocketAddr, registry: Arc<Registry>) -> Result<MetricsServer> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind metrics listener at {addr}"))?;
    let bound_addr = listener.local_addr()?;
    debug!(requested = %addr, bound = %bound_addr, "metrics endpoint bound");
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    debug!("metrics endpoint received shutdown signal");
                    break;
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((mut socket, peer)) => {
                            let registry = Arc::clone(&registry);
                            tokio::spawn(async move {
                                if let Err(err) = respond_with_metrics(&mut socket, &registry).await {
                                    warn!(target: "velocity::metrics", error = %err, peer = %peer, "failed to serve metrics request");
                                }
                            });
                        }
                        Err(err) => {
                            warn!(target: "velocity::metrics", error = %err, "metrics accept failed");
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
        Ok(())
    });

    Ok(MetricsServer {
        shutdown: Some(shutdown_tx),
        join: Some(join),
        addr: bound_addr,
    })
}

async fn respond_with_metrics(socket: &mut TcpStream, registry: &Arc<Registry>) -> Result<()> {
    let mut buf = [0u8; 1024];
    let _ = socket.read(&mut buf).await?;

    let metric_families = registry.gather();
    let mut payload = Vec::new();
    static ENCODER: Lazy<TextEncoder> = Lazy::new(TextEncoder::new);
    ENCODER
        .encode(&metric_families, &mut payload)
        .map_err(|err| anyhow!("failed to encode metrics: {err}"))?;
    if payload.is_empty() {
        payload.extend_from_slice(b"# no metrics available\n");
    }

    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    socket.write_all(header.as_bytes()).await?;
    socket.write_all(&payload).await?;
    socket.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn telemetry_counts_and_shutdown() {
        let settings = TelemetrySettings {
            listen: Some("127.0.0.1:0".parse().expect("metrics addr")),
            ..Default::default()
        };

        let telemetry = TelemetryHandle::initialize(settings)
            .await
            .expect("initialize telemetry");

        telemetry.request_started();
        telemetry.observe_http("GET", "200", 256);
        telemetry.request_finished();

        telemetry.shutdown().await.expect("shutdown telemetry");
    }

    #[tokio::test]
    async fn telemetry_metrics_endpoint_serves_payload() {
        let settings = TelemetrySettings {
            listen: Some("127.0.0.1:0".parse().expect("metrics addr")),
            ..Default::default()
        };

        let telemetry = TelemetryHandle::initialize(settings)
            .await
            .expect("initialize telemetry");

        telemetry.request_started();
        telemetry.observe_http("GET", "200", 1024);

        let addr = telemetry.metrics_addr().expect("metrics listening address");
        let mut stream = TcpStream::connect(addr).await.expect("connect metrics");
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write request");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read metrics");
        let payload = String::from_utf8_lossy(&buf);
        assert!(payload.contains("http_requests_total"));

        drop(stream);
        telemetry.shutdown().await.expect("shutdown telemetry");
    }
}
