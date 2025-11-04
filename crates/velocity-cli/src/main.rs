mod edge;
mod simple_config;
mod telemetry;

use std::borrow::Cow;
use std::env;
use std::error::Error as StdError;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use edge::{load_edge_app, resolve_config_path};
use futures_util::{
    StreamExt,
    stream::{self, BoxStream},
};
use html_escape::{encode_double_quoted_attribute, encode_text};
use http::StatusCode;
use mime_guess::Mime;
use notify::{
    Config as NotifyConfig, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
    event::ModifyKind,
};
use percent_encoding::percent_decode_str;
use pqq_server::{
    Request, Response, ResponseStreamError, SecurityProfile, Server, ServerConfig, ServerError,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use reqwest::{
    Client, Method, Url,
    header::{
        CONNECTION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue, TRANSFER_ENCODING,
        UPGRADE,
    },
};
use serde::Serialize;
use simple_config::{ConfigOverrides, load_combined_config};
use thiserror::Error;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::task;
use tokio::task::JoinHandle;
use tracing::{error, info, info_span, warn};
use tracing_subscriber::EnvFilter;
use velocity_core::https::{HttpsConfig, HttpsServer};
use velocity_edge::{
    EdgeError, EdgeRequest, EdgeResponse, ServeConfig, ServeRouter, ServeRouterController,
};
use walkdir::WalkDir;

use telemetry::{TelemetryHandle, TelemetrySettings};

#[derive(Parser, Debug)]
#[command(
    name = "velocity",
    author,
    version,
    about = "Velocity CLI: serve and deploy static sites over the Velocity transport",
    propagate_version = true
)]
struct Cli {
    /// Increase output verbosity (-v, -vv, -vvv).
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    /// Output log format (text or json).
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,

    #[command(subcommand)]
    command: Option<Command>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
enum Command {
    /// Serve a directory over Velocity with a static-file handler.
    Serve(ServeArgs),
    /// Bundle a static site directory into a deployment folder.
    Deploy(DeployArgs),
    /// Scaffold a starter Velocity-ready static site.
    Init(InitArgs),
}

#[derive(Args, Debug, Clone)]
struct ServeArgs {
    /// UDP socket to bind for Velocity traffic.
    #[arg(short = 'l', long, default_value = "0.0.0.0:4433")]
    listen: SocketAddr,

    /// Supported ALPN protocols (comma separated or repeat the flag).
    #[arg(long, value_delimiter = ',', default_values_t = vec!["velocity/1".to_string()])]
    alpn: Vec<String>,

    /// Fallback ALPN protocol advertised to clients.
    #[arg(long, default_value = "h3")]
    fallback_alpn: String,

    /// Optional fallback host for legacy HTTP/3 clients.
    #[arg(long)]
    fallback_host: Option<String>,

    /// Optional fallback port for legacy HTTP/3 clients.
    #[arg(long, default_value_t = 443)]
    fallback_port: u16,

    /// Filesystem root that will be served.
    #[arg(long, default_value = "public")]
    root: PathBuf,

    /// Custom index file to load when the client requests "/".
    #[arg(long, default_value = "index.html")]
    index: String,

    /// Enable HTML directory listings when no index file exists.
    #[arg(long)]
    listings: bool,

    /// Maximum number of concurrent Velocity sessions.
    #[arg(long)]
    max_sessions: Option<usize>,

    /// Security profile to use for the hybrid handshake.
    #[arg(long, value_enum, default_value_t = Profile::Balanced)]
    profile: Profile,

    /// Path to a PEM encoded certificate chain.
    #[arg(long)]
    cert: Option<PathBuf>,

    /// Path to a PEM encoded private key.
    #[arg(long)]
    key: Option<PathBuf>,

    /// Generate a self-signed certificate for the provided domain.
    #[arg(long)]
    self_signed: bool,

    /// Domain name to embed in the generated self-signed certificate.
    #[arg(long, default_value = "localhost")]
    domain: String,

    /// Contact email used for ACME account registration (Stage 3 preparation).
    #[arg(long)]
    email: Option<String>,

    /// Consent to the ACME Terms of Service required for automation.
    #[arg(long, action = ArgAction::SetTrue)]
    accept_tos: bool,

    /// Advertise the server's ML-KEM public key in handshake payloads.
    #[arg(long)]
    publish_kem: bool,

    /// Forward HTTP requests to an upstream origin instead of serving from disk.
    #[arg(long)]
    proxy: Option<String>,

    /// Preserve the incoming Host header when proxying instead of using the upstream host.
    #[arg(long)]
    proxy_preserve_host: bool,

    /// Timeout for establishing connections to the upstream origin (e.g. "5s", "1m").
    #[arg(long, value_parser = humantime::parse_duration, default_value = "10s")]
    proxy_connect_timeout: Duration,

    /// Timeout for receiving the upstream response headers/body.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "30s")]
    proxy_response_timeout: Duration,

    /// How long to keep idle upstream connections in the pool.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "90s")]
    proxy_idle_timeout: Duration,

    /// Interval for TCP keepalive probes on upstream connections.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "60s")]
    proxy_tcp_keepalive: Duration,

    /// Stream proxy responses using HTTP/1.1 chunked encoding instead of buffering.
    #[arg(long)]
    proxy_stream: bool,

    /// Load an edge runtime configuration (YAML) for dynamic routes and APIs.
    #[arg(long)]
    edge_config: Option<PathBuf>,

    /// Path to a unified serve configuration (YAML or JSON).
    #[arg(long)]
    config: Option<PathBuf>,

    /// Enable the built-in HTTPS preview listener.
    #[arg(long)]
    serve_https: bool,

    /// Address for the HTTPS preview listener.
    #[arg(long, default_value = "0.0.0.0:8443")]
    https_listen: SocketAddr,

    /// Optional address to expose Prometheus metrics (e.g. 127.0.0.1:9300).
    #[arg(long)]
    metrics_listen: Option<SocketAddr>,
}

impl Default for ServeArgs {
    fn default() -> Self {
        ServeArgs {
            listen: "0.0.0.0:4433".parse().expect("default listen addr"),
            alpn: vec!["velocity/1".to_string()],
            fallback_alpn: "h3".to_string(),
            fallback_host: None,
            fallback_port: 443,
            root: PathBuf::from("public"),
            index: "index.html".to_string(),
            listings: false,
            max_sessions: None,
            profile: Profile::Balanced,
            cert: None,
            key: None,
            self_signed: false,
            domain: "localhost".to_string(),
            email: None,
            accept_tos: false,
            publish_kem: false,
            proxy: None,
            proxy_preserve_host: false,
            proxy_connect_timeout: Duration::from_secs(10),
            proxy_response_timeout: Duration::from_secs(30),
            proxy_idle_timeout: Duration::from_secs(90),
            proxy_tcp_keepalive: Duration::from_secs(60),
            proxy_stream: false,
            edge_config: None,
            config: None,
            serve_https: false,
            https_listen: "0.0.0.0:8443".parse().expect("default https addr"),
            metrics_listen: None,
        }
    }
}

#[derive(Debug, Error)]
enum ProxyError {
    #[error("http request parsing was incomplete")]
    Incomplete,
    #[error("http parse error: {0}")]
    Parse(String),
    #[error("missing request line components")]
    MissingRequestLine,
    #[error("invalid http method: {0}")]
    InvalidMethod(String),
    #[error("unsupported http version {0}")]
    UnsupportedVersion(u8),
    #[error("absolute request targets are not allowed in reverse proxy mode")]
    AbsoluteTarget,
    #[error("invalid header name: {0}")]
    InvalidHeaderName(String),
    #[error("invalid header value for {0}")]
    InvalidHeaderValue(String),
    #[error("upstream request timed out")]
    Timeout(#[source] reqwest::Error),
    #[error("TLS handshake with upstream failed: {message}")]
    Tls {
        message: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("failed to connect to upstream origin")]
    Connect(#[source] reqwest::Error),
    #[error("upstream request failed: {0}")]
    Upstream(#[source] reqwest::Error),
}

type ProxyResult<T> = Result<T, ProxyError>;

#[derive(Debug)]
struct ParsedRequest {
    method: Method,
    target: String,
    headers: Vec<(String, Vec<u8>)>,
    host: Option<String>,
    body: Vec<u8>,
}

#[derive(Clone, Copy)]
struct ProxyTuning {
    connect_timeout: Duration,
    response_timeout: Duration,
    idle_timeout: Duration,
    tcp_keepalive: Duration,
    streaming: bool,
}

#[derive(Clone)]
struct ReverseProxy {
    client: Client,
    upstream: Url,
    preserve_host: bool,
    tuning: ProxyTuning,
}

impl ReverseProxy {
    fn new(origin: &str, preserve_host: bool, tuning: ProxyTuning) -> Result<Self> {
        let mut upstream = Url::parse(origin)?;
        ensure!(
            matches!(upstream.scheme(), "http" | "https"),
            "reverse proxy upstream must be http or https"
        );
        if upstream.path().is_empty() {
            upstream.set_path("/");
        }
        if !upstream.path().ends_with('/') {
            let mut path = upstream.path().to_string();
            path.push('/');
            upstream.set_path(&path);
        }

        let client = Client::builder()
            .http1_only()
            .pool_idle_timeout(Some(tuning.idle_timeout))
            .connect_timeout(tuning.connect_timeout)
            .timeout(tuning.response_timeout)
            .tcp_keepalive(Some(tuning.tcp_keepalive))
            .build()?;

        Ok(Self {
            client,
            upstream,
            preserve_host,
            tuning,
        })
    }

    fn upstream(&self) -> &Url {
        &self.upstream
    }

    fn streaming_enabled(&self) -> bool {
        self.tuning.streaming
    }

    async fn handle(&self, request: Request) -> Response {
        match self.forward(request).await {
            Ok(response) => response,
            Err(err) => {
                warn!(target: "velocity::proxy", error = %err, "proxy request failed");
                let (status, message): (StatusCode, Cow<'_, str>) = match &err {
                    ProxyError::Incomplete | ProxyError::MissingRequestLine => (
                        StatusCode::BAD_REQUEST,
                        Cow::Borrowed("Malformed HTTP request forwarded to proxy."),
                    ),
                    ProxyError::Parse(_) => (
                        StatusCode::BAD_REQUEST,
                        Cow::Borrowed("Unable to parse HTTP request forwarded to proxy."),
                    ),
                    ProxyError::InvalidHeaderName(_) | ProxyError::InvalidHeaderValue(_) => (
                        StatusCode::BAD_REQUEST,
                        Cow::Borrowed("Proxy request contained invalid header syntax."),
                    ),
                    ProxyError::InvalidMethod(_) | ProxyError::UnsupportedVersion(_) => (
                        StatusCode::NOT_IMPLEMENTED,
                        Cow::Borrowed("HTTP method or version not supported by proxy."),
                    ),
                    ProxyError::AbsoluteTarget => (
                        StatusCode::BAD_REQUEST,
                        Cow::Borrowed(
                            "Absolute-form request targets are not allowed in proxy mode.",
                        ),
                    ),
                    ProxyError::Timeout(_) => (
                        StatusCode::GATEWAY_TIMEOUT,
                        Cow::Borrowed("Upstream origin timed out while processing the request."),
                    ),
                    ProxyError::Tls { message, .. } => (
                        StatusCode::BAD_GATEWAY,
                        Cow::Owned(format!("TLS handshake with upstream failed: {message}")),
                    ),
                    ProxyError::Connect(_) => (
                        StatusCode::BAD_GATEWAY,
                        Cow::Borrowed("Unable to establish a connection to the upstream origin."),
                    ),
                    ProxyError::Upstream(_) => (
                        StatusCode::BAD_GATEWAY,
                        Cow::Borrowed(
                            "Upstream origin returned an unexpected error while handling the request.",
                        ),
                    ),
                };
                proxy_error_response(status, &message)
            }
        }
    }

    async fn forward(&self, request: Request) -> ProxyResult<Response> {
        let parsed = parse_http_request(request.payload())?;

        if parsed.target.starts_with("http://") || parsed.target.starts_with("https://") {
            return Err(ProxyError::AbsoluteTarget);
        }

        let url = self
            .upstream
            .join(parsed.target.as_str())
            .map_err(|err| ProxyError::Parse(err.to_string()))?;

        let mut headers = HeaderMap::new();
        for (name, value) in &parsed.headers {
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| ProxyError::InvalidHeaderName(name.clone()))?;
            if is_hop_by_hop(&header_name) {
                continue;
            }
            if header_name == HOST {
                if self.preserve_host {
                    let header_value = HeaderValue::from_bytes(value)
                        .map_err(|_| ProxyError::InvalidHeaderValue(name.clone()))?;
                    headers.insert(HOST, header_value);
                }
                continue;
            }
            if header_name == CONTENT_LENGTH {
                // Let reqwest compute content-length based on the body we send downstream.
                continue;
            }

            let header_value = HeaderValue::from_bytes(value)
                .map_err(|_| ProxyError::InvalidHeaderValue(name.clone()))?;
            headers.append(header_name, header_value);
        }

        if !self.preserve_host {
            if let Some(host_str) = upstream_host_header(&self.upstream) {
                let host_value = HeaderValue::from_str(&host_str)
                    .map_err(|_| ProxyError::InvalidHeaderValue("host".to_string()))?;
                headers.insert(HOST, host_value);
            }
        }

        append_forwarded_headers(&mut headers, &request, parsed.host.as_deref())?;

        let mut builder = self.client.request(parsed.method.clone(), url);
        builder = builder.headers(headers);
        if !parsed.body.is_empty() {
            builder = builder.body(parsed.body);
        }

        let upstream_response = builder.send().await.map_err(classify_upstream_error)?;
        let status = upstream_response.status();
        let mut response_headers = upstream_response.headers().clone();
        response_headers.remove(CONNECTION);
        response_headers.remove(TRANSFER_ENCODING);
        response_headers.remove(CONTENT_LENGTH);
        response_headers.remove(UPGRADE);

        if self.tuning.streaming {
            let head = build_streaming_head(status, &response_headers);
            let stream = build_chunked_stream(upstream_response);
            return Ok(Response::chunked(head, stream));
        }

        let body_bytes = upstream_response
            .bytes()
            .await
            .map_err(classify_upstream_error)?
            .to_vec();
        Ok(build_buffered_response(
            status,
            &response_headers,
            &body_bytes,
        ))
    }
}

fn classify_upstream_error(err: reqwest::Error) -> ProxyError {
    if err.is_timeout() {
        ProxyError::Timeout(err)
    } else if err.is_connect() {
        if let Some(message) = detect_tls_failure(&err) {
            ProxyError::Tls {
                message,
                source: err,
            }
        } else {
            ProxyError::Connect(err)
        }
    } else {
        ProxyError::Upstream(err)
    }
}

fn detect_tls_failure(err: &reqwest::Error) -> Option<String> {
    tls_failure_hint(err)
}

fn tls_failure_hint(err: &(dyn StdError + 'static)) -> Option<String> {
    let mut current: Option<&(dyn StdError + 'static)> = Some(err);
    while let Some(error) = current {
        let message = error.to_string();
        let lower = message.to_ascii_lowercase();
        if lower.contains("tls")
            || lower.contains("ssl")
            || lower.contains("certificate")
            || lower.contains("handshake")
        {
            return Some(message);
        }
        current = error.source();
    }
    None
}

fn parse_http_request(bytes: &[u8]) -> ProxyResult<ParsedRequest> {
    let mut header_storage = vec![httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut header_storage);
    let status = request
        .parse(bytes)
        .map_err(|err| ProxyError::Parse(err.to_string()))?;
    let header_len = match status {
        httparse::Status::Complete(len) => len,
        httparse::Status::Partial => return Err(ProxyError::Incomplete),
    };

    let method = request
        .method
        .ok_or(ProxyError::MissingRequestLine)?
        .to_string();
    let target = request
        .path
        .ok_or(ProxyError::MissingRequestLine)?
        .to_string();
    let version = request.version.ok_or(ProxyError::MissingRequestLine)?;
    if version != 1 {
        return Err(ProxyError::UnsupportedVersion(version));
    }

    let method = Method::from_bytes(method.as_bytes())
        .map_err(|_| ProxyError::InvalidMethod(method.clone()))?;

    let mut headers = Vec::with_capacity(request.headers.len());
    let mut host = None;
    for header in request.headers.iter() {
        let name = header.name.to_string();
        if name.eq_ignore_ascii_case("host") {
            let value = String::from_utf8_lossy(header.value).trim().to_string();
            if !value.is_empty() {
                host = Some(value);
            }
        }
        headers.push((name, header.value.to_vec()));
    }

    let body = bytes[header_len..].to_vec();

    Ok(ParsedRequest {
        method,
        target,
        headers,
        host,
        body,
    })
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailers"
    )
}

fn append_forwarded_headers(
    headers: &mut HeaderMap,
    request: &Request,
    original_host: Option<&str>,
) -> ProxyResult<()> {
    let peer_ip = request.peer().ip().to_string();
    let forwarded = if let Some(existing) = headers.get("x-forwarded-for") {
        let existing = existing
            .to_str()
            .map_err(|_| ProxyError::InvalidHeaderValue("x-forwarded-for".into()))?
            .trim();
        let combined = if existing.is_empty() {
            peer_ip.clone()
        } else {
            format!("{existing}, {peer_ip}")
        };
        HeaderValue::from_str(&combined)
            .map_err(|_| ProxyError::InvalidHeaderValue("x-forwarded-for".into()))?
    } else {
        HeaderValue::from_str(&peer_ip)
            .map_err(|_| ProxyError::InvalidHeaderValue("x-forwarded-for".into()))?
    };
    headers.insert(HeaderName::from_static("x-forwarded-for"), forwarded);

    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );

    if let Some(host) = original_host {
        if !host.is_empty() {
            let value = HeaderValue::from_str(host)
                .map_err(|_| ProxyError::InvalidHeaderValue("x-forwarded-host".into()))?;
            headers.insert(HeaderName::from_static("x-forwarded-host"), value);
        }
    }

    Ok(())
}

fn upstream_host_header(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    match url.port() {
        Some(port) => Some(format!("{host}:{port}")),
        None => Some(host.to_string()),
    }
}

fn build_buffered_response(status: StatusCode, headers: &HeaderMap, body: &[u8]) -> Response {
    let reason = status.canonical_reason().unwrap_or("OK");
    let mut head = format!(
        "HTTP/1.1 {} {}
",
        status.as_str(),
        reason
    );

    for (name, value) in headers.iter() {
        if is_hop_by_hop(name) || name == CONTENT_LENGTH || name == CONNECTION {
            continue;
        }
        if let Ok(value_str) = value.to_str() {
            head.push_str(name.as_str());
            head.push_str(": ");
            head.push_str(value_str);
            head.push_str("\r\n");
        }
    }

    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("Connection: keep-alive\r\n\r\n");

    let mut payload = head.into_bytes();
    payload.extend_from_slice(body);
    Response::from_bytes(payload)
}

fn build_streaming_head(status: StatusCode, headers: &HeaderMap) -> Vec<u8> {
    let reason = status.canonical_reason().unwrap_or("OK");
    let mut head = format!(
        "HTTP/1.1 {} {}
",
        status.as_str(),
        reason
    );

    for (name, value) in headers.iter() {
        if is_hop_by_hop(name) || name == CONTENT_LENGTH || name == CONNECTION {
            continue;
        }
        if let Ok(value_str) = value.to_str() {
            head.push_str(name.as_str());
            head.push_str(": ");
            head.push_str(value_str);
            head.push_str("\r\n");
        }
    }

    head.push_str("Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n");
    head.into_bytes()
}

fn encode_chunk(chunk: &Bytes) -> Bytes {
    if chunk.is_empty() {
        return Bytes::from_static(b"");
    }

    let mut encoded = Vec::with_capacity(chunk.len() + 16);
    let header = format!("{:X}\r\n", chunk.len());
    encoded.extend_from_slice(header.as_bytes());
    encoded.extend_from_slice(chunk);
    encoded.extend_from_slice(b"\r\n");
    Bytes::from(encoded)
}

fn build_chunked_stream(
    response: reqwest::Response,
) -> BoxStream<'static, Result<Bytes, ResponseStreamError>> {
    response
        .bytes_stream()
        .map(|result| match result {
            Ok(chunk) => Ok(encode_chunk(&chunk)),
            Err(err) => Err(ResponseStreamError::from_error(err)),
        })
        .chain(stream::once(async { Ok(Bytes::from_static(b"0\r\n\r\n")) }))
        .boxed()
}

fn proxy_error_response(status: StatusCode, message: &str) -> Response {
    let status_line = format!(
        "{} {}",
        status.as_str(),
        status.canonical_reason().unwrap_or("Error")
    );
    http_text_response(&status_line, message.to_string()).into_response()
}

#[derive(Args, Debug, Clone)]
struct DeployArgs {
    /// Source directory that contains the static assets to deploy.
    #[arg(long, default_value = "public")]
    source: PathBuf,
    /// Output directory that will receive the deployment bundle.
    #[arg(long, default_value = "deploy")]
    output: PathBuf,
    /// Remove the output directory before copying files.
    #[arg(long)]
    clean: bool,
    /// Emit a manifest file with deployment metadata.
    #[arg(long)]
    manifest: bool,
}

#[derive(Args, Debug, Clone)]
struct InitArgs {
    /// Directory where the starter site will be generated.
    #[arg(long, default_value = "public")]
    dir: PathBuf,
    /// Overwrite existing files if they already exist.
    #[arg(long)]
    force: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum Profile {
    Turbo,
    Balanced,
    Fortress,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

impl From<Profile> for SecurityProfile {
    fn from(value: Profile) -> Self {
        match value {
            Profile::Turbo => SecurityProfile::Turbo,
            Profile::Balanced => SecurityProfile::Balanced,
            Profile::Fortress => SecurityProfile::Fortress,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.log_format);

    let command = cli.command.unwrap_or(Command::Serve(ServeArgs::default()));

    match command {
        Command::Serve(args) => run_serve(args).await?,
        Command::Deploy(args) => run_deploy(&args)?,
        Command::Init(args) => run_init(&args)?,
    }

    Ok(())
}

fn init_tracing(verbosity: u8, format: LogFormat) {
    let filter = match verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    let env_filter = EnvFilter::builder()
        .with_default_directive(filter.parse().unwrap_or_else(|_| "info".parse().unwrap()))
        .from_env_lossy();

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false);

    let _ = match format {
        LogFormat::Text => subscriber.try_init(),
        LogFormat::Json => subscriber.json().try_init(),
    };
}

async fn run_serve(mut args: ServeArgs) -> Result<()> {
    let mut initial_router_config: Option<ServeConfig> = None;
    let mut config_overrides: Option<ConfigOverrides> = None;

    if let Some(config_path) = args.config.clone() {
        let resolved = resolve_serve_config_path(&args.root, &config_path)?;
        let combined = load_combined_config(&resolved).await?;
        if let Some(overrides) = combined.overrides.clone() {
            overrides.apply(&mut args);
            config_overrides = Some(overrides);
        }
        initial_router_config = Some(combined.router);
        args.config = Some(resolved);
    }

    let ServeArgs {
        listen,
        alpn,
        fallback_alpn,
        fallback_host,
        fallback_port,
        root,
        index,
        listings,
        max_sessions,
        profile,
        cert,
        key,
        self_signed,
        domain,
        email,
        accept_tos,
        publish_kem,
        proxy,
        proxy_preserve_host,
        proxy_connect_timeout,
        proxy_response_timeout,
        proxy_idle_timeout,
        proxy_tcp_keepalive,
        proxy_stream,
        edge_config,
        config,
        serve_https,
        https_listen,
        metrics_listen,
    } = args;

    if cert.is_some() ^ key.is_some() {
        bail!("both --cert and --key must be provided together");
    }

    if edge_config.is_some() && config.is_some() {
        bail!("--edge-config and --config cannot be used together");
    }

    if config.is_some() && proxy.is_some() {
        bail!("--proxy cannot be combined with --config");
    }

    if !root.exists() {
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create site root {}", root.display()))?;
    }
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", root.display()))?;

    let materials = if self_signed {
        Some(
            task::spawn_blocking({
                let domain = domain.clone();
                let root = root.clone();
                move || generate_self_signed_cert(&root, &domain)
            })
            .await??,
        )
    } else {
        None
    };

    let mut server_config = match (&cert, &key, &materials) {
        (Some(cert), Some(key), _) => ServerConfig::from_cert_chain(cert.clone(), key.clone()),
        (None, None, Some(materials)) => {
            ServerConfig::from_cert_chain(materials.cert_path.clone(), materials.key_path.clone())
        }
        _ => ServerConfig::default(),
    };

    let security_profile: SecurityProfile = profile.into();

    server_config = server_config
        .with_security_profile(security_profile)
        .with_alpn(alpn.clone());

    if let Some(limit) = max_sessions {
        server_config = server_config.with_max_concurrent_sessions(limit);
    }

    if let Some(host) = &fallback_host {
        server_config =
            server_config.with_fallback(fallback_alpn.clone(), host.clone(), fallback_port);
    }

    if publish_kem {
        server_config = server_config.publish_kem_public(true);
    }

    if let Some(email) = &email {
        if !accept_tos {
            warn!(
                target: "velocity::acme",
                "--email provided without --accept-tos; ACME automation will remain disabled"
            );
        } else {
            info!(
                target: "velocity::acme",
                email = %email,
                "ACME contact recorded; automation will activate once Stage 3 ships"
            );
        }
    }

    if accept_tos && email.is_none() {
        warn!(
            target: "velocity::acme",
            "--accept-tos provided but --email missing; add contact information for ACME enrollment"
        );
    }

    let https_plan = if serve_https {
        Some(HttpsConfig {
            bind_addr: https_listen,
            security_profile,
            ticket_lifetime: server_config.session_ticket_lifetime,
        })
    } else {
        None
    };

    let telemetry = if let Some(addr) = metrics_listen {
        info!(target: "velocity::metrics", address = %addr, "Prometheus metrics endpoint enabled");
        let settings = TelemetrySettings {
            listen: Some(addr),
            ..Default::default()
        };
        let telemetry = TelemetryHandle::initialize(settings).await?;
        if let Some(bound) = telemetry.metrics_addr() {
            info!(target: "velocity::metrics", address = %bound, "Prometheus metrics exporter running");
        }
        telemetry
    } else {
        TelemetryHandle::disabled()
    };

    let proxy = if let Some(origin) = &proxy {
        let tuning = ProxyTuning {
            connect_timeout: proxy_connect_timeout,
            response_timeout: proxy_response_timeout,
            idle_timeout: proxy_idle_timeout,
            tcp_keepalive: proxy_tcp_keepalive,
            streaming: proxy_stream,
        };
        Some(Arc::new(ReverseProxy::new(
            origin,
            proxy_preserve_host,
            tuning,
        )?))
    } else {
        None
    };

    let mut router_watch_task: Option<JoinHandle<()>> = None;
    let router_handle = if let Some(config_path) = &config {
        let resolved = resolve_config_path(&root, config_path);
        let serve_config = if let Some(config) = initial_router_config.take() {
            config
        } else {
            load_combined_config(&resolved).await?.router
        };
        let host_count = serve_config.hosts.len();
        let router = build_serve_router(serve_config, &root)?;
        info!(
            target: "velocity::config",
            file = %resolved.display(),
            hosts = host_count,
            "serve configuration loaded"
        );
        let (controller, handle) = ServeRouterController::new(router);
        match spawn_router_watcher(
            resolved.clone(),
            root.clone(),
            controller,
            config_overrides.clone(),
        ) {
            Ok(task_handle) => {
                router_watch_task = Some(task_handle);
            }
            Err(err) => {
                warn!(
                    target: "velocity::config",
                    error = %err,
                    file = %resolved.display(),
                    "failed to start serve configuration watcher"
                );
            }
        }
        Some(handle)
    } else {
        None
    };

    let edge_app = if let Some(config_path) = &edge_config {
        let resolved = resolve_config_path(&root, config_path);
        let app = load_edge_app(&resolved, &root).await?;
        info!(
            config = %resolved.display(),
            "Edge runtime configuration loaded"
        );
        Some(Arc::new(app))
    } else {
        None
    };

    let server = Server::bind(listen, server_config).await?;
    let local = server
        .local_addr()
        .context("failed to query bound socket address")?;

    let mut https_handle = if let Some(cfg) = https_plan {
        let https_server = HttpsServer::bind_with_router(cfg, router_handle.clone())
            .await
            .context("failed to bind HTTPS preview listener")?;
        let https_addr = https_server
            .local_addr()
            .context("failed to query HTTPS preview address")?;
        info!(address = %https_addr, profile = ?profile, "HTTPS preview listener started");
        Some(https_server.spawn_hello())
    } else {
        None
    };

    if let Some(proxy) = proxy.clone() {
        let telemetry = telemetry.clone();
        info!(
            address = %local,
            upstream = %proxy.upstream(),
            profile = ?profile,
            preserve_host = proxy_preserve_host,
            streaming = proxy.streaming_enabled(),
            "Velocity reverse proxy started"
        );

        let serve_future = server.serve(move |request: Request| {
            let proxy = Arc::clone(&proxy);
            let telemetry = telemetry.clone();
            async move {
                let (method_label, target_label) = request_labels(&request);
                let span = info_span!(
                    "velocity_http_request",
                    method = %method_label,
                    target = %target_label
                );
                let _guard = span.enter();
                telemetry.request_started();
                let response = proxy.handle(request).await;
                telemetry.request_finished();
                response
            }
        });

        tokio::select! {
            res = serve_future => {
                if let Err(err) = res {
                    match err {
                        ServerError::Handshake(inner) => bail!("handshake failed: {inner}"),
                        other => return Err(other.into()),
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("shutdown signal received; terminating server");
            }
        }

        if let Some(handle) = https_handle.take() {
            handle
                .shutdown()
                .await
                .context("failed to shutdown HTTPS preview listener")?;
        }
    } else {
        let telemetry = telemetry.clone();
        info!(
            address = %local,
            root = %root.display(),
            profile = ?profile,
            edge_enabled = edge_app.is_some(),
            "Velocity static site server started"
        );

        let site = Arc::new(SiteConfig {
            root,
            index,
            listings,
        });

        let edge_app = edge_app.clone();
        let router_handle = router_handle.clone();

        let serve_future = server.serve(move |request: Request| {
            let site = Arc::clone(&site);
            let edge_app = edge_app.clone();
            let router_handle = router_handle.clone();
            let telemetry = telemetry.clone();
            async move {
                let (method_label, target_label) = request_labels(&request);
                let span = info_span!(
                    "velocity_http_request",
                    method = %method_label,
                    target = %target_label
                );
                let _guard = span.enter();
                telemetry.request_started();

                let telemetry_for_handler = telemetry.clone();

                if let Some(handle) = router_handle.as_ref() {
                    let raw_request = request.clone();
                    match EdgeRequest::from_pqq(raw_request) {
                        Ok(edge_request) => {
                            let router = handle.current();
                            if let Some(route) = router.resolve(
                                edge_request.host(),
                                edge_request.method(),
                                edge_request.path(),
                            ) {
                                if let Some(rebased) = edge_request.strip_prefix(&route.prefix) {
                                    match route.handler.handle(rebased).await {
                                        Ok(response) => {
                                            telemetry.request_finished();
                                            return response.into_transport_response();
                                        }
                                        Err(err) => {
                                            telemetry.request_finished();
                                            return EdgeResponse::from(err).into_transport_response();
                                        }
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            telemetry.request_finished();
                            return EdgeResponse::from(err).into_transport_response();
                        }
                    }
                }

                let response = if let Some(app) = edge_app.as_ref() {
                    let fallback = request.clone();
                    match app.handle(request).await {
                        Ok(response) => response,
                        Err(err) => match err {
                            EdgeError::NotFound { .. } => {
                                handle_request(site, fallback, telemetry_for_handler).await
                            }
                            other => {
                                warn!(target: "velocity::edge", error = %other, "edge handler failed");
                                EdgeResponse::from(other).into_transport_response()
                            }
                        },
                    }
                } else {
                    handle_request(site, request, telemetry_for_handler).await
                };

                telemetry.request_finished();
                response
            }
        });

        tokio::select! {
            res = serve_future => {
                if let Err(err) = res {
                    match err {
                        ServerError::Handshake(inner) => bail!("handshake failed: {inner}"),
                        other => return Err(other.into()),
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("shutdown signal received; terminating server");
            }
        }

        if let Some(handle) = https_handle.take() {
            handle
                .shutdown()
                .await
                .context("failed to shutdown HTTPS preview listener")?;
        }
    }

    if let Some(task) = router_watch_task.take() {
        if let Err(err) = task.await {
            warn!(
                target: "velocity::config",
                error = %err,
                "serve config watcher task terminated unexpectedly"
            );
        }
    }

    telemetry.shutdown().await?;

    Ok(())
}

fn resolve_serve_config_path(root: &Path, config: &Path) -> Result<PathBuf> {
    if config.is_absolute() {
        return Ok(config.to_path_buf());
    }

    let cwd = env::current_dir().context("failed to determine current working directory")?;
    let candidate = cwd.join(config);
    if candidate.exists() {
        return Ok(candidate.canonicalize().unwrap_or(candidate));
    }

    let fallback = resolve_config_path(root, config);
    if fallback.exists() {
        Ok(fallback.canonicalize().unwrap_or(fallback))
    } else {
        Ok(fallback)
    }
}

struct ResponseOutcome {
    response: Response,
    status: String,
    bytes: usize,
}

impl ResponseOutcome {
    fn finish(self, telemetry: &TelemetryHandle, method: &str) -> Response {
        let status_code = self
            .status
            .split_whitespace()
            .next()
            .unwrap_or("200")
            .to_string();
        telemetry.observe_http(method, &status_code, self.bytes);
        self.response
    }

    fn into_response(self) -> Response {
        self.response
    }
}

async fn handle_request(
    site: Arc<SiteConfig>,
    request: Request,
    telemetry: TelemetryHandle,
) -> Response {
    let line = match request.http_request_line() {
        Some(line) => line,
        None => {
            let outcome = http_text_response("400 Bad Request", "Malformed HTTP request");
            return outcome.finish(&telemetry, "UNKNOWN");
        }
    };

    let method = line.method.to_string();

    match build_response(site, request).await {
        Ok(outcome) => outcome.finish(&telemetry, &method),
        Err(err) => {
            let outcome = match err {
                SiteError::BadRequest => {
                    http_text_response("400 Bad Request", "Malformed HTTP request")
                }
                SiteError::Forbidden => {
                    http_text_response("403 Forbidden", "Directory traversal is not allowed")
                }
                SiteError::MethodNotAllowed(method) => http_text_response(
                    "405 Method Not Allowed",
                    format!("Method {method} is not supported"),
                ),
                SiteError::NotFound => http_text_response("404 Not Found", "Resource not found"),
                SiteError::Io(io_err) => {
                    error!(error = %io_err, "I/O error while serving request");
                    http_text_response("500 Internal Server Error", "Internal server error")
                }
                SiteError::InvalidPath => {
                    http_text_response("400 Bad Request", "Invalid request path")
                }
                SiteError::Utf8(_) => {
                    http_text_response("400 Bad Request", "Request target was not valid UTF-8")
                }
            };
            outcome.finish(&telemetry, &method)
        }
    }
}

async fn build_response(
    site: Arc<SiteConfig>,
    request: Request,
) -> Result<ResponseOutcome, SiteError> {
    let line = request.http_request_line().ok_or(SiteError::BadRequest)?;

    match line.method {
        "GET" | "HEAD" => {}
        method => return Err(SiteError::MethodNotAllowed(method.to_string())),
    }

    let normalized = normalize_target(line.target)?;
    let full_path = site.root.join(&normalized);
    let metadata = tokio::fs::metadata(&full_path).await.map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            SiteError::NotFound
        } else {
            SiteError::Io(err)
        }
    })?;

    if metadata.is_dir() {
        return handle_directory(site, &full_path, line.method).await;
    }

    let body = tokio::fs::read(&full_path).await.map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            SiteError::NotFound
        } else {
            SiteError::Io(err)
        }
    })?;

    let mime = mime_guess::from_path(&full_path).first_or_octet_stream();
    Ok(http_response("200 OK", mime, &body, line.method == "HEAD"))
}

async fn handle_directory(
    site: Arc<SiteConfig>,
    dir: &Path,
    method: &str,
) -> Result<ResponseOutcome, SiteError> {
    let index_path = dir.join(&site.index);
    if tokio::fs::metadata(&index_path)
        .await
        .map(|meta| meta.is_file())
        .unwrap_or(false)
    {
        let bytes = tokio::fs::read(&index_path).await.map_err(SiteError::Io)?;
        let mime = mime_guess::from_path(&index_path).first_or_octet_stream();
        return Ok(http_response("200 OK", mime, &bytes, method == "HEAD"));
    }

    if !site.listings {
        return Err(SiteError::NotFound);
    }

    let listing = render_directory_listing(dir).await?;
    Ok(http_response(
        "200 OK",
        "text/html; charset=utf-8"
            .parse()
            .expect("valid text/html mime"),
        listing.as_bytes(),
        method == "HEAD",
    ))
}

fn build_serve_router(config: ServeConfig, base_root: &Path) -> Result<Arc<ServeRouter>> {
    let router = ServeRouter::from_config(config, base_root)
        .map_err(|err| anyhow::anyhow!("failed to build serve router: {err}"))?;
    Ok(Arc::new(router))
}

fn spawn_router_watcher(
    path: PathBuf,
    base_root: PathBuf,
    controller: ServeRouterController,
    overrides: Option<ConfigOverrides>,
) -> Result<JoinHandle<()>> {
    Ok(tokio::spawn(async move {
        if let Err(err) = watch_router_config(path, base_root, controller, overrides).await {
            warn!(target: "velocity::config", error = %err, "serve config watcher exited");
        }
    }))
}

async fn watch_router_config(
    path: PathBuf,
    base_root: PathBuf,
    controller: ServeRouterController,
    overrides: Option<ConfigOverrides>,
) -> Result<()> {
    let (event_tx, mut event_rx) = mpsc::channel(16);
    let mut watcher = RecommendedWatcher::new(
        {
            let event_tx = event_tx.clone();
            move |res| {
                let _ = event_tx.blocking_send(res);
            }
        },
        NotifyConfig::default(),
    )
    .with_context(|| format!("failed to watch serve config {}", path.display()))?;

    watcher
        .watch(path.as_path(), RecursiveMode::NonRecursive)
        .with_context(|| format!("failed to register watcher for {}", path.display()))?;

    while let Some(event) = event_rx.recv().await {
        match event {
            Ok(event) => {
                if should_reload(&event.kind) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    match load_combined_config(&path).await {
                        Ok(bundle) => {
                            if let (Some(expected), Some(current)) =
                                (overrides.clone(), bundle.overrides.clone())
                            {
                                if current != expected {
                                    warn!(
                                        target: "velocity::config",
                                        file = %path.display(),
                                        "serve config overrides changed; restart Velocity to apply"
                                    );
                                }
                            }

                            match build_serve_router(bundle.router, &base_root) {
                                Ok(router) => {
                                    if let Err(err) = controller.update(router) {
                                        warn!(
                                            target: "velocity::config",
                                            error = %err,
                                            "failed to publish reloaded router"
                                        );
                                    } else {
                                        info!(
                                            target: "velocity::config",
                                            file = %path.display(),
                                            "serve configuration reloaded"
                                        );
                                    }
                                }
                                Err(err) => warn!(
                                    target: "velocity::config",
                                    error = %err,
                                    file = %path.display(),
                                    "serve router rebuild failed"
                                ),
                            }
                        }
                        Err(err) => warn!(
                            target: "velocity::config",
                            error = %err,
                            file = %path.display(),
                            "failed to reload serve configuration"
                        ),
                    }
                }
            }
            Err(err) => warn!(
                target: "velocity::config",
                error = %err,
                file = %path.display(),
                "serve config watch event failed"
            ),
        }
    }

    Ok(())
}

fn should_reload(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::Create(_)
            | EventKind::Modify(ModifyKind::Name(_))
            | EventKind::Modify(ModifyKind::Data(_))
    )
}

async fn render_directory_listing(dir: &Path) -> Result<String, SiteError> {
    let mut entries = tokio::fs::read_dir(dir).await.map_err(SiteError::Io)?;
    let mut items: Vec<ListingItem> = Vec::new();

    while let Some(entry) = entries.next_entry().await.map_err(SiteError::Io)? {
        let file_type = entry.file_type().await.map_err(SiteError::Io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SiteError::InvalidPath)?;
        items.push(ListingItem {
            name,
            is_dir: file_type.is_dir(),
        });
    }

    items.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    let mut body = String::from(
        "<html><head><title>Directory listing</title><style>body{font-family:system-ui;margin:2rem;}table{width:100%;border-collapse:collapse;}th,td{padding:0.5rem;text-align:left;border-bottom:1px solid #ddd;}th{background:#f5f5f5;}</style></head><body>",
    );
    body.push_str("<h1>Index of ");
    body.push_str(&encode_text(&dir.display().to_string()));
    body.push_str("</h1><table><tr><th>Name</th><th>Type</th></tr>");

    for item in items {
        let href = encode_double_quoted_attribute(&item.name);
        let display = encode_text(&item.name);
        let kind = if item.is_dir { "Directory" } else { "File" };
        let _ = FmtWrite::write_fmt(
            &mut body,
            format_args!(
                "<tr><td><a href=\"{href}\">{display}</a></td><td>{kind}</td></tr>",
                href = href,
                display = display,
                kind = kind
            ),
        );
    }

    body.push_str("</table></body></html>");
    Ok(body)
}

fn http_response(status: &str, mime: Mime, body: &[u8], head: bool) -> ResponseOutcome {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    )
    .into_bytes();

    if !head {
        response.extend_from_slice(body);
    }

    ResponseOutcome {
        response: Response::from_bytes(response),
        status: status.to_string(),
        bytes: body.len(),
    }
}

fn http_text_response(status: &str, message: impl Into<Cow<'static, str>>) -> ResponseOutcome {
    let body = message.into();
    let mime = "text/plain; charset=utf-8"
        .parse()
        .expect("valid text/plain mime");
    http_response(status, mime, body.as_bytes(), false)
}

fn request_labels(request: &Request) -> (String, String) {
    if let Some(line) = request.http_request_line() {
        (line.method.to_string(), line.target.to_string())
    } else {
        ("UNKNOWN".to_string(), "<opaque>".to_string())
    }
}

fn normalize_target(target: &str) -> Result<PathBuf, SiteError> {
    let clean = target.split('?').next().unwrap_or(target);
    let decoded = percent_decode_str(clean)
        .decode_utf8()
        .map_err(SiteError::Utf8)?;
    let path = decoded.trim_matches('/');

    let mut normalized = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(segment) => normalized.push(segment),
            Component::ParentDir | Component::Prefix(_) => return Err(SiteError::Forbidden),
        }
    }

    Ok(normalized)
}

fn run_deploy(args: &DeployArgs) -> Result<()> {
    if !args.source.exists() {
        bail!("source directory {} does not exist", args.source.display());
    }

    if args.clean && args.output.exists() {
        fs::remove_dir_all(&args.output)
            .with_context(|| format!("failed to remove {}", args.output.display()))?;
    }

    fs::create_dir_all(&args.output)
        .with_context(|| format!("failed to create {}", args.output.display()))?;

    let mut summary = DeploymentSummary::default();
    let mut manifest_entries = Vec::new();

    for entry in WalkDir::new(&args.source) {
        let entry = entry?;
        let src_path = entry.path();
        let rel = match src_path.strip_prefix(&args.source) {
            Ok(r) if r.as_os_str().is_empty() => continue,
            Ok(r) => r,
            Err(_) => continue,
        };

        let dst_path = args.output.join(rel);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&dst_path)
                .with_context(|| format!("failed to create directory {}", dst_path.display()))?;
            continue;
        }

        if let Some(parent) = dst_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }

        fs::copy(src_path, &dst_path)
            .with_context(|| format!("failed to copy {}", src_path.display()))?;

        let size = entry.metadata()?.len();
        summary.files += 1;
        summary.bytes += size;
        manifest_entries.push(ManifestEntry {
            path: rel.to_string_lossy().into_owned(),
            bytes: size,
        });
    }

    if args.manifest {
        let manifest = DeploymentManifest {
            source: args.source.to_string_lossy().into_owned(),
            output: args.output.to_string_lossy().into_owned(),
            files: manifest_entries,
            total_bytes: summary.bytes,
        };
        let manifest_path = args.output.join("velocity-manifest.json");
        let json = serde_json::to_vec_pretty(&manifest)?;
        fs::write(&manifest_path, json)
            .with_context(|| format!("failed to write {}", manifest_path.display()))?;
        info!(path = %manifest_path.display(), "wrote deployment manifest");
    }

    info!(
        files = summary.files,
        bytes = summary.bytes,
        target = %args.output.display(),
        "deployment bundle ready"
    );
    println!(
        "Deployed {} files ({:.2} KiB) to {}",
        summary.files,
        summary.bytes as f64 / 1024.0,
        args.output.display()
    );
    Ok(())
}

fn run_init(args: &InitArgs) -> Result<()> {
    fs::create_dir_all(&args.dir)
        .with_context(|| format!("failed to create {}", args.dir.display()))?;

    let files = [
        (args.dir.join("index.html"), INDEX_HTML),
        (args.dir.join("styles.css"), STYLES_CSS),
        (args.dir.join("app.js"), APP_JS),
    ];

    for (path, contents) in files {
        if path.exists() && !args.force {
            warn!(path = %path.display(), "skipping existing file");
            continue;
        }
        fs::write(&path, contents)
            .with_context(|| format!("failed to write {}", path.display()))?;
        info!(path = %path.display(), "created file");
    }

    println!(
        "Starter site ready at {}. Try: velocity serve --root {}",
        args.dir.display(),
        args.dir.display()
    );

    Ok(())
}

fn generate_self_signed_cert(root: &Path, domain: &str) -> Result<SelfSignedMaterial> {
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![domain.to_string()])?;
    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();

    let cert_dir = root.join(".velocity").join("certs");
    fs::create_dir_all(&cert_dir)
        .with_context(|| format!("failed to create {}", cert_dir.display()))?;

    let cert_path = cert_dir.join("self-signed-cert.pem");
    let key_path = cert_dir.join("self-signed-key.pem");
    fs::write(&cert_path, cert_pem)
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    fs::write(&key_path, key_pem)
        .with_context(|| format!("failed to write {}", key_path.display()))?;

    info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        domain,
        "generated self-signed certificate"
    );

    Ok(SelfSignedMaterial {
        cert_path,
        key_path,
    })
}

#[derive(Debug)]
struct SiteConfig {
    root: PathBuf,
    index: String,
    listings: bool,
}

#[derive(Debug, Error)]
enum SiteError {
    #[error("bad request")]
    BadRequest,
    #[error("method not allowed: {0}")]
    MethodNotAllowed(String),
    #[error("resource not found")]
    NotFound,
    #[error("invalid UTF-8 in request path: {0}")]
    Utf8(#[source] std::str::Utf8Error),
    #[error("invalid request path")]
    InvalidPath,
    #[error("directory traversal attempt")]
    Forbidden,
    #[error("io error: {0}")]
    Io(#[source] io::Error),
}

#[derive(Debug, Default)]
struct DeploymentSummary {
    files: usize,
    bytes: u64,
}

#[derive(Debug, Serialize)]
struct DeploymentManifest {
    source: String,
    output: String,
    files: Vec<ManifestEntry>,
    total_bytes: u64,
}

#[derive(Debug, Serialize)]
struct ManifestEntry {
    path: String,
    bytes: u64,
}

#[derive(Debug)]
struct SelfSignedMaterial {
    cert_path: PathBuf,
    key_path: PathBuf,
}

#[derive(Debug)]
struct ListingItem {
    name: String,
    is_dir: bool,
}

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Velocity • Hello World</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <main>
        <h1>Velocity is live!</h1>
        <p>If you can see this page, the Velocity CLI static server is running.</p>
        <section>
            <h2>Next steps</h2>
            <ul>
                <li>Drop your static assets into this folder.</li>
                <li>Run <code>velocity serve --root public</code> to serve them with post-quantum transport.</li>
                <li>Use <code>velocity deploy</code> to copy files into a production-ready bundle.</li>
            </ul>
        </section>
        <footer>Powered by the Velocity reference implementation.</footer>
    </main>
    <script src="app.js"></script>
</body>
</html>"#;

const STYLES_CSS: &str = r#"body{font-family:system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:0;}main{max-width:720px;margin:4rem auto;padding:2rem;background:#161b22;border-radius:16px;box-shadow:0 30px 80px rgba(0,0,0,0.25);}h1{font-size:2.5rem;margin-bottom:1rem;}h2{margin-top:2rem;}ul{line-height:1.6;}code{background:#1f2937;padding:0.15rem 0.4rem;border-radius:0.4rem;}footer{margin-top:3rem;font-size:0.85rem;color:#8b949e;text-align:right;}"#;

const APP_JS: &str = r#"document.addEventListener('DOMContentLoaded', () => {
    console.log('Velocity static site ready.');
});"#;

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn normalize_target_allows_simple_paths() {
        let path = normalize_target("/assets/app.js").expect("sanitize");
        assert_eq!(path, PathBuf::from("assets").join("app.js"));
    }

    #[test]
    fn normalize_target_rejects_traversal() {
        let err = normalize_target("/../secret").unwrap_err();
        assert!(matches!(err, SiteError::Forbidden));
    }

    #[test]
    fn normalize_target_handles_root() {
        let path = normalize_target("/").expect("sanitize");
        assert!(path.as_os_str().is_empty());
    }

    #[test]
    fn normalize_target_rejects_invalid_utf8() {
        let err = normalize_target("/%FF").unwrap_err();
        assert!(matches!(err, SiteError::Utf8(_)));
    }

    #[test]
    fn encode_chunk_formats_hex_length() {
        let chunk = Bytes::from_static(b"hello");
        let encoded = super::encode_chunk(&chunk);
        assert_eq!(encoded.as_ref(), b"5\r\nhello\r\n");
    }

    #[test]
    fn streaming_head_includes_transfer_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-test"),
            HeaderValue::from_static("ok"),
        );
        let head = super::build_streaming_head(StatusCode::OK, &headers);
        let text = String::from_utf8(head).expect("utf8");
        assert!(text.contains("Transfer-Encoding: chunked"));
        assert!(text.contains("Connection: keep-alive"));
        assert!(text.contains("x-test: ok"));
    }

    #[derive(Debug)]
    struct FakeError {
        msg: &'static str,
        source: Option<Box<dyn StdError + Send + Sync>>,
    }

    impl FakeError {
        fn new(msg: &'static str) -> Self {
            Self { msg, source: None }
        }

        fn with_source(msg: &'static str, source: Box<dyn StdError + Send + Sync>) -> Self {
            Self {
                msg,
                source: Some(source),
            }
        }
    }

    impl std::fmt::Display for FakeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.msg)
        }
    }

    impl StdError for FakeError {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            self.source
                .as_ref()
                .map(|inner| inner.as_ref() as &(dyn StdError + 'static))
        }
    }

    #[test]
    fn tls_failure_hint_detects_certificate_errors() {
        let leaf = FakeError::new("invalid certificate: UnknownIssuer");
        let err = FakeError::with_source("error trying to connect", Box::new(leaf));
        let hint = super::tls_failure_hint(&err).expect("tls hint");
        assert!(hint.to_ascii_lowercase().contains("certificate"));
    }

    #[test]
    fn tls_failure_hint_skips_non_tls_errors() {
        let err = FakeError::new("connection refused");
        assert!(super::tls_failure_hint(&err).is_none());
    }
}
