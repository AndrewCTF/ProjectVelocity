use std::time::Duration;

use async_trait::async_trait;
use http::header::{HeaderName, CONTENT_LENGTH, HOST};
use http::{Method, StatusCode};
use reqwest::{Client, Method as ReqwestMethod, Url};

use crate::config::ProxyTargetConfig;
use crate::error::{EdgeError, EdgeResult};
use crate::request::EdgeRequest;
use crate::response::EdgeResponse;

use super::ServeHandler;

#[derive(Debug, Clone)]
pub struct ProxyTuning {
    pub connect_timeout: Duration,
    pub response_timeout: Duration,
    pub idle_timeout: Duration,
    pub tcp_keepalive: Duration,
    pub streaming: bool,
}

impl ProxyTuning {
    pub fn from_config(config: &ProxyTargetConfig) -> EdgeResult<Self> {
        Ok(Self {
            connect_timeout: humantime::parse_duration(&config.connect_timeout).map_err(|err| {
                EdgeError::Config(format!(
                    "invalid proxy connect_timeout '{}': {err}",
                    config.connect_timeout
                ))
            })?,
            response_timeout: humantime::parse_duration(&config.response_timeout).map_err(
                |err| {
                    EdgeError::Config(format!(
                        "invalid proxy response_timeout '{}': {err}",
                        config.response_timeout
                    ))
                },
            )?,
            idle_timeout: humantime::parse_duration(&config.idle_timeout).map_err(|err| {
                EdgeError::Config(format!(
                    "invalid proxy idle_timeout '{}': {err}",
                    config.idle_timeout
                ))
            })?,
            tcp_keepalive: humantime::parse_duration(&config.tcp_keepalive).map_err(|err| {
                EdgeError::Config(format!(
                    "invalid proxy tcp_keepalive '{}': {err}",
                    config.tcp_keepalive
                ))
            })?,
            streaming: config.streaming,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ProxyHandler {
    client: Client,
    upstream: Url,
    preserve_host: bool,
    tuning: ProxyTuning,
}

impl ProxyHandler {
    pub fn new(config: &ProxyTargetConfig) -> EdgeResult<Self> {
        let mut upstream = Url::parse(&config.origin)
            .map_err(|err| EdgeError::Config(format!("invalid proxy origin: {err}")))?;
        if upstream.path().is_empty() {
            upstream.set_path("/");
        }
        if !upstream.path().ends_with('/') {
            let mut path = upstream.path().to_string();
            path.push('/');
            upstream.set_path(&path);
        }

        let tuning = ProxyTuning::from_config(config)?;
        let client = Client::builder()
            .http1_only()
            .pool_idle_timeout(Some(tuning.idle_timeout))
            .connect_timeout(tuning.connect_timeout)
            .timeout(tuning.response_timeout)
            .tcp_keepalive(Some(tuning.tcp_keepalive))
            .build()
            .map_err(|err| EdgeError::Config(format!("failed to build proxy client: {err}")))?;

        Ok(Self {
            client,
            upstream,
            preserve_host: config.preserve_host,
            tuning,
        })
    }
}

#[async_trait]
impl ServeHandler for ProxyHandler {
    async fn handle(&self, request: EdgeRequest) -> EdgeResult<EdgeResponse> {
        let target = request.target();
        if target.starts_with("http://") || target.starts_with("https://") {
            return Err(EdgeError::BadRequest(
                "absolute-form request targets are not allowed in proxy mode".into(),
            ));
        }

        let url = self
            .upstream
            .join(target)
            .map_err(|err| EdgeError::BadRequest(format!("invalid request target: {err}")))?;

        let method = ReqwestMethod::from_bytes(request.method().as_str().as_bytes())
            .map_err(|_| EdgeError::BadRequest("unsupported HTTP method for proxy".into()))?;

        let mut builder = self.client.request(method, url);

        let mut saw_host = false;
        for (name, value) in request.headers().iter() {
            if is_hop_by_hop(name) {
                continue;
            }
            if name == HOST {
                saw_host = true;
                if self.preserve_host {
                    builder = builder.header(name, value);
                }
                continue;
            }
            if name == CONTENT_LENGTH {
                continue;
            }
            builder = builder.header(name, value);
        }

        if !self.preserve_host {
            if let Some(host) = self.upstream.host_str() {
                let mut host_value = host.to_string();
                if let Some(port) = self.upstream.port() {
                    host_value.push(':');
                    host_value.push_str(&port.to_string());
                }
                builder = builder.header(HOST, host_value);
            }
        } else if !saw_host {
            if let Some(host) = request.host() {
                builder = builder.header(HOST, host);
            }
        }

        if !request.body().is_empty() {
            builder = builder.body(request.body_bytes());
        }

        let upstream_response = builder.send().await.map_err(EdgeError::Upstream)?;
        let status = upstream_response.status();
        let mut response = EdgeResponse::new(status);

        for (name, value) in upstream_response.headers().iter() {
            if is_hop_by_hop(name) {
                continue;
            }
            response.set_header(name.clone(), value.clone());
        }

        if request.method() == Method::HEAD
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::NOT_MODIFIED
        {
            return Ok(response);
        }

        let streaming = self.tuning.streaming;
        let body = upstream_response
            .bytes()
            .await
            .map_err(EdgeError::Upstream)?;

        if streaming {
            // TODO: Support true streaming responses once EdgeResponse exposes streaming APIs.
        }

        Ok(response.with_body(body))
    }
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    let name = name.as_str();
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
}
