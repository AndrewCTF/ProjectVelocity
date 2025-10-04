use std::{net::SocketAddr, path::PathBuf, thread, time::Duration};

use pqq_client::{extract_kem_public, Client, ClientConfig, ClientSession};
use pqq_core::{
    build_initial_packet, decode_handshake_response, AlpnResolution, ChunkAssembler,
    FallbackDirective, FrameSequencer, HandshakeError, FRAME_HEADER_LEN, FRAME_MAX_PAYLOAD,
    HANDSHAKE_MESSAGE_MAX,
};
use pqq_tls::SecurityProfile;
use reqwest::blocking::Client as BlockingHttpClient;
use reqwest::redirect::Policy;
use tokio::net::UdpSocket;
use tokio::runtime::{Builder, Runtime};

use crate::error::EasyError;
use crate::util::{
    cache_dir_override, decode_base64_key, load_cached_key, profile_from_str, store_cached_key,
};

const DEFAULT_CLIENT_ALPNS: &[&str] = &["velocity/1", "pqq/1", "h3"];

#[derive(Clone, Debug)]
pub struct EasyFallbackOptions {
    pub enabled: bool,
    pub force_http1: bool,
    pub retries: u32,
    pub base_url_override: Option<String>,
    pub request_timeout: Duration,
    pub initial_backoff: Duration,
}

impl EasyFallbackOptions {
    fn backoff_delay(&self, attempt: u32) -> Duration {
        self.initial_backoff
            .checked_mul(attempt.saturating_add(1))
            .unwrap_or(self.request_timeout)
    }
}

impl Default for EasyFallbackOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            force_http1: true,
            retries: 2,
            base_url_override: None,
            request_timeout: Duration::from_secs(5),
            initial_backoff: Duration::from_millis(200),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EasyClientConfig {
    pub server_addr: SocketAddr,
    pub hostname: String,
    pub profile: SecurityProfile,
    pub server_kem_key: Vec<u8>,
    pub cache: bool,
    pub cache_dir: Option<PathBuf>,
    pub fallback: EasyFallbackOptions,
}

impl EasyClientConfig {
    pub fn builder() -> EasyClientBuilder {
        EasyClientBuilder::default()
    }

    pub fn from_base64(
        server_addr: SocketAddr,
        hostname: impl Into<String>,
        profile: SecurityProfile,
        key_b64: &str,
    ) -> Result<Self, EasyError> {
        let key = decode_base64_key(key_b64)?;
        Ok(Self {
            server_addr,
            hostname: hostname.into(),
            profile,
            server_kem_key: key,
            cache: false,
            cache_dir: None,
            fallback: EasyFallbackOptions::default(),
        })
    }
}

pub struct EasyClientBuilder {
    server_addr: Option<SocketAddr>,
    hostname: Option<String>,
    profile: Option<SecurityProfile>,
    server_key: Option<Vec<u8>>,
    key_from_cache: Option<String>,
    cache_key: bool,
    cache_dir: Option<PathBuf>,
    fallback: EasyFallbackOptions,
    autodiscover: bool,
}

impl Default for EasyClientBuilder {
    fn default() -> Self {
        Self {
            server_addr: None,
            hostname: None,
            profile: None,
            server_key: None,
            key_from_cache: None,
            cache_key: false,
            cache_dir: None,
            fallback: EasyFallbackOptions::default(),
            autodiscover: true,
        }
    }
}

impl EasyClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn server_addr(mut self, addr: impl AsRef<str>) -> Result<Self, EasyError> {
        self.server_addr = Some(addr.as_ref().parse()?);
        Ok(self)
    }

    pub fn hostname(mut self, host: impl Into<String>) -> Self {
        self.hostname = Some(host.into());
        self
    }

    pub fn security_profile(mut self, profile: SecurityProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    pub fn security_profile_str(self, label: impl AsRef<str>) -> Result<Self, EasyError> {
        let profile = profile_from_str(label.as_ref())?;
        Ok(self.security_profile(profile))
    }

    pub fn server_key_bytes(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.server_key = Some(key.into());
        self
    }

    pub fn server_key_base64(self, key_b64: &str) -> Result<Self, EasyError> {
        let key = decode_base64_key(key_b64)?;
        Ok(self.server_key_bytes(key))
    }

    pub fn server_key_cache(mut self, host: impl Into<String>) -> Self {
        self.key_from_cache = Some(host.into());
        self
    }

    pub fn cache_key(mut self, cache: bool) -> Self {
        self.cache_key = cache;
        self
    }

    pub fn cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cache_dir = Some(dir.into());
        self
    }

    pub fn server_key_autodiscover(mut self, enable: bool) -> Self {
        self.autodiscover = enable;
        self
    }

    pub fn disable_fallback(mut self) -> Self {
        self.fallback.enabled = false;
        self
    }

    pub fn fallback_http1_only(mut self, force: bool) -> Self {
        self.fallback.force_http1 = force;
        self
    }

    pub fn fallback_retries(mut self, retries: u32) -> Self {
        self.fallback.retries = retries;
        self
    }

    pub fn fallback_timeout(mut self, timeout: Duration) -> Self {
        self.fallback.request_timeout = timeout;
        self
    }

    pub fn fallback_initial_backoff(mut self, backoff: Duration) -> Self {
        self.fallback.initial_backoff = backoff;
        self
    }

    pub fn fallback_base_url(mut self, url: impl Into<String>) -> Self {
        self.fallback.base_url_override = Some(url.into());
        self
    }

    pub fn build(mut self) -> Result<EasyClientConfig, EasyError> {
        let server_addr = self.server_addr.ok_or(EasyError::MissingServerAddress)?;
        let hostname = self.hostname.unwrap_or_else(|| server_addr.to_string());
        let profile = self.profile.unwrap_or(SecurityProfile::Balanced);

        let server_kem_key = if let Some(key) = self.server_key.take() {
            key
        } else if let Some(host) = self.key_from_cache.take() {
            let cache_dir = self.cache_dir.clone().or_else(cache_dir_override);
            load_cached_key(&host, cache_dir.as_deref()).map_err(|_| EasyError::MissingServerKey)?
        } else if self.autodiscover {
            autodiscover_server_key(server_addr)?
        } else {
            return Err(EasyError::MissingServerKey);
        };

        Ok(EasyClientConfig {
            server_addr,
            hostname,
            profile,
            server_kem_key,
            cache: self.cache_key,
            cache_dir: self.cache_dir,
            fallback: self.fallback,
        })
    }
}

pub struct EasyClient {
    runtime: Option<Runtime>,
    client: Client,
    base_url: String,
    fallback: EasyFallbackOptions,
}

impl EasyClient {
    pub fn connect(config: EasyClientConfig) -> Result<Self, EasyError> {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .thread_name("velocity-easy-client")
            .build()
            .map_err(EasyError::runtime)?;

        let mut client_config = ClientConfig::new(config.server_addr)
            .with_security_profile(config.profile)
            .with_server_kem_public(config.server_kem_key.clone());
        client_config.handshake = client_config
            .handshake
            .with_supported_alpns(DEFAULT_CLIENT_ALPNS.iter().copied());

        let client = Client::new(client_config);
        let base_url = format!("https://{}", config.hostname);

        if config.cache {
            let dir = config
                .cache_dir
                .clone()
                .or_else(cache_dir_override)
                .unwrap_or_else(crate::util::default_cache_dir);
            let _ = store_cached_key(
                &config.hostname,
                &config.server_kem_key,
                Some(dir.as_path()),
            );
        }

        Ok(Self {
            runtime: Some(runtime),
            client,
            base_url,
            fallback: config.fallback,
        })
    }

    pub fn fetch_text(&self, path: &str) -> Result<String, EasyError> {
        let url = compose_url(&self.base_url, path);
        match self.runtime().block_on(self.client.get(&url)) {
            Ok(body) => Ok(body),
            Err(err) => self.perform_fallback(path, err),
        }
    }

    pub fn fetch_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, EasyError> {
        let body = self.fetch_text(path)?;
        Ok(serde_json::from_str(&body)?)
    }

    pub fn open_session(&self) -> Result<ClientSession, EasyError> {
        self.runtime()
            .block_on(self.client.connect())
            .map_err(EasyError::request)
    }

    pub fn probe(&self) -> Result<pqq_core::HandshakeResponse, EasyError> {
        self.runtime()
            .block_on(self.client.probe())
            .map_err(EasyError::request)
    }
}

impl EasyClient {
    fn runtime(&self) -> &Runtime {
        self.runtime
            .as_ref()
            .expect("EasyClient runtime should be available")
    }

    fn perform_fallback(
        &self,
        path: &str,
        origin_err: pqq_client::ClientError,
    ) -> Result<String, EasyError> {
        eprintln!("fallback invoked due to client error: {origin_err}");
        if !self.fallback.enabled {
            return Err(EasyError::request(origin_err));
        }

        let directive = match &origin_err {
            pqq_client::ClientError::AlpnFallback(response)
            | pqq_client::ClientError::AlpnUnsupported(response) => response.fallback.clone(),
            _ => None,
        };

        let base_url = self
            .fallback
            .base_url_override
            .clone()
            .or_else(|| directive.as_ref().map(fallback_base_url))
            .unwrap_or_else(|| self.base_url.clone());

        let target_url = compose_url(&base_url, path);
        let client = self.build_fallback_http_client()?;
        let mut last_error: Option<EasyError> = None;
        for attempt in 0..=self.fallback.retries {
            match client.get(&target_url).send() {
                Ok(response) => {
                    if response.status().is_success() {
                        return response
                            .text()
                            .map_err(|err| EasyError::FallbackHttp(err.to_string()));
                    } else {
                        last_error = Some(EasyError::FallbackStatus {
                            code: response.status().as_u16(),
                            url: target_url.clone(),
                        });
                    }
                }
                Err(err) => {
                    last_error = Some(EasyError::FallbackHttp(err.to_string()));
                }
            }

            if attempt < self.fallback.retries {
                thread::sleep(self.fallback.backoff_delay(attempt));
            }
        }

        Err(last_error.unwrap_or_else(|| EasyError::request(origin_err)))
    }

    fn build_fallback_http_client(&self) -> Result<BlockingHttpClient, EasyError> {
        let mut builder = BlockingHttpClient::builder()
            .timeout(self.fallback.request_timeout)
            .redirect(Policy::limited(5));
        if self.fallback.force_http1 {
            builder = builder.http1_only();
        }
        builder
            .build()
            .map_err(|err| EasyError::FallbackHttp(err.to_string()))
    }
}

fn compose_url(base_url: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else if path.starts_with('/') {
        format!("{}{}", base_url, path)
    } else {
        format!("{}/{}", base_url, path)
    }
}

fn fallback_base_url(directive: &FallbackDirective) -> String {
    let host = if directive.host.contains(':') && !directive.host.contains(']') {
        format!("[{}]", directive.host)
    } else {
        directive.host.clone()
    };
    format!("https://{}:{}", host, directive.port)
}

impl Drop for EasyClient {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

fn autodiscover_server_key(addr: SocketAddr) -> Result<Vec<u8>, EasyError> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .thread_name("velocity-easy-autodiscover")
        .build()
        .map_err(EasyError::runtime)?;

    let outcome = runtime.block_on(async move {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(addr).await?;

        let packet = build_initial_packet(DEFAULT_CLIENT_ALPNS.iter().copied());
        socket.send(&packet).await?;

        const HANDSHAKE_FRAME_CAPACITY: usize = FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD;
        let mut frame_buf = [0u8; HANDSHAKE_FRAME_CAPACITY];
        let mut framing = FrameSequencer::new(0, 0);
        let mut assembler = ChunkAssembler::new(HANDSHAKE_MESSAGE_MAX);
        let response_bytes = loop {
            let len = socket.recv(&mut frame_buf).await?;
            let slice = match framing.decode(&frame_buf[..len]) {
                Ok(slice) => slice,
                Err(err) => {
                    return Err(EasyError::AutodiscoveryFailed(
                        HandshakeError::Frame(err).to_string(),
                    ));
                }
            };
            match assembler.push_slice(slice) {
                Ok(Some(message)) => break message,
                Ok(None) => continue,
                Err(err) => {
                    return Err(EasyError::AutodiscoveryFailed(
                        HandshakeError::Frame(err).to_string(),
                    ));
                }
            }
        };

        let response = decode_handshake_response(&response_bytes)
            .map_err(|err| EasyError::AutodiscoveryFailed(err.to_string()))?;

        match response.resolution {
            AlpnResolution::Supported(_) => extract_kem_public(&response).ok_or_else(|| {
                EasyError::AutodiscoveryFailed(
                    "server did not publish an ML-KEM public key; start the server with --publish-kem".to_string(),
                )
            }),
            AlpnResolution::Fallback(_) => {
                let note = response
                    .fallback
                    .map(|d| format!("{}://{}:{}", d.alpn, d.host, d.port))
                    .unwrap_or_else(|| "an unspecified endpoint".to_string());
                Err(EasyError::AutodiscoveryFailed(format!(
                    "server requested fallback via {note}"
                )))
            }
            AlpnResolution::Unsupported => Err(EasyError::AutodiscoveryFailed(
                "server does not support Velocity ALPN values".to_string(),
            )),
        }
    });

    drop(runtime);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_missing_key() {
        crate::util::set_cache_dir_override(None);
        let err = EasyClientConfig::builder()
            .server_addr("127.0.0.1:443")
            .unwrap()
            .hostname("example.com")
            .server_key_autodiscover(false)
            .build()
            .unwrap_err();
        assert!(matches!(err, EasyError::MissingServerKey));
    }

    #[test]
    fn compose_url_variants() {
        let base_url = "https://example.com";

        assert_eq!(compose_url(base_url, "/hello"), "https://example.com/hello");
        assert_eq!(compose_url(base_url, "hello"), "https://example.com/hello");
        assert_eq!(
            compose_url(base_url, "https://other/abc"),
            "https://other/abc"
        );
    }

    #[test]
    fn fallback_base_url_formats_https() {
        let directive = FallbackDirective {
            alpn: "h3".into(),
            host: "fallback.example".into(),
            port: 444,
            note: None,
        };
        assert_eq!(
            fallback_base_url(&directive),
            "https://fallback.example:444"
        );
    }

    #[test]
    fn fallback_base_url_wraps_ipv6() {
        let directive = FallbackDirective {
            alpn: "h3".into(),
            host: "::1".into(),
            port: 8443,
            note: None,
        };
        assert_eq!(fallback_base_url(&directive), "https://[::1]:8443");
    }
}
