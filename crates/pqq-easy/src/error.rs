use std::{io, net::AddrParseError, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EasyError {
    #[error("missing server address in configuration")]
    MissingServerAddress,
    #[error("invalid server address: {0}")]
    InvalidAddress(#[from] AddrParseError),
    #[error("missing server KEM public key")]
    MissingServerKey,
    #[error("failed to decode base64 key: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("tokio runtime error: {0}")]
    RuntimeCreation(String),
    #[error("http request failed: {0}")]
    Request(anyhow::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("unsupported security profile: {0}")]
    UnknownProfile(String),
    #[error("no cached key found for host {host:?} in {path:?}")]
    MissingCachedKey { host: String, path: PathBuf },
    #[error("no fallback strategy available")]
    FallbackDisabled,
    #[error("fallback request failed: {0}")]
    FallbackHttp(String),
    #[error("fallback returned unexpected status {code} for {url}")]
    FallbackStatus { code: u16, url: String },
    #[error("fallback attempts exhausted")]
    FallbackExhausted,
    #[error("failed to auto-discover server key: {0}")]
    AutodiscoveryFailed(String),
}

impl EasyError {
    pub fn runtime(err: impl ToString) -> Self {
        EasyError::RuntimeCreation(err.to_string())
    }

    pub fn request(err: impl Into<anyhow::Error>) -> Self {
        EasyError::Request(err.into())
    }
}
