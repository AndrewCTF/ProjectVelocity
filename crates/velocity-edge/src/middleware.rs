use std::collections::HashMap;

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};

use crate::{error::EdgeResult, request::EdgeRequest, response::EdgeResponse};

#[async_trait]
pub trait EdgeMiddleware: Send + Sync {
    async fn before(&self, _request: &EdgeRequest) -> EdgeResult<()> {
        Ok(())
    }

    async fn after(&self, _request: &EdgeRequest, _response: &mut EdgeResponse) -> EdgeResult<()> {
        Ok(())
    }
}

/// Middleware that injects recommended security headers into every response.
#[derive(Default, Clone)]
pub struct SecurityHeadersMiddleware {
    headers: HashMap<HeaderName, HeaderValue>,
}

impl SecurityHeadersMiddleware {
    pub fn new() -> Self {
        let mut headers = HashMap::new();
        headers.insert(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
        headers.insert(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        );
        headers.insert(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("0"),
        );
        headers.insert(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'self'"),
        );
        headers.insert(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        );
        Self { headers }
    }
}

#[async_trait]
impl EdgeMiddleware for SecurityHeadersMiddleware {
    async fn after(&self, _request: &EdgeRequest, response: &mut EdgeResponse) -> EdgeResult<()> {
        for (name, value) in &self.headers {
            if !response.headers().contains_key(name) {
                response.set_header(name.clone(), value.clone());
            }
        }
        Ok(())
    }
}
