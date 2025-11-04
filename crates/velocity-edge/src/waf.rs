use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::{
    error::{EdgeError, EdgeResult},
    middleware::EdgeMiddleware,
    request::EdgeRequest,
    response::EdgeResponse,
};

static DEFAULT_RULES: Lazy<Vec<Regex>> = Lazy::new(|| {
    // SAFETY: These are compile-time constant regex patterns, tested and known valid.
    // The unwrap() here is acceptable because:
    // 1. Patterns are hardcoded and verified
    // 2. Failure would indicate a programming error caught during development
    // 3. This runs once at startup, not in request path
    vec![
        Regex::new(r"(?i)select\\s+.+\\s+from").expect("WAF regex: SQL SELECT pattern invalid"),
        Regex::new(r"(?i)union\\s+select").expect("WAF regex: SQL UNION pattern invalid"),
        Regex::new(r"(?i)<script[>\\s]").expect("WAF regex: XSS script pattern invalid"),
        Regex::new(r"(?i)onerror=|onload=").expect("WAF regex: XSS event handler pattern invalid"),
        Regex::new(r"(?i)\b(drop|alter)\\s+table\b").expect("WAF regex: SQL DDL pattern invalid"),
    ]
});

/// Basic Web Application Firewall middleware.
#[derive(Debug)]
pub struct WafMiddleware {
    patterns: Vec<Regex>,
}

impl WafMiddleware {
    pub fn new(patterns: Vec<Regex>) -> Self {
        let patterns = if patterns.is_empty() {
            DEFAULT_RULES.clone()
        } else {
            patterns
        };
        Self { patterns }
    }

    fn inspect_value(&self, value: &str) -> EdgeResult<()> {
        for pattern in &self.patterns {
            if pattern.is_match(value) {
                return Err(EdgeError::WafBlocked(pattern.as_str().to_string()));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl EdgeMiddleware for WafMiddleware {
    async fn before(&self, request: &EdgeRequest) -> EdgeResult<()> {
        self.inspect_value(request.path())?;
        for values in request.path_params().values() {
            self.inspect_value(values)?;
        }
        for (key, values) in request.query().iter() {
            for value in values {
                self.inspect_value(value)?;
            }
            self.inspect_value(key)?;
        }
        if let Ok(body_str) = std::str::from_utf8(request.body()) {
            if !body_str.trim().is_empty() {
                self.inspect_value(body_str)?;
            }
        }
        Ok(())
    }

    async fn after(&self, _request: &EdgeRequest, _response: &mut EdgeResponse) -> EdgeResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn blocks_malicious_query() {
        let waf = WafMiddleware::new(Vec::new());
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let req = crate::request::EdgeRequest::testing(Method::GET, "/search?q=<script>", peer);
        let err = waf.before(&req).await.unwrap_err();
        assert!(matches!(err, EdgeError::WafBlocked(_)));
    }

    #[tokio::test]
    async fn allows_safe_request() {
        let waf = WafMiddleware::new(Vec::new());
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let req = crate::request::EdgeRequest::testing(Method::GET, "/search?q=velocity", peer);
        assert!(waf.before(&req).await.is_ok());
    }
}
