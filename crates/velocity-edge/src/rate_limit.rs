use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;

use crate::{
    error::{EdgeError, EdgeResult},
    middleware::EdgeMiddleware,
    request::EdgeRequest,
    response::EdgeResponse,
};

/// Sliding-window rate limiter keyed by client IP.
#[derive(Debug)]
pub struct RateLimitMiddleware {
    limit: usize,
    window: Duration,
    buckets: DashMap<IpAddr, VecDeque<Instant>>,
}

impl RateLimitMiddleware {
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            buckets: DashMap::new(),
        }
    }

    fn check(&self, address: IpAddr) -> EdgeResult<()> {
        if self.limit == 0 {
            return Ok(());
        }
        let now = Instant::now();
        let mut entry = self.buckets.entry(address).or_insert_with(VecDeque::new);
        while let Some(front) = entry.front() {
            if now.duration_since(*front) > self.window {
                entry.pop_front();
            } else {
                break;
            }
        }
        if entry.len() >= self.limit {
            return Err(EdgeError::TooManyRequests(address.to_string()));
        }
        entry.push_back(now);
        Ok(())
    }
}

#[async_trait]
impl EdgeMiddleware for RateLimitMiddleware {
    async fn before(&self, request: &EdgeRequest) -> EdgeResult<()> {
        self.check(request.peer().ip())
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
    async fn rate_limit_blocks_after_threshold() {
        let limiter = RateLimitMiddleware::new(2, Duration::from_secs(60));
        let peer: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let edge_req = crate::request::EdgeRequest::testing(Method::GET, "/", peer);
        limiter.before(&edge_req).await.unwrap();
        limiter.before(&edge_req).await.unwrap();
        let err = limiter.before(&edge_req).await.unwrap_err();
        assert!(matches!(err, EdgeError::TooManyRequests(_)));
    }
}
