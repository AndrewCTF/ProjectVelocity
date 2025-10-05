use std::collections::HashMap;
use std::net::SocketAddr;

use bytes::Bytes;
use http::{header::HeaderName, header::HOST, HeaderMap, HeaderValue, Method};
use httparse::Status;
use url::form_urlencoded::parse as parse_query;

use crate::error::{EdgeError, EdgeResult};
use crate::utils::normalize_prefix_path;
use pqq_server::Request;

#[derive(Clone, Debug)]
pub struct EdgeRequest {
    method: Method,
    path: String,
    target: String,
    query: HashMap<String, Vec<String>>,
    headers: HeaderMap,
    body: Bytes,
    peer: SocketAddr,
    path_params: HashMap<String, String>,
}

impl EdgeRequest {
    pub fn from_pqq(request: Request) -> EdgeResult<Self> {
        let peer = request.peer();
        let payload = request.payload();

        let mut header_storage = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Request::new(&mut header_storage);
        let status = parsed
            .parse(payload)
            .map_err(|err| EdgeError::BadRequest(format!("failed to parse http request: {err}")))?;
        let header_len = match status {
            Status::Complete(len) => len,
            Status::Partial => {
                return Err(EdgeError::BadRequest(
                    "incomplete http request forwarded over velocity".into(),
                ))
            }
        };

        let method_str = parsed
            .method
            .ok_or_else(|| EdgeError::BadRequest("missing http method".into()))?;
        let target = parsed
            .path
            .ok_or_else(|| EdgeError::BadRequest("missing request target".into()))?;

        let method = Method::from_bytes(method_str.as_bytes())
            .map_err(|_| EdgeError::BadRequest(format!("invalid http method: {method_str}")))?;

        let mut headers = HeaderMap::new();
        for header in parsed.headers.iter() {
            let name = HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| {
                EdgeError::BadRequest(format!("invalid header name: {}", header.name))
            })?;
            let value = HeaderValue::from_bytes(header.value).map_err(|_| {
                EdgeError::BadRequest(format!("invalid header value for {}", header.name))
            })?;
            headers.append(name, value);
        }

        let body = Bytes::copy_from_slice(&payload[header_len..]);
        Self::from_http_parts(method, target.to_string(), headers, body, peer)
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn host(&self) -> Option<&str> {
        self.headers
            .get(HOST)
            .and_then(|value| std::str::from_utf8(value.as_bytes()).ok())
    }

    pub fn query_values(&self, key: &str) -> Option<&[String]> {
        self.query.get(key).map(|values| values.as_slice())
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn header(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.headers.get(name)
    }

    pub fn query(&self) -> &HashMap<String, Vec<String>> {
        &self.query
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn body_bytes(&self) -> Bytes {
        self.body.clone()
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> EdgeResult<T> {
        let value = serde_json::from_slice(&self.body)?;
        Ok(value)
    }

    pub fn param(&self, key: &str) -> Option<&str> {
        self.path_params.get(key).map(|value| value.as_str())
    }

    pub fn path_params(&self) -> &HashMap<String, String> {
        &self.path_params
    }

    pub(crate) fn with_path_params(mut self, params: HashMap<String, String>) -> Self {
        self.path_params = params;
        self
    }

    pub fn strip_prefix(&self, prefix: &str) -> Option<Self> {
        if prefix == "/" {
            return Some(self.clone());
        }
        if !self.path.starts_with(prefix) {
            return None;
        }
        let remainder = &self.path[prefix.len()..];
        if !remainder.is_empty() && !remainder.starts_with('/') {
            return None;
        }
        let new_path = if remainder.is_empty() { "/" } else { remainder };
        let mut clone = self.clone();
        clone.path = new_path.to_string();
        clone.target = if let Some(idx) = self.target.find('?') {
            format!("{}{}", clone.path, &self.target[idx..])
        } else {
            clone.path.clone()
        };
        clone.path_params.clear();
        Some(clone)
    }

    pub fn from_http_parts(
        method: Method,
        target: String,
        headers: HeaderMap,
        body: Bytes,
        peer: SocketAddr,
    ) -> EdgeResult<Self> {
        let (path, query_map) = split_target(&target);
        Ok(Self {
            method,
            path,
            target,
            query: query_map,
            headers,
            body,
            peer,
            path_params: HashMap::new(),
        })
    }

    #[cfg(test)]
    pub fn testing(method: Method, target: &str, peer: SocketAddr) -> Self {
        let (path, query) = split_target(target);
        Self {
            method,
            path,
            target: target.to_string(),
            query,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            peer,
            path_params: HashMap::new(),
        }
    }
}

fn split_target(target: &str) -> (String, HashMap<String, Vec<String>>) {
    let mut parts = target.splitn(2, '?');
    let path = normalize_prefix_path(parts.next().unwrap_or("/"));
    let query = parts.next();
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(q) = query {
        for (key, value) in parse_query(q.as_bytes()) {
            map.entry(key.into_owned())
                .or_default()
                .push(value.into_owned());
        }
    }
    (path, map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{header::HOST, HeaderMap, HeaderValue, Method};

    #[test]
    fn strip_prefix_adjusts_path_and_target() {
        let peer: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let request = EdgeRequest::testing(Method::GET, "/api/users?id=10", peer);
        let rebased = request.strip_prefix("/api").expect("prefix matches");
        assert_eq!(rebased.path(), "/users");
        assert_eq!(rebased.target(), "/users?id=10");
    }

    #[test]
    fn host_header_accessor_returns_value() {
        let peer: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("example.com"));
        let request =
            EdgeRequest::from_http_parts(Method::GET, "/".to_string(), headers, Bytes::new(), peer)
                .expect("edge request");
        assert_eq!(request.host(), Some("example.com"));
    }
}
