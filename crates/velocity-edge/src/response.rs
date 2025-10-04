use bytes::Bytes;
use http::{
    header::{HeaderName, HeaderValue, CONTENT_LENGTH},
    HeaderMap, StatusCode,
};
use serde::Serialize;
use serde_json::{self, json};

use crate::error::{EdgeError, EdgeResult};

/// Represents an application response produced by the edge runtime.
#[derive(Debug, Clone)]
pub struct EdgeResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl EdgeResponse {
    /// Create a new response with the provided status code and empty body.
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        }
    }

    /// Convenience constructor for a 200 OK response.
    pub fn ok() -> Self {
        Self::new(StatusCode::OK)
    }

    /// Create a JSON response from a serializable value.
    pub fn json<T: Serialize>(value: &T) -> EdgeResult<Self> {
        let payload = serde_json::to_vec(value)?;
        let mut response = Self::new(StatusCode::OK);
        response.set_header(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        response.body = Bytes::from(payload);
        Ok(response)
    }

    /// Create a plain text response.
    pub fn text(body: impl Into<String>) -> Self {
        let mut response = Self::new(StatusCode::OK);
        response.set_header(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        response.body = Bytes::from(body.into());
        response
    }

    /// Create an HTML response.
    pub fn html(body: impl Into<String>) -> Self {
        let mut response = Self::new(StatusCode::OK);
        response.set_header(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        response.body = Bytes::from(body.into());
        response
    }

    /// Set the response body directly from bytes.
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Update the status code.
    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    /// Borrow the current status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Insert or replace a header value.
    pub fn set_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.headers.insert(name, value);
    }

    /// Append a header without removing existing values.
    pub fn append_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.headers.append(name, value);
    }

    /// Get a mutable reference to the headers map.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    /// Get an immutable reference to the headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Borrow the response body as bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Convert the edge response into a Velocity transport response.
    pub fn into_transport_response(self) -> pqq_server::Response {
        let mut response = self;
        response.ensure_content_length();
        let mut head = Vec::new();
        let reason = response
            .status
            .canonical_reason()
            .unwrap_or("Unknown Status");
        head.extend_from_slice(
            format!("HTTP/1.1 {} {}\r\n", response.status.as_u16(), reason).as_bytes(),
        );
        for (name, value) in response.headers.iter() {
            head.extend_from_slice(name.as_str().as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(value.as_bytes());
            head.extend_from_slice(b"\r\n");
        }
        head.extend_from_slice(b"\r\n");
        head.extend_from_slice(&response.body);
        pqq_server::Response::from_bytes(head)
    }

    fn ensure_content_length(&mut self) {
        if !self.headers.contains_key(CONTENT_LENGTH) {
            if let Ok(len) = HeaderValue::from_str(&self.body.len().to_string()) {
                self.headers.insert(CONTENT_LENGTH, len);
            }
        }
    }
}

impl From<EdgeError> for EdgeResponse {
    fn from(err: EdgeError) -> Self {
        let mut response = EdgeResponse::new(err.status_code());
        response.set_header(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        let payload = json!({
            "error": err.to_string(),
        });
        response.body = Bytes::from(serde_json::to_vec(&payload).unwrap_or_default());
        response
    }
}
