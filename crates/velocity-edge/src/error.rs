use http::StatusCode;
use thiserror::Error;

pub type EdgeResult<T> = Result<T, EdgeError>;

#[derive(Debug, Error)]
pub enum EdgeError {
    #[error("route not found: {method} {path}")]
    NotFound { method: String, path: String },
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("template rendering failed: {0}")]
    Template(#[from] tera::Error),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("too many requests from {0}")]
    TooManyRequests(String),
    #[error("request blocked by WAF: {0}")]
    WafBlocked(String),
}

impl EdgeError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            EdgeError::NotFound { .. } => StatusCode::NOT_FOUND,
            EdgeError::Forbidden(_) => StatusCode::FORBIDDEN,
            EdgeError::BadRequest(_) => StatusCode::BAD_REQUEST,
            EdgeError::Template(_) => StatusCode::INTERNAL_SERVER_ERROR,
            EdgeError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            EdgeError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            EdgeError::Upstream(_) => StatusCode::BAD_GATEWAY,
            EdgeError::Json(_) | EdgeError::Yaml(_) => StatusCode::BAD_REQUEST,
            EdgeError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            EdgeError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            EdgeError::WafBlocked(_) => StatusCode::FORBIDDEN,
        }
    }
}
