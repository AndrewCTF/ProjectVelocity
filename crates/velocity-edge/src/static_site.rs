use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use html_escape::{encode_double_quoted_attribute, encode_text};
use http::header::{HeaderName, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use http::{Method, StatusCode};
use tokio::fs;

use crate::error::{EdgeError, EdgeResult};
use crate::request::EdgeRequest;
use crate::response::EdgeResponse;

use super::ServeHandler;

/// Handler that serves files from a static directory and optional directory listings.
#[derive(Clone, Debug)]
pub struct StaticSiteHandler {
    root: PathBuf,
    index: String,
    listings: bool,
}

impl StaticSiteHandler {
    pub fn new(root: PathBuf, index: String, listings: bool) -> EdgeResult<Self> {
        let canonical = std::fs::canonicalize(&root).map_err(|err| {
            EdgeError::Config(format!(
                "failed to canonicalize static directory {}: {err}",
                root.display()
            ))
        })?;
        Ok(Self {
            root: canonical,
            index,
            listings,
        })
    }

    fn sanitize_relative_path(&self, path: &str) -> PathBuf {
        let trimmed = path.trim_start_matches('/');
        if trimmed.is_empty() {
            PathBuf::new()
        } else {
            PathBuf::from(trimmed)
        }
    }
}

#[async_trait]
impl ServeHandler for StaticSiteHandler {
    async fn handle(&self, request: EdgeRequest) -> EdgeResult<EdgeResponse> {
        let method = request.method().clone();
        if method != Method::GET && method != Method::HEAD {
            let mut response = EdgeResponse::text(format!("Method {method} is not supported"));
            response = response.with_status(StatusCode::METHOD_NOT_ALLOWED);
            return Ok(response);
        }

        let relative = self.sanitize_relative_path(request.path());
        let mut full = self.root.clone();
        full.push(&relative);

        let canonical = match fs::canonicalize(&full).await {
            Ok(path) => path,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let mut response = EdgeResponse::text("Resource not found");
                response = response.with_status(StatusCode::NOT_FOUND);
                return Ok(response);
            }
            Err(err) => return Err(EdgeError::Io(err)),
        };

        if !canonical.starts_with(&self.root) {
            let mut response = EdgeResponse::text("Forbidden");
            response = response.with_status(StatusCode::FORBIDDEN);
            return Ok(response);
        }

        let metadata = fs::metadata(&canonical).await?;
        if metadata.is_dir() {
            return self.handle_directory(&method, &canonical).await;
        }
        self.handle_file(&method, &canonical, metadata.len()).await
    }
}

impl StaticSiteHandler {
    async fn handle_file(
        &self,
        method: &Method,
        path: &Path,
        size: u64,
    ) -> EdgeResult<EdgeResponse> {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        let mut response = EdgeResponse::new(StatusCode::OK);
        response.set_header(
            HeaderName::from_static("content-type"),
            HeaderValue::from_str(mime.essence_str())
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        );
        let content_length = HeaderValue::from_str(&size.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0"));
        response.set_header(CONTENT_LENGTH, content_length);

        if method == Method::HEAD {
            return Ok(response);
        }

        let bytes = fs::read(path).await?;
        Ok(response.with_body(Bytes::from(bytes)))
    }

    async fn handle_directory(&self, method: &Method, dir: &Path) -> EdgeResult<EdgeResponse> {
        let index_path = dir.join(&self.index);
        if fs::metadata(&index_path)
            .await
            .map(|meta| meta.is_file())
            .unwrap_or(false)
        {
            let size = fs::metadata(&index_path).await.map(|meta| meta.len())?;
            return self.handle_file(method, &index_path, size).await;
        }

        if !self.listings {
            let mut response = EdgeResponse::text("Resource not found");
            response = response.with_status(StatusCode::NOT_FOUND);
            return Ok(response);
        }

        let listing = self.render_directory_listing(dir).await?;
        let mut response = EdgeResponse::html(listing);
        response = response.with_status(StatusCode::OK);
        response.set_header(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        if method == Method::HEAD {
            response.set_header(CONTENT_LENGTH, HeaderValue::from_static("0"));
            Ok(response.with_body(Bytes::new()))
        } else {
            Ok(response)
        }
    }

    async fn render_directory_listing(&self, dir: &Path) -> EdgeResult<String> {
        let mut entries = fs::read_dir(dir).await?;
        let mut items: Vec<(String, bool)> = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| EdgeError::BadRequest("directory entry was not valid UTF-8".into()))?;
            items.push((name, file_type.is_dir()));
        }
        items.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

        let mut body = String::from("<html><head><title>Directory listing</title><style>body{font-family:system-ui;margin:2rem;}table{width:100%;border-collapse:collapse;}th,td{padding:0.5rem;text-align:left;border-bottom:1px solid #ddd;}th{background:#f5f5f5;}</style></head><body>");
        body.push_str("<h1>Index of ");
        body.push_str(&encode_text(&dir.display().to_string()));
        body.push_str("</h1><table><tr><th>Name</th><th>Type</th></tr>");

        for (name, is_dir) in items {
            let href = encode_double_quoted_attribute(&name);
            let display = encode_text(&name);
            let kind = if is_dir { "Directory" } else { "File" };
            body.push_str(&format!(
                "<tr><td><a href=\"{href}\">{display}</a></td><td>{kind}</td></tr>",
                href = href,
                display = display,
                kind = kind
            ));
        }

        body.push_str("</table></body></html>");
        Ok(body)
    }
}
