use http::Method;

use crate::error::{EdgeError, EdgeResult};

/// Normalize an HTTP target into a path beginning with `/` and without `.`/`..` segments.
pub fn normalize_prefix_path(target: &str) -> String {
    let trimmed = target.trim();
    let raw = if trimmed.is_empty() { "/" } else { trimmed };
    let mut normalized = String::from("/");
    let mut first = true;
    for segment in raw.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            continue;
        }
        if !first {
            normalized.push('/');
        }
        normalized.push_str(segment);
        first = false;
    }
    if normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    normalized
}

/// Parse a list of method strings into http::Method values.
pub fn parse_methods(values: &[String]) -> EdgeResult<Vec<Method>> {
    let mut methods = Vec::with_capacity(values.len());
    for value in values {
        if value.eq_ignore_ascii_case("ANY") {
            methods.clear();
            return Ok(Vec::new());
        }
        let method = Method::from_bytes(value.as_bytes()).map_err(|_| {
            EdgeError::Config(format!("unsupported HTTP method in edge config: {value}"))
        })?;
        methods.push(method);
    }
    if methods.is_empty() {
        methods.push(Method::GET);
    }
    Ok(methods)
}
