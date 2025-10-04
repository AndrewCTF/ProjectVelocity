use std::collections::HashMap;

use http::Method;

use crate::error::{EdgeError, EdgeResult};

#[derive(Debug, Clone)]
pub struct EdgeRouter {
    routes: Vec<RouteEntry>,
}

#[derive(Debug, Clone)]
struct RouteEntry {
    methods: Vec<Method>,
    pattern: PathPattern,
    handler_index: usize,
}

#[derive(Debug, Clone)]
pub struct RouteMatch {
    pub handler_index: usize,
    pub params: HashMap<String, String>,
}

impl EdgeRouter {
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    pub fn add_route(&mut self, methods: Vec<Method>, pattern: PathPattern, handler_index: usize) {
        self.routes.push(RouteEntry {
            methods,
            pattern,
            handler_index,
        });
    }

    pub fn resolve(&self, method: &Method, path: &str) -> Option<RouteMatch> {
        let segments: Vec<&str> = path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        for route in &self.routes {
            if !route.methods.is_empty() && !route.methods.iter().any(|m| m == method) {
                continue;
            }
            if let Some(params) = route.pattern.matches(&segments) {
                return Some(RouteMatch {
                    handler_index: route.handler_index,
                    params,
                });
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct PathPattern {
    segments: Vec<PathSegment>,
    wildcard: bool,
}

#[derive(Debug, Clone)]
enum PathSegment {
    Static(String),
    Param(String),
}

impl PathPattern {
    pub fn parse(pattern: &str) -> EdgeResult<Self> {
        if !pattern.starts_with('/') {
            return Err(EdgeError::Config(format!(
                "route pattern must start with '/': {pattern}"
            )));
        }
        let parts: Vec<&str> = pattern
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        let mut segments = Vec::new();
        let mut wildcard = false;
        let last_index = parts.len().saturating_sub(1);
        for (index, segment) in parts.iter().enumerate() {
            let segment = *segment;
            if segment == "*" {
                if index != last_index {
                    return Err(EdgeError::Config(
                        "wildcard segment '*' is only allowed at the end of a route".into(),
                    ));
                }
                wildcard = true;
                break;
            }
            if segment.starts_with('{') && segment.ends_with('}') {
                let name = &segment[1..segment.len() - 1];
                if name.is_empty() {
                    return Err(EdgeError::Config(
                        "path parameter name cannot be empty".into(),
                    ));
                }
                segments.push(PathSegment::Param(name.to_string()));
            } else {
                segments.push(PathSegment::Static((*segment).to_string()));
            }
        }
        Ok(Self { segments, wildcard })
    }

    fn matches(&self, segments: &[&str]) -> Option<HashMap<String, String>> {
        if !self.wildcard && segments.len() != self.segments.len() {
            return None;
        }
        if self.wildcard && segments.len() < self.segments.len() {
            return None;
        }
        let mut params = HashMap::new();
        for (idx, pattern_segment) in self.segments.iter().enumerate() {
            if let Some(actual) = segments.get(idx) {
                match pattern_segment {
                    PathSegment::Static(value) if value == actual => {}
                    PathSegment::Static(_) => return None,
                    PathSegment::Param(name) => {
                        params.insert(name.clone(), (*actual).to_string());
                    }
                }
            } else {
                return None;
            }
        }
        Some(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_static_route() {
        let pattern = PathPattern::parse("/hello/world").unwrap();
        let segments = vec!["hello", "world"];
        assert!(pattern.matches(&segments).is_some());
    }

    #[test]
    fn matches_param_route() {
        let pattern = PathPattern::parse("/users/{id}").unwrap();
        let segments = vec!["users", "42"];
        let params = pattern.matches(&segments).unwrap();
        assert_eq!(params.get("id"), Some(&"42".to_string()));
    }

    #[test]
    fn rejects_mismatched_route() {
        let pattern = PathPattern::parse("/users/{id}").unwrap();
        let segments = vec!["accounts", "42"];
        assert!(pattern.matches(&segments).is_none());
    }
}
