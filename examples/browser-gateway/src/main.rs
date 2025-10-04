use anyhow::{Context, Result};
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::{make_service_fn, service_fn};
use hyper::{
    Body, Method, Request as HttpRequest, Response as HttpResponse, Server as HttpServer,
    StatusCode,
};
use pqq_client::{Client, ClientConfig};
use pqq_server::{Request, Response, Server, ServerConfig};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};

struct AppState {
    upstream: SocketAddr,
    server_kem_public: Vec<u8>,
}

type ParsedResponse = (StatusCode, Vec<(HeaderName, HeaderValue)>, Vec<u8>);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();

    let static_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static/index.html");
    let index_html = Arc::new(tokio::fs::read_to_string(&static_path).await?);

    let server = Arc::new(
        Server::bind(
            ([127, 0, 0, 1], 0),
            ServerConfig::default()
                .with_alpn(["pqq/1"])
                .with_fallback("h3", "localhost", 443),
        )
        .await?,
    );
    let upstream = server.local_addr()?;
    info!(?upstream, "PQ-QUIC content server ready");

    let html = Arc::clone(&index_html);
    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let handler_html = Arc::clone(&html);
            if let Err(err) = server
                .serve(move |request: Request| {
                    let handler_html = Arc::clone(&handler_html);
                    async move {
                        if let Some(line) = request.http_request_line() {
                            if line.target == "/" || line.target == "/index.html" {
                                return Response::html(handler_html.as_str());
                            }
                        }
                        let body = "404 Not Found";
                        Response::from_bytes(format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        ))
                    }
                })
                .await
            {
                error!(error = %err, "pq server loop terminated");
            }
        })
    };

    let state = Arc::new(AppState {
        upstream,
        server_kem_public: server.kem_public_key().to_vec(),
    });
    let http_addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    info!(?http_addr, "HTTP gateway listening for browsers");

    let make_svc = {
        let state = Arc::clone(&state);
        make_service_fn(move |_| {
            let state = Arc::clone(&state);
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let state = Arc::clone(&state);
                    async move { handle_browser_request(req, state).await }
                }))
            }
        })
    };

    let http_server = HttpServer::bind(&http_addr).serve(make_svc);
    let graceful = http_server.with_graceful_shutdown(async {
        signal::ctrl_c()
            .await
            .expect("ctrl-c handler should succeed");
        info!("ctrl-c received, shutting down gateway");
    });

    if let Err(err) = graceful.await {
        error!(error = %err, "http server exited with error");
    }

    server_task.abort();

    Ok(())
}

async fn handle_browser_request(
    req: HttpRequest<Body>,
    state: Arc<AppState>,
) -> Result<HttpResponse<Body>, Infallible> {
    match forward_to_pq(req, state).await {
        Ok(response) => Ok(response),
        Err(err) => {
            error!(error = %err, "failed to service browser request");
            let body = format!("Internal error: {err}");
            let response = HttpResponse::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("content-type", "text/plain; charset=utf-8")
                .body(Body::from(body))
                .unwrap();
            Ok(response)
        }
    }
}

async fn forward_to_pq(req: HttpRequest<Body>, state: Arc<AppState>) -> Result<HttpResponse<Body>> {
    match *req.method() {
        Method::GET | Method::HEAD => {}
        _ => {
            return Ok(HttpResponse::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from("Only GET and HEAD are supported"))?);
        }
    }

    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let request_line = format!(
        "{} {} HTTP/1.1\r\nHost: browser-gateway\r\nConnection: close\r\n\r\n",
        req.method(),
        path
    );

    let client = Client::new(
        ClientConfig::new(state.upstream)
            .with_alpns(["pqq/1", "h3"])
            .with_server_kem_public(state.server_kem_public.clone()),
    );
    let session = client.connect().await?;
    let response_text = session.send_request_string(request_line.as_bytes()).await?;
    let (status, headers, body) = parse_http_response(&response_text)?;

    let mut builder = HttpResponse::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }

    Ok(builder.body(Body::from(body))?)
}

fn parse_http_response(response: &str) -> Result<ParsedResponse> {
    let (head, body) = response
        .split_once("\r\n\r\n")
        .context("missing header/body separator")?;
    let mut lines = head.lines();
    let status_line = lines.next().context("missing status line")?;
    let mut parts = status_line.split_whitespace();
    let _http_version = parts.next().context("missing HTTP version")?;
    let status_code = parts
        .next()
        .context("missing status code")?
        .parse::<u16>()
        .context("invalid status code")?;
    let status = StatusCode::from_u16(status_code)?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let header_name = HeaderName::from_bytes(name.trim().as_bytes())?;
            let header_value = HeaderValue::from_str(value.trim())?;
            headers.push((header_name, header_value));
        }
    }

    Ok((status, headers, body.as_bytes().to_vec()))
}
