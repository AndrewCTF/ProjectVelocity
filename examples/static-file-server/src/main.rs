use anyhow::Result;
use pqq_client::{Client, ClientConfig};
use pqq_server::{Request, Response, Server, ServerConfig};
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();

    let static_root = env::var("VELOCITY_STATIC_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static"));

    let static_path = static_root.join("index.html");
    let index_html = Arc::new(tokio::fs::read_to_string(&static_path).await?);

    let bind_addr = env::var("VELOCITY_BIND_ADDR")
        .ok()
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));

    let publish_kem = env::var("VELOCITY_PUBLISH_KEM")
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    let mut server_config =
        ServerConfig::default()
            .with_alpn(["pqq/1"])
            .with_fallback("h3", "localhost", 443);

    if publish_kem {
        info!("publishing ML-KEM public key in Velocity handshake payloads");
        server_config = server_config.publish_kem_public(true);
    }

    let server = Arc::new(Server::bind(bind_addr, server_config).await?);

    let server_addr = server.local_addr()?;
    info!(?server_addr, path = %static_path.display(), publish_kem, "static file server ready");

    let html = Arc::clone(&index_html);
    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let handler_html = Arc::clone(&html);
            let result = server
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
                .await;
            if let Err(err) = result {
                warn!(error = %err, "server loop exited");
            }
        })
    };

    let disable_embedded_client = env::var("VELOCITY_DISABLE_EMBEDDED_CLIENT").is_ok();

    if disable_embedded_client {
        info!("embedded demo client disabled; awaiting external requests");
        signal::ctrl_c().await?;
        info!("ctrl-c received, shutting down static server");
        server_task.abort();
    } else {
        let client_server = Arc::clone(&server);
        let demo_client = tokio::spawn(async move {
            let client = Client::new(
                ClientConfig::new(server_addr)
                    .with_alpns(["pqq/1", "h3"])
                    .with_server_kem_public(client_server.kem_public_key().to_vec()),
            );
            let response = client.get("https://localhost/").await?;
            info!(%response, "demo client received response");
            Result::<_, anyhow::Error>::Ok(())
        });

        tokio::select! {
            res = demo_client => { res??; }
            _ = signal::ctrl_c() => {
                info!("ctrl-c received, shutting down static server");
            }
        }

        server_task.abort();
    }
    Ok(())
}
