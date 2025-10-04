use anyhow::Result;
use pqq_client::{Client, ClientConfig};
use pqq_core::AlpnResolution;
use pqq_server::{Request, Response, Server, ServerConfig};
use serde::Serialize;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, warn};

#[derive(Serialize)]
struct ApiMessage {
    message: String,
    negotiated_alpn: String,
    peer: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();

    let server = Arc::new(
        Server::bind(
            ([127, 0, 0, 1], 0),
            ServerConfig::default()
                .with_alpn(["pqq/1"])
                .with_fallback("h3", "localhost", 443),
        )
        .await?,
    );

    let server_addr = server.local_addr()?;
    info!(?server_addr, "json api demo listening");

    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let result = server
                .serve(|request: Request| async move {
                    let negotiated = match &request.handshake().resolution {
                        AlpnResolution::Supported(proto) => proto.clone(),
                        AlpnResolution::Fallback(proto) => proto.clone(),
                        AlpnResolution::Unsupported => "unsupported".into(),
                    };
                    let body = serde_json::json!(ApiMessage {
                        message: "Post-quantum handshake successful".into(),
                        negotiated_alpn: negotiated,
                        peer: request.peer().to_string(),
                    });

                    if let Some(line) = request.http_request_line() {
                        if line.target == "/status" {
                            return Response::json(&body);
                        }
                    }

                    let body = serde_json::json!({
                        "error": "unknown endpoint",
                        "allowed": "/status"
                    });
                    let body_str = body.to_string();
                    Response::from_bytes(format!(
                        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body_str.len(),
                        body_str
                    ))
                })
                .await;
            if let Err(err) = result {
                warn!(error = %err, "server loop exited unexpectedly");
            }
        })
    };

    let client_server = Arc::clone(&server);
    let demo_client = tokio::spawn(async move {
        let client = Client::new(
            ClientConfig::new(server_addr)
                .with_alpns(["pqq/1", "h3"])
                .with_server_kem_public(client_server.kem_public_key().to_vec()),
        );
        let response = client.get("https://localhost/status").await?;
        info!(%response, "demo client received JSON");
        Result::<_, anyhow::Error>::Ok(())
    });

    tokio::select! {
        res = demo_client => { res??; }
        _ = signal::ctrl_c() => {
            info!("ctrl-c received, shutting down JSON API demo");
        }
    }

    server_task.abort();
    Ok(())
}
