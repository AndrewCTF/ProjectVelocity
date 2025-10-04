use anyhow::{ensure, Result};
use pqq_client::{Client, ClientConfig, ClientError, HandshakeOutcome};
use pqq_core::AlpnResolution;
use pqq_server::{Response, Server, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();

    info!("starting PQ-QUIC handshake demo");

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

    info!(?server_addr, "server socket bound");

    run_supported_roundtrip(server.clone(), server_addr).await?;
    run_fallback_roundtrip(server, server_addr).await?;

    info!("demo finished");
    Ok(())
}

async fn run_supported_roundtrip(server: Arc<Server>, server_addr: SocketAddr) -> Result<()> {
    info!("=== PQ-QUIC HTTP roundtrip ===");

    let server_task = {
        let server = Arc::clone(&server);
        async move {
            let session = server.accept().await?;
            ensure!(
                matches!(session.handshake().resolution, AlpnResolution::Supported(_)),
                "expected ALPN support"
            );
            let transcript = session.handshake_transcript().cloned();
            let request = session.recv_request().await?;
            let request_line = request
                .http_request_line()
                .map(|line| format!("{} {} {}", line.method, line.target, line.version))
                .unwrap_or_else(|| "<invalid>".into());
            let body = format!("Hello from VELO PQ-QUIC!\nRequest-Line: {}\n", request_line);
            session.send_response(Response::text(&body)).await?;

            Ok::<_, anyhow::Error>((request, body, transcript))
        }
    };

    let client_task = {
        let server = Arc::clone(&server);
        async move {
            let client_config = ClientConfig::new(server_addr)
                .with_alpns(["pqq/1", "h3"])
                .with_server_kem_public(server.kem_public_key().to_vec());
            let client = Client::new(client_config);
            let session = client.connect().await?;
            let handshake_reply = session.handshake_response().clone();
            let http_request = "GET /resource HTTP/1.1\r\nHost: demo\r\n\r\n";
            let http_response = session.send_request_string(http_request.as_bytes()).await?;

            Ok::<_, ClientError>((handshake_reply, http_request.to_string(), http_response))
        }
    };

    let (server_outcome, client_outcome) = tokio::join!(server_task, client_task);
    let (server_seen_request, server_response, transcript) = server_outcome?;
    let (handshake_reply, client_request, client_response) = client_outcome?;
    let request_line = server_seen_request
        .http_request_line()
        .map(|line| format!("{} {} {}", line.method, line.target, line.version))
        .unwrap_or_else(|| "<invalid>".into());
    let handshake_json = serde_json::to_string(&handshake_reply)?;
    info!(handshake = %handshake_json, "client handshake response");
    if let Some(transcript) = transcript {
        info!(
            client_hello_b64 = %transcript.client_base64(),
            server_hello_b64 = %transcript.server_base64(),
            "hybrid PQ handshake transcript"
        );
    }
    info!(request_line = %request_line, "server observed request");
    info!(%client_request, "client sent HTTP request");
    info!(%client_response, "client received HTTP response");
    info!(%server_response, "server sent HTTP response payload");

    Ok(())
}

async fn run_fallback_roundtrip(server: Arc<Server>, server_addr: SocketAddr) -> Result<()> {
    info!("=== HTTP/3 fallback negotiation ===");

    let server_task = {
        let server = Arc::clone(&server);
        async move {
            let session = server.accept().await?;
            Ok::<_, anyhow::Error>(session.handshake().clone())
        }
    };

    let client_task = async {
        let client_config = ClientConfig::new(server_addr).with_alpns(["spdy/3", "h3"]);
        let client = Client::new(client_config);
        match client.connect_or_fallback().await? {
            HandshakeOutcome::Fallback(response) => Ok::<_, ClientError>(response),
            HandshakeOutcome::Unsupported(response) => Err(ClientError::AlpnUnsupported(response)),
            HandshakeOutcome::Established { session, .. } => {
                Ok(session.handshake_response().clone())
            }
        }
    };

    let (server_outcome, client_outcome) = tokio::join!(server_task, client_task);
    let server_response = server_outcome?;
    let handshake_reply = client_outcome?;

    ensure!(
        matches!(server_response.resolution, AlpnResolution::Fallback(_)),
        "expected fallback ALPN"
    );
    let server_fallback = server_response
        .fallback
        .as_ref()
        .expect("server provided fallback directive");
    let client_fallback = handshake_reply
        .fallback
        .as_ref()
        .expect("client should receive fallback directive");
    ensure!(
        client_fallback.alpn == "h3" && client_fallback.port == server_fallback.port,
        "client fallback directive should mirror server"
    );
    let server_json = serde_json::to_string(&server_response)?;
    let client_json = serde_json::to_string(&handshake_reply)?;
    info!(
        server = %server_json,
        client = %client_json,
        "client instructed to downgrade to HTTP/3"
    );

    Ok(())
}
