use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use pqq_client::{Client, ClientConfig};
use pqq_core::AlpnResolution;
use pqq_server::{HandshakeTelemetryCollector, HandshakeTelemetryEvent, Server, ServerConfig};
use tokio::sync::oneshot;

#[tokio::test]
async fn captures_hybrid_handshake_transcript_over_udp() {
    let server = Arc::new(
        Server::bind(([127, 0, 0, 1], 0), ServerConfig::default())
            .await
            .expect("server bind"),
    );
    let addr = server.local_addr().expect("server addr");
    let kem_public = server.kem_public_key().to_vec();

    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let session = server.accept().await.expect("session accept");
            assert!(matches!(
                session.handshake().resolution,
                AlpnResolution::Supported(_)
            ));
            let transcript = session
                .handshake_transcript()
                .cloned()
                .expect("transcript present");
            let client_decoded = BASE64_STANDARD
                .decode(transcript.client_base64())
                .expect("decode client payload");
            assert_eq!(client_decoded, transcript.client_raw());
            let server_decoded = BASE64_STANDARD
                .decode(transcript.server_base64())
                .expect("decode server payload");
            assert_eq!(server_decoded, transcript.server_raw());
        })
    };

    let client_task = tokio::spawn(async move {
        let client = Client::new(
            ClientConfig::new(addr)
                .with_alpns(["pqq/1", "h3"])
                .with_server_kem_public(kem_public),
        );
        let session = client.connect().await.expect("client connect");
        assert!(matches!(
            session.alpn_resolution(),
            AlpnResolution::Supported(_)
        ));
    });

    let (server_res, client_res) = tokio::join!(server_task, client_task);
    server_res.expect("server task");
    client_res.expect("client task");
}

#[derive(Debug)]
struct ChannelTelemetryCollector {
    tx: Mutex<Option<oneshot::Sender<HandshakeTelemetryEvent>>>,
}

impl ChannelTelemetryCollector {
    fn new(tx: oneshot::Sender<HandshakeTelemetryEvent>) -> Self {
        Self {
            tx: Mutex::new(Some(tx)),
        }
    }
}

impl HandshakeTelemetryCollector for ChannelTelemetryCollector {
    fn record(&self, event: &HandshakeTelemetryEvent) {
        if let Some(tx) = self.tx.lock().expect("collector mutex").take() {
            let _ = tx.send(event.clone());
        }
    }
}

#[tokio::test]
async fn emits_handshake_telemetry_event() {
    let (tx, rx) = oneshot::channel();
    let telemetry = Arc::new(ChannelTelemetryCollector::new(tx));

    let server = Arc::new(
        Server::bind(
            ([127, 0, 0, 1], 0),
            ServerConfig::default().with_telemetry(telemetry),
        )
        .await
        .expect("server bind"),
    );
    let addr = server.local_addr().expect("server addr");
    let kem_public = server.kem_public_key().to_vec();

    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let session = server.accept().await.expect("session accept");
            assert!(matches!(
                session.handshake().resolution,
                AlpnResolution::Supported(_)
            ));
        })
    };

    let client_task = tokio::spawn(async move {
        let client = Client::new(
            ClientConfig::new(addr)
                .with_alpns(["pqq/1", "h3"])
                .with_server_kem_public(kem_public),
        );
        client.connect().await.expect("client connect");
    });

    let event = rx.await.expect("telemetry event");
    assert!(matches!(event.resolution, AlpnResolution::Supported(_)));
    assert!(event.session_ticket_issued);
    assert!(event.client_hello_len > 0);
    assert!(event.server_hello_len > 0);

    server_task.await.expect("server task");
    client_task.await.expect("client task");
}
