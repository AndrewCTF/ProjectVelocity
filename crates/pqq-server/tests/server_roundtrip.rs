use pqq_client::{Client, ClientConfig};
use pqq_core::AlpnResolution;
use pqq_server::{Response, SecurityProfile, Server, ServerConfig};
use pqq_tls::ServerHelloPayload;
use tokio::sync::oneshot;

#[tokio::test]
async fn server_accepts_and_replies() {
    let server = Server::bind(
        ([127, 0, 0, 1], 0),
        ServerConfig::default()
            .with_alpn(["pqq/1"])
            .with_fallback("h3", "localhost", 443),
    )
    .await
    .expect("server bind");

    let addr = server.local_addr().expect("local addr");
    let kem_public = server.kem_public_key().to_vec();

    let server_task = tokio::spawn(async move {
        let session = server.accept().await.expect("accept");
        assert!(matches!(
            session.handshake().resolution,
            AlpnResolution::Supported(_)
        ));
        let request = session.recv_request().await.expect("request");
        assert!(request.http_request_line().is_some());
        session
            .send_response(Response::text("pong"))
            .await
            .expect("response");
    });

    let client_task = tokio::spawn(async move {
        let client = Client::new(
            ClientConfig::new(addr)
                .with_alpns(["pqq/1", "h3"])
                .with_server_kem_public(kem_public),
        );
        let session = client.connect().await.expect("connect");
        let response = session
            .send_request_string(b"GET /ping HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .expect("response");
        assert!(response.contains("pong"));
    });

    let (server_res, client_res) = tokio::join!(server_task, client_task);
    server_res.expect("server join");
    client_res.expect("client join");
}

#[tokio::test]
async fn server_accepts_0rtt_resumption() {
    let server = Server::bind(
        ([127, 0, 0, 1], 0),
        ServerConfig::default().with_alpn(["pqq/1"]),
    )
    .await
    .expect("server bind");

    let addr = server.local_addr().expect("local addr");
    let kem_public = server.kem_public_key().to_vec();

    let server_task = tokio::spawn(async move {
        let session1 = server.accept().await.expect("initial accept");
        let request1 = session1.recv_request().await.expect("initial request");
        assert!(!request1.is_early_data());
        session1
            .send_response(Response::text("initial"))
            .await
            .expect("initial response");

        let session2 = server.accept().await.expect("resumed accept");
        assert!(session2.resumption_accepted());
        let request2 = session2.recv_request().await.expect("resumed request");
        assert!(request2.is_early_data());
        let request_line = request2.http_request_line().expect("valid http");
        assert_eq!(request_line.target, "/0rtt");
        session2
            .send_response(Response::text("resumed"))
            .await
            .expect("resumed response");
    });

    let client_task = tokio::spawn(async move {
        let client = Client::new(
            ClientConfig::new(addr)
                .with_alpns(["pqq/1"])
                .with_server_kem_public(kem_public),
        );
        let first = client
            .get("https://example.com/first")
            .await
            .expect("first request");
        assert!(first.contains("initial"));

        let resumed = client
            .get("https://example.com/0rtt")
            .await
            .expect("resumed request");
        assert!(resumed.contains("resumed"));
    });

    let (server_res, client_res) = tokio::join!(server_task, client_task);
    server_res.expect("server join");
    client_res.expect("client join");
}

#[tokio::test]
async fn security_profiles_select_expected_suites_and_limits() {
    for profile in [
        SecurityProfile::Turbo,
        SecurityProfile::Balanced,
        SecurityProfile::Fortress,
    ] {
        exercise_profile(profile).await;
    }
}

async fn exercise_profile(profile: SecurityProfile) {
    let server = Server::bind(
        ([127, 0, 0, 1], 0),
        ServerConfig::default()
            .with_security_profile(profile)
            .with_alpn(["pqq/1"]),
    )
    .await
    .expect("server bind");

    let addr = server.local_addr().expect("local addr");
    let kem_public = server.kem_public_key().to_vec();
    let expected_suite = profile.suite();
    let expected_max_early = profile.max_early_data();

    let (tx, rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let session = server.accept().await.expect("accept");
        let transcript = session.handshake_transcript().expect("transcript").clone();
        let max_early = session.max_early_data();
        tx.send((transcript, max_early)).ok();
        let request = session.recv_request().await.expect("request");
        assert!(request.http_request_line().is_some());
        session
            .send_response(Response::text("ok"))
            .await
            .expect("response");
    });

    let client_task = tokio::spawn(async move {
        let client = Client::new(
            ClientConfig::new(addr)
                .with_alpns(["pqq/1"])
                .with_security_profile(profile)
                .with_server_kem_public(kem_public),
        );
        let session = client.connect().await.expect("connect");
        let response = session
            .send_request_string(b"GET /profile HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .expect("response");
        assert!(response.contains("ok"));
    });

    let (transcript, max_early_data) = rx.await.expect("handshake data");
    let payload: ServerHelloPayload =
        pqq_core::cbor_from_slice(transcript.server_raw()).expect("decode payload");
    assert_eq!(payload.selected_kem, expected_suite.kem_suite);
    assert_eq!(payload.selected_cipher, expected_suite.cipher_suite);
    assert_eq!(payload.max_early_data, expected_max_early);
    assert_eq!(max_early_data, expected_max_early);

    let (server_res, client_res) = tokio::join!(server_task, client_task);
    server_res.expect("server join");
    client_res.expect("client join");
}
