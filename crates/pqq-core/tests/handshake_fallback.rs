use pqq_core::{
    build_initial_packet, decode_handshake_response, AlpnResolution, ChunkAssembler,
    FrameSequencer, HandshakeConfig, HandshakeDriver, FRAME_HEADER_LEN, FRAME_MAX_PAYLOAD,
    HANDSHAKE_MESSAGE_MAX,
};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[tokio::test]
async fn fallback_is_signaled_when_server_lacks_client_preference(
) -> Result<(), Box<dyn std::error::Error>> {
    let driver = HandshakeDriver::new(HandshakeConfig {
        supported_alpns: vec!["pqq/1".into()],
        fallback_alpn: Some("h3".into()),
        ..HandshakeConfig::default()
    });

    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr: SocketAddr = server_socket.local_addr().unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let server_future = driver.run_once(&server_socket);
    let client_future = async {
        let packet = build_initial_packet(["spdy/3", "h3"]);
        client_socket
            .send_to(&packet, server_addr)
            .await
            .expect("client send");

        let mut buf = [0u8; FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD];
        let mut framing = FrameSequencer::new(0, 0);
        let mut assembler = ChunkAssembler::new(HANDSHAKE_MESSAGE_MAX);
        loop {
            let (len, _addr) = client_socket
                .recv_from(&mut buf)
                .await
                .expect("client recv");
            let slice = framing.decode(&buf[..len]).expect("decode frame");
            if let Some(message) = assembler.push_slice(slice).expect("assemble") {
                break decode_handshake_response(&message).expect("compact response");
            }
        }
    };

    let (server_res, client_res) = tokio::join!(server_future, client_future);
    let (_peer, resolution) = server_res?;
    let response = client_res;

    assert!(matches!(
        resolution.resolution,
        AlpnResolution::Fallback(ref proto) if proto == "h3"
    ));
    assert_eq!(response.resolution, resolution.resolution);
    let fallback = response.fallback.expect("fallback directive present");
    assert_eq!(fallback.alpn, "h3");
    assert_eq!(fallback.host, "127.0.0.1");
    assert_eq!(fallback.port, 443);

    Ok(())
}
