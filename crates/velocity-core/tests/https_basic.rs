use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pqq_core::{cbor_from_slice, cbor_to_vec};
use pqq_tls::{
    ClientHandshake, ClientHelloOptions, HybridHandshakeError, MlKem1024, MlKem512, MlKem768,
    SecurityProfile, ServerHelloPayload,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use velocity_core::https::{HttpsConfig, HttpsServer};
use velocity_core::{run_udp_loop, PacketType, SecurityConfig, SecurityContext};

fn next_loopback_addr() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("ephemeral bind");
    let addr = socket.local_addr().expect("local addr");
    drop(socket);
    addr
}

async fn send_sample_datagram(security: &Arc<SecurityContext>, target: SocketAddr) {
    let mut datagram = Vec::new();
    datagram.push(PacketType::Initial as u8);
    datagram.extend_from_slice(&velocity_core::CURRENT_VERSION.to_be_bytes());
    let dcid = [0x11u8; 8];
    let scid = [0x22u8; 8];
    datagram.push(dcid.len() as u8);
    datagram.push(scid.len() as u8);
    let payload = vec![0u8; 12];
    datagram.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    datagram.extend_from_slice(&dcid);
    datagram.extend_from_slice(&scid);
    datagram.extend_from_slice(&payload);
    let mut sealed = datagram;
    security.seal_outbound(&mut sealed);

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("udp bind");
    socket
        .send_to(&sealed, target)
        .await
        .expect("send datagram");
}

async fn perform_https_handshake(
    stream: TcpStream,
    profile: SecurityProfile,
    suite: pqq_tls::HybridSuite,
    kem_public: Vec<u8>,
) -> Result<TcpStream, HybridHandshakeError> {
    match profile {
        SecurityProfile::Turbo => {
            client_handshake_flow::<MlKem512>(stream, suite, kem_public).await
        }
        SecurityProfile::Balanced => {
            client_handshake_flow::<MlKem768>(stream, suite, kem_public).await
        }
        SecurityProfile::Fortress => {
            client_handshake_flow::<MlKem1024>(stream, suite, kem_public).await
        }
    }
}

async fn client_handshake_flow<P: pqq_tls::KemProvider + Copy + Default>(
    stream: TcpStream,
    suite: pqq_tls::HybridSuite,
    kem_public: Vec<u8>,
) -> Result<TcpStream, HybridHandshakeError> {
    let mut stream = stream;
    let handshake = ClientHandshake::new(
        P::default(),
        suite,
        kem_public,
        ClientHelloOptions::default(),
    )?;
    write_framed(&mut stream, handshake.client_payload_bytes())
        .await
        .expect("write client hello");

    let server_bytes = read_framed(&mut stream).await.expect("read server hello");
    let server_payload: ServerHelloPayload =
        cbor_from_slice(&server_bytes).expect("decode server hello");

    let completion = handshake.complete(&server_payload)?;
    let finished_bytes = cbor_to_vec(&completion.client_finished).expect("encode finished");
    write_framed(&mut stream, &finished_bytes)
        .await
        .expect("write client finished");

    Ok(stream)
}

async fn read_framed(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_framed(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

#[tokio::test]
async fn serves_udp_and_https() {
    let udp_security = Arc::new(SecurityContext::new(SecurityConfig::default()));
    let udp_addr = next_loopback_addr();
    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

    let udp_runner = {
        let security = Arc::clone(&udp_security);
        let dispatcher = move |packet, peer| {
            let _ = packet_tx.send((packet, peer));
        };
        tokio::spawn(async move {
            let _ = run_udp_loop(udp_addr, security, dispatcher).await;
        })
    };

    send_sample_datagram(&udp_security, udp_addr).await;
    let observed = timeout(Duration::from_secs(1), packet_rx.recv())
        .await
        .expect("dispatcher invocation")
        .expect("packet contents");

    assert_eq!(observed.0.header.packet_type, PacketType::Initial);
    assert_eq!(observed.0.header.payload_length as usize, 12);

    udp_runner.abort();

    let https_server = HttpsServer::bind(HttpsConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        security_profile: SecurityProfile::Balanced,
        ticket_lifetime: Duration::from_secs(900),
    })
    .await
    .expect("bind https listener");

    let https_addr = https_server.local_addr().expect("https addr");
    let kem_public = https_server.kem_public_key().to_vec();
    let suite = https_server.suite();
    let profile = https_server.profile();
    let handle = https_server.spawn_hello();

    let mut stream = TcpStream::connect(https_addr).await.expect("tcp connect");
    stream = perform_https_handshake(stream, profile, suite, kem_public)
        .await
        .expect("handshake complete");

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");

    let mut response_bytes = Vec::new();
    stream
        .read_to_end(&mut response_bytes)
        .await
        .expect("read response");

    let response_text = String::from_utf8_lossy(&response_bytes);
    assert!(response_text.contains("Hello from Velocity HTTPS preview"));

    handle.shutdown().await.expect("shutdown https");
}
