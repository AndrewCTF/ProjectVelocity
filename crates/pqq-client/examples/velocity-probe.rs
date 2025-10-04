use std::env;
use std::error::Error;
use std::net::SocketAddr;

use pqq_core::{
    build_initial_packet, decode_handshake_response, ChunkAssembler, FrameSequencer,
    HandshakeResponse, FRAME_HEADER_LEN, FRAME_MAX_PAYLOAD, HANDSHAKE_MESSAGE_MAX,
};
use tokio::net::UdpSocket;

fn parse_args() -> Result<(SocketAddr, Vec<String>), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let server = args
        .next()
        .ok_or("Usage: velocity-probe <host:port> [alpn_csv]")?;
    let server: SocketAddr = server.parse()?;
    let alpns = args
        .next()
        .map(|csv| csv.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_else(|| vec!["velocity/1".to_string(), "h3".to_string()]);

    Ok((server, alpns))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (server, alpns) = match parse_args() {
        Ok(values) => values,
        Err(err) => {
            eprintln!("{err}");
            return Ok(());
        }
    };

    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|err| -> Box<dyn Error> { Box::new(err) })?;
    socket
        .connect(server)
        .await
        .map_err(|err| -> Box<dyn Error> { Box::new(err) })?;

    let packet = build_initial_packet(alpns.clone());
    socket
        .send(&packet)
        .await
        .map_err(|err| -> Box<dyn Error> { Box::new(err) })?;

    let mut buf = [0u8; FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD];
    let mut framing = FrameSequencer::new(0, 0);
    let mut assembler = ChunkAssembler::new(HANDSHAKE_MESSAGE_MAX);
    let payload: Vec<u8> = loop {
        let len = socket
            .recv(&mut buf)
            .await
            .map_err(|err| -> Box<dyn Error> { Box::new(err) })?;
        let slice = match framing.decode(&buf[..len]) {
            Ok(slice) => slice,
            Err(err) => {
                return Err(Box::new(pqq_core::HandshakeError::Frame(err)) as Box<dyn Error>);
            }
        };
        match assembler.push_slice(slice) {
            Ok(Some(message)) => break message,
            Ok(None) => continue,
            Err(err) => {
                return Err(Box::new(pqq_core::HandshakeError::Frame(err)) as Box<dyn Error>);
            }
        }
    };

    match decode_handshake_response(&payload) {
        Ok(response) => display_response(server, &alpns, response),
        Err(err) => eprintln!(
            "Failed to decode Velocity handshake response: {err}. Raw bytes: {}",
            to_hex(&payload)
        ),
    }

    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn display_response(server: SocketAddr, alpns: &[String], response: HandshakeResponse) {
    println!("Velocity probe successful: {server}");
    println!("  Offered ALPNs: {}", alpns.join(", "));
    println!("  Resolution: {:?}", response.resolution);

    if let Some(fallback) = response.fallback {
        println!(
            "  Fallback: {} via {}:{}{}",
            fallback.alpn,
            fallback.host,
            fallback.port,
            fallback
                .note
                .as_ref()
                .map(|note| format!(" ({note})"))
                .unwrap_or_default()
        );
    } else {
        println!("  Fallback: <none>");
    }

    if let Some(payload) = response.pq_payload {
        println!("  PQ payload (base64): {payload}");
    }

    if let Some(strict) = response.strict_transport {
        println!(
            "  Strict transport: max_age={} include_subdomains={} preload={}",
            strict.max_age, strict.include_subdomains, strict.preload
        );
    }
}
