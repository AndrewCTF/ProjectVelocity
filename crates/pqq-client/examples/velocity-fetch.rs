use std::env;
use std::error::Error;
use std::fs;
use std::net::SocketAddr;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use pqq_client::{extract_kem_public, Client, ClientConfig, ClientError, SecurityProfile};
use pqq_core::{
    build_initial_packet, decode_handshake_response, AlpnResolution, ChunkAssembler,
    FrameSequencer, HandshakeResponse, FRAME_HEADER_LEN, FRAME_MAX_PAYLOAD, HANDSHAKE_MESSAGE_MAX,
};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = Args::parse()?;

    let mut warmup_response = None;
    let kem_public = match args.kem_public.take() {
        Some(key) => key,
        None => match initial_probe(args.server, &args.alpns).await {
            Ok(response) => {
                warmup_response = Some(response.clone());
                match response.resolution {
                    AlpnResolution::Supported(_) => {
                        if let Some(key) = extract_kem_public(&response) {
                            key
                        } else {
                            eprintln!(
                                "Server did not include a usable PQ payload in its Velocity handshake response."
                            );
                            print_fallback(&response);
                            eprintln!(
                                "Ask the operator to enable --publish-kem or provide the ML-KEM public key via --kem-b64/--kem-file."
                            );
                            return Ok(());
                        }
                    }
                    _ => {
                        print_fallback(&response);
                        return Ok(());
                    }
                }
            }
            Err(err) => {
                eprintln!("Failed to perform the Velocity probe: {err}");
                return Ok(());
            }
        },
    };

    let client = Client::new(
        ClientConfig::new(args.server)
            .with_alpns(args.alpns.clone())
            .with_server_kem_public(kem_public.clone())
            .with_security_profile(args.profile),
    );

    if let Some(response) = warmup_response {
        println!("Velocity probe: {:?}", response.resolution);
    }

    match client.get(&args.url).await {
        Ok(body) => {
            println!(
                "Velocity request succeeded\n-----------------------\n{}",
                body
            );
        }
        Err(ClientError::AlpnFallback(response)) => {
            print_fallback(&response);
        }
        Err(ClientError::AlpnUnsupported(response)) => {
            eprintln!(
                "Velocity handshake unsupported. Server response: {:?}",
                response
            );
            print_fallback(&response);
        }
        Err(err) => {
            eprintln!("Velocity request failed: {err}");
        }
    }

    Ok(())
}

fn print_fallback(response: &HandshakeResponse) {
    if let Some(fallback) = &response.fallback {
        eprintln!(
            "Server advised fallback to {} via {}:{}",
            fallback.alpn, fallback.host, fallback.port
        );
        if let Some(note) = &fallback.note {
            eprintln!("Note: {note}");
        }
    } else {
        eprintln!("Server did not advertise a fallback endpoint.");
    }
}

struct Args {
    server: SocketAddr,
    url: String,
    kem_public: Option<Vec<u8>>,
    alpns: Vec<String>,
    profile: SecurityProfile,
}

impl Args {
    fn parse() -> Result<Self, Box<dyn Error>> {
        let mut iter = env::args().skip(1);

        let server = iter
            .next()
            .ok_or("Usage: velocity-fetch <server:port> <url> [--kem-file path | --kem-b64 b64] [--alpn list] [--profile turbo|balanced|fortress]")?;
        let url = iter
            .next()
            .ok_or("Usage: velocity-fetch <server:port> <url> [--kem-file path | --kem-b64 b64] [--alpn list] [--profile turbo|balanced|fortress]")?;

        let mut kem_public = None;
        let mut alpns: Vec<String> = vec![
            "velocity/1".to_string(),
            "pqq/1".to_string(),
            "h3".to_string(),
        ];
        let mut profile = SecurityProfile::Balanced;

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--kem-file" => {
                    let path = iter
                        .next()
                        .ok_or("--kem-file requires a path to the server KEM public key")?;
                    kem_public = Some(fs::read(path)?);
                }
                "--kem-b64" => {
                    let value = iter
                        .next()
                        .ok_or("--kem-b64 requires a base64-encoded key string")?;
                    kem_public = Some(BASE64_STANDARD.decode(value.as_bytes())?);
                }
                "--alpn" => {
                    let value = iter
                        .next()
                        .ok_or("--alpn requires a comma-separated ALPN list")?;
                    alpns = value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "--profile" => {
                    let value = iter
                        .next()
                        .ok_or("--profile requires turbo|balanced|fortress")?;
                    profile = match value.to_lowercase().as_str() {
                        "turbo" => SecurityProfile::Turbo,
                        "balanced" => SecurityProfile::Balanced,
                        "fortress" => SecurityProfile::Fortress,
                        other => return Err(format!("unknown profile '{other}'").into()),
                    };
                }
                other => {
                    return Err(format!("unknown argument '{other}'").into());
                }
            }
        }

        Ok(Self {
            server: server.parse()?,
            url,
            kem_public,
            alpns,
            profile,
        })
    }
}

async fn initial_probe(
    server: SocketAddr,
    alpns: &[String],
) -> Result<HandshakeResponse, ProbeError> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
    socket.connect(server).await?;

    let packet = build_initial_packet(alpns.iter().map(|s| s.as_str()));
    socket.send(&packet).await?;

    let mut buf = [0u8; FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD];
    let mut framing = FrameSequencer::new(0, 0);
    let mut assembler = ChunkAssembler::new(HANDSHAKE_MESSAGE_MAX);
    let response_bytes = loop {
        let len = socket.recv(&mut buf).await?;
        let slice = framing
            .decode(&buf[..len])
            .map_err(|err| ProbeError::Handshake(pqq_core::HandshakeError::Frame(err)))?;
        if let Some(message) = assembler
            .push_slice(slice)
            .map_err(|err| ProbeError::Handshake(pqq_core::HandshakeError::Frame(err)))?
        {
            break message;
        }
    };
    let response = decode_handshake_response(&response_bytes)?;
    Ok(response)
}

#[derive(Debug)]
enum ProbeError {
    Io(std::io::Error),
    Handshake(pqq_core::HandshakeError),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::Io(err) => write!(f, "{err}"),
            ProbeError::Handshake(err) => write!(f, "{err}"),
        }
    }
}

impl Error for ProbeError {}

impl From<std::io::Error> for ProbeError {
    fn from(err: std::io::Error) -> Self {
        ProbeError::Io(err)
    }
}

impl From<pqq_core::HandshakeError> for ProbeError {
    fn from(err: pqq_core::HandshakeError) -> Self {
        ProbeError::Handshake(err)
    }
}
