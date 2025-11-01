use std::net::SocketAddr;
use clap::Parser;
use tokio::net::UdpSocket;
use tokio::time::{self, Duration};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Address to listen on for client connections (proxy).
    #[clap(long, default_value = "127.0.0.1:7000")]
    listen: String,

    /// Upstream server address to forward packets to.
    #[clap(long, default_value = "127.0.0.1:7001")]
    server: String,

    /// If set, tamper client->server packets by XORing a byte at offset.
    #[clap(long, default_value_t = 0)]
    tamper_offset: usize,

    /// Number of bytes to XOR with (0 means no tamper)
    #[clap(long, default_value_t = 0u8)]
    tamper_xor: u8,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();
    let listen_addr: SocketAddr = args.listen.parse()?;
    let server_addr: SocketAddr = args.server.parse()?;

    let socket = UdpSocket::bind(listen_addr).await?;
    log::info!("UDP MITM listening on {} -> upstream {}", listen_addr, server_addr);

    let mut buf = vec![0u8; 65535];
    // We'll record the first peer we see as the client.
    let mut client_addr: Option<SocketAddr> = None;

    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        let packet = &mut buf[..len];

        // Discover client address
        if client_addr.is_none() {
            // If packet came from server, maybe we started in opposite order; still set client on first non-server address.
            if src != server_addr {
                client_addr = Some(src);
                log::info!("Learned client address: {}", src);
            }
        }

        // Decide direction: client->server if src == client_addr; server->client if src == server_addr
        if Some(src) == client_addr {
            // client -> server
            let mut out = packet.to_vec();
            if args.tamper_xor != 0 && args.tamper_offset < out.len() {
                out[args.tamper_offset] ^= args.tamper_xor;
                log::warn!("Tampered packet from client: flipped offset {} with xor {:#x}", args.tamper_offset, args.tamper_xor);
            } else if args.tamper_xor != 0 {
                log::warn!("Tamper offset {} out of range for packet len {}", args.tamper_offset, out.len());
            }
            socket.send_to(&out, server_addr).await?;
            log::debug!("Forwarded {} bytes client->server", out.len());
        } else if src == server_addr {
            // server -> client
            if let Some(ca) = client_addr {
                socket.send_to(packet, ca).await?;
                log::debug!("Forwarded {} bytes server->client", packet.len());
            } else {
                log::warn!("Received packet from server but client unknown; dropping");
            }
        } else {
            // Unknown peer (neither server nor client). If we haven't seen client, treat as client.
            if client_addr.is_none() {
                client_addr = Some(src);
                log::info!("Learned client address (late): {}", src);
                // forward to server
                let mut out = packet.to_vec();
                if args.tamper_xor != 0 && args.tamper_offset < out.len() {
                    out[args.tamper_offset] ^= args.tamper_xor;
                    log::warn!("Tampered packet from client (late): flipped offset {}", args.tamper_offset);
                }
                socket.send_to(&out, server_addr).await?;
            } else {
                // unexpected
                log::warn!("Packet from unknown {} (client known {}) - dropping", src, client_addr.unwrap());
            }
        }

        // tiny sleep to avoid busy-loop in some environments
        time::sleep(Duration::from_millis(1)).await;
    }
}
