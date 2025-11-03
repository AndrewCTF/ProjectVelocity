use std::net::SocketAddr;
use clap::Parser;
use tokio::net::UdpSocket;
use tokio::time::{self, Duration};
use std::time::Instant;
use rand::Rng;

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
    /// Truncate client->server packets to this length (0 means no truncation)
    #[clap(long, default_value_t = 0)]
    truncate: usize,
    /// Duplicate client->server packets N times (0 means no duplication)
    #[clap(long, default_value_t = 0u8)]
    dup: u8,
    /// Add a per-packet delay in ms
    #[clap(long, default_value_t = 0u64)]
    delay_ms: u64,
    /// Drop rate (0-100) percent of client->server packets to randomly drop
    #[clap(long, default_value_t = 0u8)]
    drop_rate: u8,
    /// Exit after forwarding this many packets total (0 means run forever)
    #[clap(long, default_value_t = 0u64)]
    max_packets: u64,
    /// Idle timeout in milliseconds — exit if no packets seen for this many ms (0 means no timeout)
    #[clap(long, default_value_t = 10000u64)]
    idle_timeout_ms: u64,
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
    let mut forwarded_packets: u64 = 0;
    let idle_timeout = Duration::from_millis(args.idle_timeout_ms);
    let mut last_activity = Instant::now();

    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        let packet = &mut buf[..len];
    last_activity = Instant::now();

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
            // Random drop
            if args.drop_rate > 0 {
                let mut rng = rand::thread_rng();
                let roll: u8 = rng.gen_range(0..100);
                if roll < args.drop_rate {
                    log::warn!("Dropped packet from client (drop_rate {}%)", args.drop_rate);
                    continue;
                }
            }

            if args.tamper_xor != 0 && args.tamper_offset < out.len() {
                out[args.tamper_offset] ^= args.tamper_xor;
                log::warn!("Tampered packet from client: flipped offset {} with xor {:#x}", args.tamper_offset, args.tamper_xor);
            } else if args.tamper_xor != 0 {
                log::warn!("Tamper offset {} out of range for packet len {}", args.tamper_offset, out.len());
            }

            if args.truncate > 0 && args.truncate < out.len() {
                out.truncate(args.truncate);
                log::warn!("Truncated packet to {} bytes", args.truncate);
            }

            let send_times = if args.dup > 0 { args.dup as usize } else { 1 };
            for i in 0..send_times {
                if args.delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(args.delay_ms)).await;
                }
                socket.send_to(&out, server_addr).await?;
                log::debug!("Forwarded {} bytes client->server (dup idx {})", out.len(), i);
                forwarded_packets += 1;
                if args.max_packets > 0 && forwarded_packets >= args.max_packets {
                    log::info!("Reached max_packets={}, exiting", args.max_packets);
                    return Ok(());
                }
            }
        } else if src == server_addr {
            // server -> client
            if let Some(ca) = client_addr {
                socket.send_to(packet, ca).await?;
                log::debug!("Forwarded {} bytes server->client", packet.len());
                forwarded_packets += 1;
                if args.max_packets > 0 && forwarded_packets >= args.max_packets {
                    log::info!("Reached max_packets={} (server->client), exiting", args.max_packets);
                    return Ok(());
                }
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
        // Exit if idle timeout exceeded
        if args.idle_timeout_ms > 0 && last_activity.elapsed() > idle_timeout {
            log::info!("Idle timeout exceeded ({} ms), exiting", args.idle_timeout_ms);
            return Ok(());
        }
        time::sleep(Duration::from_millis(1)).await;
    }
}
