//! Core transport primitives for the Velocity protocol.
//!
//! This crate currently offers three foundational pieces used by the
//! wider Velocity stack:
//!
//! * `run_udp_loop` — a Tokio-based UDP receive loop that parses
//!   Velocity datagrams and hands them to a caller-provided dispatcher.
//! * `parse_packet` and supporting packet data structures — a compact
//!   reference framing layout suitable for early interoperability tests.
//! * `negotiate_alpn` — a helper that determines whether Velocity can
//!   be spoken with a remote peer based on the ALPN values exchanged
//!   during connection establishment.
//!
//! The implementations are intentionally simple: they set a baseline
//! for discussion, fuzzing and performance work while the full QUIC-
//! compatible transport machinery is developed.

pub mod https;

pub use https::{HttpsConfig, HttpsError, HttpsHandle, HttpsServer};

use ahash::AHashMap;
use bytes::BytesMut;
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use rand::{rngs::OsRng, RngCore};
use sha3::Sha3_256;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::net::UdpSocket;
use tracing::debug;

type HmacSha3 = Hmac<Sha3_256>;

/// Velocity's ALPN identifier used during TLS-style negotiation.
pub const VELOCITY_ALPN: &str = "velocity/1";

/// Experimental on-wire version tag (ASCII `VLC1`).
pub const CURRENT_VERSION: u32 = 0x564C4331;

/// Maximum size of a Velocity datagram accepted by the parser.
const MAX_DATAGRAM_SIZE: usize = 64 * 1024;

const HEADER_TAG_LEN: usize = 32;
const MIN_CONNECTION_ID_LEN: usize = 8;
const MAX_CONNECTION_ID_LEN: usize = 20;
const MAX_ALPN_LIST_LEN: usize = 256;

/// Enumerates the recognised Velocity long-packet types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Initial = 0x0,
    Handshake = 0x1,
    OneRtt = 0x2,
    Retry = 0x3,
}

impl TryFrom<u8> for PacketType {
    type Error = ParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x0 => Ok(PacketType::Initial),
            0x1 => Ok(PacketType::Handshake),
            0x2 => Ok(PacketType::OneRtt),
            0x3 => Ok(PacketType::Retry),
            other => Err(ParseError::UnknownPacketType(other)),
        }
    }
}

/// Header information shared by all Velocity packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    pub version: u32,
    pub packet_type: PacketType,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub payload_length: u16,
}

/// Parsed Velocity packet consisting of a header and payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VelocityPacket {
    pub header: PacketHeader,
    pub payload: BytesMut,
}

/// Errors returned by [`parse_packet`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    /// The datagram did not contain enough bytes for the fixed header.
    #[error("truncated datagram")]
    Truncated,
    /// A packet advertised lengths that exceeded the datagram bounds.
    #[error("invalid length fields")]
    InvalidLengths,
    /// Packet type byte was not recognised.
    #[error("unknown packet type {0}")]
    UnknownPacketType(u8),
    /// Datagrams larger than [`MAX_DATAGRAM_SIZE`] are rejected early.
    #[error("datagram exceeds maximum size {MAX_DATAGRAM_SIZE}")]
    DatagramTooLarge,
    /// Connection IDs shorter than the configured minimum are rejected.
    #[error("connection id too short")]
    ConnectionIdTooShort,
    /// Connection IDs longer than allowed are rejected to avoid large allocations.
    #[error("connection id too long")]
    ConnectionIdTooLong,
    /// Header authentication failed.
    #[error("header authentication failed")]
    HeaderAuthFailed,
}

/// Configuration knobs governing inbound packet validation.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub max_datagram_size: usize,
    pub min_connection_id_len: usize,
    pub max_connection_id_len: usize,
    pub max_alpn_list_len: usize,
    pub header_key: [u8; 32],
    pub max_initials_per_second: u32,
    pub packet_window: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        let mut header_key = [0u8; 32];
        OsRng.fill_bytes(&mut header_key);
        Self {
            max_datagram_size: MAX_DATAGRAM_SIZE,
            min_connection_id_len: MIN_CONNECTION_ID_LEN,
            max_connection_id_len: MAX_CONNECTION_ID_LEN,
            max_alpn_list_len: MAX_ALPN_LIST_LEN,
            header_key,
            max_initials_per_second: 10,
            packet_window: 32,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecurityError {
    #[error("datagram exceeds configured maximum")]
    DatagramTooLarge,
    #[error("rate limit exceeded for peer {0}")]
    RateLimited(SocketAddr),
    #[error("header authentication failed")]
    HeaderAuth,
    #[error("connection id reuse detected")]
    ConnectionCollision,
    #[error("packet number replay detected")]
    PacketReplay,
}

#[derive(Debug)]
pub struct SecurityContext {
    config: SecurityConfig,
    header: HeaderProtector,
    seen_connections: Mutex<AHashMap<Vec<u8>, SocketAddr>>,
    packet_windows: Mutex<AHashMap<Vec<u8>, u64>>,
    rate_limiter: RateLimiter,
}

impl SecurityContext {
    pub fn new(config: SecurityConfig) -> Self {
        let header = HeaderProtector::new(config.header_key);
        let burst = config.max_initials_per_second.max(1);
        Self {
            config,
            header,
            seen_connections: Mutex::new(AHashMap::new()),
            packet_windows: Mutex::new(AHashMap::new()),
            rate_limiter: RateLimiter::new(Duration::from_secs(1), burst),
        }
    }

    pub fn config(&self) -> &SecurityConfig {
        &self.config
    }

    pub fn seal_outbound(&self, datagram: &mut Vec<u8>) {
        self.header.seal(datagram);
    }

    pub fn verify_and_register<'a>(
        &self,
        peer: SocketAddr,
        datagram: &'a [u8],
    ) -> Result<&'a [u8], SecurityError> {
        if datagram.len() > self.config.max_datagram_size {
            return Err(SecurityError::DatagramTooLarge);
        }

        if !self.rate_limiter.try_consume(peer.ip()) {
            return Err(SecurityError::RateLimited(peer));
        }

        let body = self
            .header
            .open(datagram)
            .map_err(|_| SecurityError::HeaderAuth)?;

        Ok(body)
    }

    pub fn enforce_packet_rules(
        &self,
        peer: SocketAddr,
        packet: &VelocityPacket,
    ) -> Result<(), SecurityError> {
        self.enforce_connection_id(peer, &packet.header.dcid)?;
        self.enforce_packet_number(&packet.header.dcid, &packet.payload)
    }

    fn enforce_connection_id(&self, peer: SocketAddr, dcid: &[u8]) -> Result<(), SecurityError> {
        let mut guard = self.seen_connections.lock();
        if let Some(existing) = guard.get(dcid) {
            if *existing == peer {
                Ok(())
            } else {
                Err(SecurityError::ConnectionCollision)
            }
        } else {
            guard.insert(dcid.to_vec(), peer);
            Ok(())
        }
    }

    fn enforce_packet_number(&self, dcid: &[u8], payload: &[u8]) -> Result<(), SecurityError> {
        if payload.len() < 8 {
            return Err(SecurityError::PacketReplay);
        }
        let mut number_bytes = [0u8; 8];
        number_bytes.copy_from_slice(&payload[..8]);
        let packet_number = u64::from_be_bytes(number_bytes);

        let mut windows = self.packet_windows.lock();
        let entry = windows.entry(dcid.to_vec()).or_insert(0);
        if packet_number < *entry {
            return Err(SecurityError::PacketReplay);
        }
        if packet_number > *entry + self.config.packet_window {
            return Err(SecurityError::PacketReplay);
        }
        *entry = packet_number + 1;
        Ok(())
    }
}

#[derive(Debug)]
struct HeaderProtector {
    key: [u8; 32],
}

impl HeaderProtector {
    fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn seal(&self, datagram: &mut Vec<u8>) {
        let mut mac = HmacSha3::new_from_slice(&self.key).expect("header mac key");
        mac.update(datagram);
        let tag = mac.finalize().into_bytes();
        datagram.extend_from_slice(&tag);
    }

    fn open<'a>(&self, datagram: &'a [u8]) -> Result<&'a [u8], ParseError> {
        if datagram.len() < HEADER_TAG_LEN {
            return Err(ParseError::Truncated);
        }
        let (body, tag) = datagram.split_at(datagram.len() - HEADER_TAG_LEN);
        let mut mac = HmacSha3::new_from_slice(&self.key).expect("header mac key");
        mac.update(body);
        let expected = mac.finalize().into_bytes();
        if expected.ct_eq(tag).unwrap_u8() == 0 {
            return Err(ParseError::HeaderAuthFailed);
        }
        Ok(body)
    }
}

#[derive(Debug)]
struct RateLimiter {
    refill_interval: Duration,
    buckets: Mutex<AHashMap<IpAddr, Bucket>>,
    max_tokens: u32,
}

#[derive(Debug)]
struct Bucket {
    tokens: u32,
    last_refill: Instant,
}

impl RateLimiter {
    fn new(refill_interval: Duration, max_tokens: u32) -> Self {
        Self {
            refill_interval,
            buckets: Mutex::new(AHashMap::new()),
            max_tokens,
        }
    }

    fn try_consume(&self, ip: IpAddr) -> bool {
        let mut guard = self.buckets.lock();
        let bucket = guard.entry(ip).or_insert_with(|| Bucket {
            tokens: self.max_tokens,
            last_refill: Instant::now(),
        });

        let now = Instant::now();
        if now.duration_since(bucket.last_refill) >= self.refill_interval {
            bucket.tokens = self.max_tokens;
            bucket.last_refill = now;
        }

        if bucket.tokens == 0 {
            return false;
        }
        bucket.tokens -= 1;
        true
    }
}

/// Attempt to parse a Velocity packet from `datagram`.
///
/// The reference layout is intentionally compact for the prototype:
///
/// ```text
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |T| Version (32 bits)         |DCID Len|SCID Len| Payload Len   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Destination Connection ID ...                                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Source Connection ID ...                                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Payload ...                                                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// where `T` is the packet type nibble.
pub fn parse_packet(datagram: &[u8]) -> Result<VelocityPacket, ParseError> {
    if datagram.len() > MAX_DATAGRAM_SIZE {
        return Err(ParseError::DatagramTooLarge);
    }

    if datagram.len() < 9 {
        return Err(ParseError::Truncated);
    }

    let packet_type = PacketType::try_from(datagram[0])?;
    let version = u32::from_be_bytes([datagram[1], datagram[2], datagram[3], datagram[4]]);
    let dcid_len = datagram[5] as usize;
    let scid_len = datagram[6] as usize;

    if dcid_len < MIN_CONNECTION_ID_LEN || scid_len < MIN_CONNECTION_ID_LEN {
        return Err(ParseError::ConnectionIdTooShort);
    }

    if dcid_len > MAX_CONNECTION_ID_LEN || scid_len > MAX_CONNECTION_ID_LEN {
        return Err(ParseError::ConnectionIdTooLong);
    }
    let payload_len = u16::from_be_bytes([datagram[7], datagram[8]]) as usize;

    let header_len = 9 + dcid_len + scid_len;
    if datagram.len() < header_len {
        return Err(ParseError::InvalidLengths);
    }

    let remaining = datagram.len() - header_len;
    if remaining < payload_len {
        return Err(ParseError::InvalidLengths);
    }

    let payload_end = header_len + payload_len;

    let dcid = datagram[9..9 + dcid_len].to_vec();
    let scid_start = 9 + dcid_len;
    let scid = datagram[scid_start..scid_start + scid_len].to_vec();
    let payload = BytesMut::from(&datagram[header_len..payload_end]);

    Ok(VelocityPacket {
        header: PacketHeader {
            version,
            packet_type,
            dcid,
            scid,
            payload_length: payload_len as u16,
        },
        payload,
    })
}

/// ALPN negotiation outcome between two peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlpnDecision<'a> {
    /// Both peers agreed to speak Velocity.
    Velocity,
    /// Velocity was unavailable; peers fell back to another ALPN value.
    Fallback(&'a str),
    /// Negotiation failed.
    Reject,
}

/// Determine the negotiated ALPN given `client_offered` values and the
/// `server_supported` list returned by the peer.
///
/// The function prefers Velocity when offered by both sides. Otherwise
/// it picks the first mutually supported protocol returned by the
/// server, enabling structured fallback flows.
pub fn negotiate_alpn<'a>(
    client_offered: &'a [&'a str],
    server_supported: &'a [&'a str],
) -> AlpnDecision<'a> {
    let client_has_velocity = client_offered.contains(&VELOCITY_ALPN);
    let server_has_velocity = server_supported.contains(&VELOCITY_ALPN);

    if client_has_velocity && server_has_velocity {
        return AlpnDecision::Velocity;
    }

    for server_alpn in server_supported {
        if client_offered
            .iter()
            .any(|candidate| candidate == server_alpn)
        {
            return AlpnDecision::Fallback(server_alpn);
        }
    }

    AlpnDecision::Reject
}

/// Trait implemented by callers that wish to receive parsed packets
/// from the UDP loop.
pub trait PacketDispatcher: Send + Sync {
    fn dispatch(&self, packet: VelocityPacket, peer: SocketAddr);
}

impl<T> PacketDispatcher for T
where
    T: Fn(VelocityPacket, SocketAddr) + Send + Sync,
{
    fn dispatch(&self, packet: VelocityPacket, peer: SocketAddr) {
        (self)(packet, peer);
    }
}

/// Minimal Tokio-based UDP loop that waits for datagrams, attempts to
/// parse them as Velocity packets, and forwards the result to `dispatcher`.
///
/// Malformed packets are logged at debug level and dropped. The stub
/// intentionally avoids allocation-heavy buffering so microbenchmarks
/// can focus on parser costs.
pub async fn run_udp_loop<D>(
    bind_addr: SocketAddr,
    security: Arc<SecurityContext>,
    dispatcher: D,
) -> tokio::io::Result<()>
where
    D: PacketDispatcher,
{
    let socket = UdpSocket::bind(bind_addr).await?;
    let mut buffer = vec![0u8; security.config.max_datagram_size + HEADER_TAG_LEN];

    loop {
        let (len, peer) = socket.recv_from(&mut buffer).await?;
        let datagram = &buffer[..len];

        let body = match security.verify_and_register(peer, datagram) {
            Ok(body) => body,
            Err(err) => {
                debug!(?err, %peer, "security preflight failed");
                continue;
            }
        };

        match parse_packet(body) {
            Ok(packet) => {
                if let Err(err) = security.enforce_packet_rules(peer, &packet) {
                    debug!(?err, %peer, "dropping packet failing policy");
                    continue;
                }
                dispatcher.dispatch(packet, peer)
            }
            Err(err) => debug!(?err, "dropping malformed packet"),
        }
    }
}

/// Describes the outcome of an ALPN negotiation performed by the handshake harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeOutcome {
    Velocity { selected_alpn: String },
    Fallback { selected_alpn: String },
    Reject,
}

/// Context provided to a dispatcher each time the harness observes an Initial packet.
#[derive(Debug, Clone)]
pub struct HandshakeContext {
    pub peer: SocketAddr,
    pub packet: VelocityPacket,
    pub offered_alpns: Vec<String>,
    pub outcome: HandshakeOutcome,
}

/// Trait implemented by components that wish to react to Velocity Initial packets.
pub trait HandshakeDispatcher: Send + Sync + 'static {
    fn handle_handshake(&self, ctx: HandshakeContext) -> Option<Vec<u8>>;
}

/// Drives ALPN negotiation for incoming Velocity Initial packets and gives callers a chance
/// to produce follow-up datagrams (e.g. PQ handshake responses).
pub async fn run_handshake_harness(
    socket: UdpSocket,
    security: Arc<SecurityContext>,
    server_supported: Vec<String>,
    dispatcher: Arc<dyn HandshakeDispatcher>,
) -> std::io::Result<()> {
    let server_supported = Arc::new(server_supported);
    let mut buffer = vec![0u8; security.config.max_datagram_size + HEADER_TAG_LEN];

    loop {
        let (len, peer) = socket.recv_from(&mut buffer).await?;
        let datagram = &buffer[..len];

        let body = match security.verify_and_register(peer, datagram) {
            Ok(body) => body,
            Err(err) => {
                debug!(?err, %peer, "security preflight failed");
                continue;
            }
        };

        let packet = match parse_packet(body) {
            Ok(packet) => packet,
            Err(err) => {
                debug!(?err, %peer, "dropping malformed Velocity packet");
                continue;
            }
        };

        if packet.header.packet_type != PacketType::Initial {
            debug!(packet_type = ?packet.header.packet_type, %peer, "ignoring non-Initial packet");
            continue;
        }

        if let Err(err) = security.enforce_packet_rules(peer, &packet) {
            debug!(?err, %peer, "dropping packet failing policy");
            continue;
        }

        let offered = match parse_offered_alpns(packet.payload.as_ref()) {
            Ok(list) => list,
            Err(err) => {
                debug!(?err, %peer, "failed to parse ALPN payload");
                continue;
            }
        };

        let client_refs: Vec<&str> = offered.iter().map(String::as_str).collect();
        let server_refs: Vec<&str> = server_supported.iter().map(String::as_str).collect();

        let decision = match negotiate_alpn(&client_refs, &server_refs) {
            AlpnDecision::Velocity => HandshakeOutcome::Velocity {
                selected_alpn: VELOCITY_ALPN.to_string(),
            },
            AlpnDecision::Fallback(alpn) => HandshakeOutcome::Fallback {
                selected_alpn: alpn.to_string(),
            },
            AlpnDecision::Reject => HandshakeOutcome::Reject,
        };

        let context = HandshakeContext {
            peer,
            packet: packet.clone(),
            offered_alpns: offered,
            outcome: decision,
        };

        if let Some(mut response) = dispatcher.handle_handshake(context) {
            security.seal_outbound(&mut response);
            if let Err(err) = socket.send_to(&response, peer).await {
                debug!(%peer, ?err, "failed to emit handshake response");
            }
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
enum HandshakeHarnessError {
    #[error("payload missing ALPN prefix")]
    MissingPrefix,
    #[error("payload not valid UTF-8")]
    InvalidUtf8,
    #[error("payload too short for packet number")]
    TooShort,
    #[error("alpn payload exceeds configured maximum")]
    TooLong,
}

fn parse_offered_alpns(payload: &[u8]) -> Result<Vec<String>, HandshakeHarnessError> {
    if payload.len() < 8 {
        return Err(HandshakeHarnessError::TooShort);
    }
    let payload = &payload[8..];
    const PREFIX: &str = "ALPN\0";
    if payload.len() < PREFIX.len() {
        return Err(HandshakeHarnessError::MissingPrefix);
    }
    let prefix = &payload[..PREFIX.len()];
    if prefix != PREFIX.as_bytes() {
        return Err(HandshakeHarnessError::MissingPrefix);
    }
    let rest = std::str::from_utf8(&payload[PREFIX.len()..])
        .map_err(|_| HandshakeHarnessError::InvalidUtf8)?;
    if rest.len() > MAX_ALPN_LIST_LEN {
        return Err(HandshakeHarnessError::TooLong);
    }
    let mut alpns = Vec::new();
    for entry in rest.split(',') {
        if !entry.is_empty() {
            alpns.push(entry.to_string());
        }
    }
    Ok(alpns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use tokio::net::UdpSocket;
    use tokio::sync::oneshot;
    use tokio::time::{timeout, Duration};

    fn test_security_context() -> Arc<SecurityContext> {
        let cfg = SecurityConfig {
            header_key: [0x55; 32],
            max_initials_per_second: 1_000,
            packet_window: 1024,
            ..SecurityConfig::default()
        };
        Arc::new(SecurityContext::new(cfg))
    }

    fn build_sample_packet() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(PacketType::Initial as u8);
        bytes.extend_from_slice(&CURRENT_VERSION.to_be_bytes());
        let dcid = [0xAAu8; MIN_CONNECTION_ID_LEN];
        let scid = [0x11u8; MIN_CONNECTION_ID_LEN];
        bytes.push(dcid.len() as u8); // dcid length
        bytes.push(scid.len() as u8); // scid length
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u64.to_be_bytes());
        payload.extend_from_slice(b"hello");
        bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&dcid);
        bytes.extend_from_slice(&scid);
        bytes.extend_from_slice(&payload);
        bytes
    }

    #[test]
    fn parses_valid_packet() {
        let bytes = build_sample_packet();
        let packet = parse_packet(&bytes).expect("packet parses");

        assert_eq!(packet.header.packet_type, PacketType::Initial);
        assert_eq!(packet.header.version, CURRENT_VERSION);
        assert_eq!(packet.header.dcid, vec![0xAA; MIN_CONNECTION_ID_LEN]);
        assert_eq!(packet.header.scid, vec![0x11; MIN_CONNECTION_ID_LEN]);
        assert_eq!(packet.header.payload_length, 8 + 5);
        assert_eq!(&packet.payload[..8], &0u64.to_be_bytes());
        assert_eq!(&packet.payload[8..], b"hello");
    }

    #[test]
    fn rejects_truncated_header() {
        let bytes = vec![0x00, 0x01];
        let err = parse_packet(&bytes).unwrap_err();
        assert_eq!(err, ParseError::Truncated);
    }

    #[test]
    fn rejects_invalid_lengths() {
        let mut bytes = build_sample_packet();
        bytes[7] = 0xFF;
        bytes[8] = 0xFF; // wildly inflate payload length without providing bytes
        let err = parse_packet(&bytes).unwrap_err();
        assert_eq!(err, ParseError::InvalidLengths);
    }

    #[test]
    fn negotiate_velocity_success() {
        let client = ["velocity/1", "h3"];
        let server = ["velocity/1"];
        assert_eq!(negotiate_alpn(&client, &server), AlpnDecision::Velocity);
    }

    #[test]
    fn negotiate_fallback() {
        let client = ["velocity/1", "h3"];
        let server = ["h3"];
        assert_eq!(
            negotiate_alpn(&client, &server),
            AlpnDecision::Fallback("h3")
        );
    }

    #[test]
    fn negotiate_reject() {
        let client = ["velocity/1"];
        let server = ["spdy/3"];
        assert_eq!(negotiate_alpn(&client, &server), AlpnDecision::Reject);
    }

    fn build_initial_datagram(alpns: &[&str]) -> Vec<u8> {
        let mut payload = String::from("ALPN\0");
        for (idx, alpn) in alpns.iter().enumerate() {
            if idx > 0 {
                payload.push(',');
            }
            payload.push_str(alpn);
        }
        let payload_text = payload.into_bytes();
        let mut payload_bytes = Vec::with_capacity(8 + payload_text.len());
        payload_bytes.extend_from_slice(&0u64.to_be_bytes());
        payload_bytes.extend_from_slice(&payload_text);
        let dcid = [0x21u8; MIN_CONNECTION_ID_LEN];
        let scid = [0x43u8; MIN_CONNECTION_ID_LEN];
        let mut bytes = Vec::with_capacity(9 + dcid.len() + scid.len() + payload_bytes.len());
        bytes.push(PacketType::Initial as u8);
        bytes.extend_from_slice(&CURRENT_VERSION.to_be_bytes());
        bytes.push(dcid.len() as u8);
        bytes.push(scid.len() as u8);
        bytes.extend_from_slice(&(payload_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&dcid);
        bytes.extend_from_slice(&scid);
        bytes.extend_from_slice(&payload_bytes);
        bytes
    }

    #[derive(Default)]
    struct RecordingDispatcher {
        tx: Mutex<Option<oneshot::Sender<HandshakeContext>>>,
    }

    impl RecordingDispatcher {
        fn new(tx: oneshot::Sender<HandshakeContext>) -> Self {
            Self {
                tx: Mutex::new(Some(tx)),
            }
        }
    }

    impl HandshakeDispatcher for RecordingDispatcher {
        fn handle_handshake(&self, ctx: HandshakeContext) -> Option<Vec<u8>> {
            if let Some(tx) = self.tx.lock().expect("mutex poisoned").take() {
                let _ = tx.send(ctx);
            }
            None
        }
    }

    #[tokio::test]
    async fn harness_reports_velocity_selection() {
        let server_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind server socket");
        let server_addr = server_socket.local_addr().expect("server addr");
        let (tx, rx) = oneshot::channel();
        let dispatcher = Arc::new(RecordingDispatcher::new(tx));
        let security = test_security_context();
        let harness = tokio::spawn(run_handshake_harness(
            server_socket,
            security.clone(),
            vec![VELOCITY_ALPN.to_string(), "h3".to_string()],
            dispatcher.clone(),
        ));

        let client = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind client socket");
        let mut payload = build_initial_datagram(&[VELOCITY_ALPN, "h3"]);
        security.seal_outbound(&mut payload);
        client
            .send_to(&payload, server_addr)
            .await
            .expect("send handshake");

        let ctx = timeout(Duration::from_secs(1), rx)
            .await
            .expect("harness response timeout")
            .expect("receive context");

        assert_eq!(ctx.peer, client.local_addr().expect("client addr"));
        assert_eq!(
            ctx.offered_alpns,
            vec![VELOCITY_ALPN.to_string(), "h3".to_string()]
        );
        assert!(matches!(
            ctx.outcome,
            HandshakeOutcome::Velocity { ref selected_alpn }
            if selected_alpn == VELOCITY_ALPN
        ));

        harness.abort();
    }

    #[tokio::test]
    async fn harness_reports_fallback_selection() {
        let server_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind server socket");
        let server_addr = server_socket.local_addr().expect("server addr");
        let (tx, rx) = oneshot::channel();
        let dispatcher = Arc::new(RecordingDispatcher::new(tx));
        let security = test_security_context();
        let harness = tokio::spawn(run_handshake_harness(
            server_socket,
            security.clone(),
            vec![VELOCITY_ALPN.to_string(), "h3".to_string()],
            dispatcher.clone(),
        ));

        let client = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind client socket");
        let mut payload = build_initial_datagram(&["spdy/3", "h3"]);
        security.seal_outbound(&mut payload);
        client
            .send_to(&payload, server_addr)
            .await
            .expect("send handshake");

        let ctx = timeout(Duration::from_secs(1), rx)
            .await
            .expect("harness response timeout")
            .expect("receive context");

        assert!(matches!(
            ctx.outcome,
            HandshakeOutcome::Fallback { ref selected_alpn }
            if selected_alpn == "h3"
        ));

        harness.abort();
    }

    #[derive(Default)]
    struct RespondingDispatcher {
        response: Mutex<Option<Vec<u8>>>,
        tx: Mutex<Option<oneshot::Sender<HandshakeContext>>>,
    }

    impl RespondingDispatcher {
        fn new(response: Vec<u8>, tx: oneshot::Sender<HandshakeContext>) -> Self {
            Self {
                response: Mutex::new(Some(response)),
                tx: Mutex::new(Some(tx)),
            }
        }
    }

    impl HandshakeDispatcher for RespondingDispatcher {
        fn handle_handshake(&self, ctx: HandshakeContext) -> Option<Vec<u8>> {
            if let Some(tx) = self.tx.lock().expect("mutex poisoned").take() {
                let _ = tx.send(ctx);
            }
            self.response.lock().expect("mutex poisoned").take()
        }
    }

    #[tokio::test]
    async fn harness_emits_dispatcher_response() {
        let server_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind server socket");
        let server_addr = server_socket.local_addr().expect("server addr");
        let (tx, rx) = oneshot::channel();
        let dispatcher = Arc::new(RespondingDispatcher::new(b"OK".to_vec(), tx));
        let security = test_security_context();
        let harness = tokio::spawn(run_handshake_harness(
            server_socket,
            security.clone(),
            vec![VELOCITY_ALPN.to_string()],
            dispatcher.clone(),
        ));

        let client = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind client socket");
        let mut payload = build_initial_datagram(&[VELOCITY_ALPN]);
        security.seal_outbound(&mut payload);
        client
            .send_to(&payload, server_addr)
            .await
            .expect("send handshake");

        let _ctx = timeout(Duration::from_secs(1), rx)
            .await
            .expect("harness response timeout")
            .expect("receive context");

        let mut buf = [0u8; 128];
        let (len, addr) = timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .expect("recv timeout")
            .expect("receive response");
        assert_eq!(addr, server_addr);
        assert!(len >= HEADER_TAG_LEN);
        assert_eq!(&buf[..len - HEADER_TAG_LEN], b"OK");

        harness.abort();
    }
}
