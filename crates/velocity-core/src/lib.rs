/// Minimal transport primitives for the Velocity protocol.
///
/// This crate establishes three baseline building blocks used throughout
/// the repository:
/// - [`run_udp_handshake_loop`], which binds a UDP socket and forwards
///   inbound datagrams to a supplied handler;
/// - [`parse_packet`], the reference packet framing parser that keeps the
///   payload offset so consumers can process ciphertext without copying; and
/// - the ALPN helpers [`parse_alpn_payload`] and [`negotiate_alpn`] that
///   mirror the TLS Application Layer Protocol Negotiation extension.
///
/// The code purposely favors clarity over optimisations so future crates can
/// iterate on congestion control, header protection, and handshake logic
/// without dragging in additional complexity at this stage.

use std::io;
use std::net::SocketAddr;

use thiserror::Error;
use tokio::net::UdpSocket;

/// Maximum size of an Initial datagram we accept during the bootstrap phase.
pub const MAX_DATAGRAM_SIZE: usize = 1350;

/// Velocity's ALPN token as negotiated during the cryptographic handshake.
pub const VELOCITY_ALPN: &str = "velocity/1";

const MIN_CONNECTION_ID_LEN: usize = 4;
const MAX_CONNECTION_ID_LEN: usize = 18;
const MAX_ALPN_PROTOCOLS: usize = 16;

/// High level ALPN negotiation outcome used by the handshake driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlpnDecision {
    /// Velocity was selected by both peers.
    Accepted(String),
    /// Velocity was not available; peer should downgrade to the supplied fallback.
    Fallback(String),
    /// Negotiation failed; connection should be aborted.
    Reject,
}

/// Packet types supported by the minimal wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Initial = 0x0,
    ServerInitial = 0x1,
    OneRtt = 0x2,
    Retry = 0x3,
}

impl TryFrom<u8> for PacketType {
    type Error = PacketError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x0 => Ok(PacketType::Initial),
            0x1 => Ok(PacketType::ServerInitial),
            0x2 => Ok(PacketType::OneRtt),
            0x3 => Ok(PacketType::Retry),
            other => Err(PacketError::UnknownType(other)),
        }
    }
}

/// Parsed Velocity packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    pub version: u32,
    pub packet_type: PacketType,
    pub destination_connection_id: Vec<u8>,
    pub source_connection_id: Vec<u8>,
    pub payload_length: u16,
}

/// Parsed Velocity packet with payload offset retained for downstream consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPacket<'a> {
    pub header: PacketHeader,
    pub payload_offset: usize,
    datagram: &'a [u8],
}

impl<'a> ParsedPacket<'a> {
    /// Return the payload slice without re-parsing the datagram.
    pub fn payload(&self) -> &'a [u8] {
        let end = self.payload_offset + self.header.payload_length as usize;
        &self.datagram[self.payload_offset..end]
    }
}

/// Errors emitted while parsing packets or ALPN payloads.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    /// Received datagram exceeded the configured maximum.
    #[error("datagram too long (max {MAX_DATAGRAM_SIZE} bytes)")]
    DatagramTooLong,
    /// Datagram did not contain enough bytes for the fixed header.
    #[error("datagram truncated")]
    DatagramTooShort,
    /// The packet advertised lengths that exceeded the datagram bounds.
    #[error("payload length exceeds datagram bounds")]
    PayloadOutOfBounds,
    /// Connection identifiers were shorter or longer than allowed.
    #[error("connection identifier length out of range")]
    ConnectionIdLength,
    /// Packet type nibble was not recognised.
    #[error("unknown packet type {0:#x}")]
    UnknownType(u8),
    /// ALPN payload was malformed.
    #[error("malformed ALPN payload")]
    MalformedAlpn,
    /// ALPN payload contained non UTF-8 data.
    #[error("ALPN entry contains non-UTF-8 data")]
    NonUtf8Alpn,
    /// ALPN payload exceeded the configured entry limit.
    #[error("too many ALPN entries (max {MAX_ALPN_PROTOCOLS})")]
    TooManyAlpnProtocols,
}

/// Parse a Velocity packet from the provided datagram.
pub fn parse_packet(datagram: &[u8]) -> Result<ParsedPacket<'_>, PacketError> {
    if datagram.len() > MAX_DATAGRAM_SIZE {
        return Err(PacketError::DatagramTooLong);
    }

    if datagram.len() < 9 {
        return Err(PacketError::DatagramTooShort);
    }

    let packet_type = PacketType::try_from(datagram[0])?;
    let version = u32::from_be_bytes([datagram[1], datagram[2], datagram[3], datagram[4]]);
    let dcid_len = datagram[5] as usize;
    let scid_len = datagram[6] as usize;
    let payload_len = u16::from_be_bytes([datagram[7], datagram[8]]) as usize;

    if !(MIN_CONNECTION_ID_LEN..=MAX_CONNECTION_ID_LEN).contains(&dcid_len)
        || !(MIN_CONNECTION_ID_LEN..=MAX_CONNECTION_ID_LEN).contains(&scid_len)
    {
        return Err(PacketError::ConnectionIdLength);
    }

    let payload_offset = 9 + dcid_len + scid_len;
    let payload_end = payload_offset + payload_len;

    if datagram.len() < payload_end {
        return Err(PacketError::PayloadOutOfBounds);
    }

    let dcid = datagram[9..9 + dcid_len].to_vec();
    let scid_start = 9 + dcid_len;
    let scid = datagram[scid_start..scid_start + scid_len].to_vec();

    Ok(ParsedPacket {
        header: PacketHeader {
            version,
            packet_type,
            destination_connection_id: dcid,
            source_connection_id: scid,
            payload_length: payload_len as u16,
        },
        payload_offset,
        datagram,
    })
}

/// Parse an ALPN payload encoded as a sequence of length-prefixed strings.
///
/// The format mirrors the TLS Application Layer Protocol Negotiation extension
/// where each entry begins with an unsigned 8-bit length followed by UTF-8 bytes.
pub fn parse_alpn_payload(payload: &[u8]) -> Result<Vec<String>, PacketError> {
    let mut cursor = 0usize;
    let mut entries = Vec::new();

    while cursor < payload.len() {
        let remaining = payload.len() - cursor;
        if remaining < 1 {
            return Err(PacketError::MalformedAlpn);
        }
        let len = payload[cursor] as usize;
        cursor += 1;
        if len == 0 || cursor + len > payload.len() {
            return Err(PacketError::MalformedAlpn);
        }
        let entry = std::str::from_utf8(&payload[cursor..cursor + len])
            .map_err(|_| PacketError::NonUtf8Alpn)?;
        entries.push(entry.to_owned());
        cursor += len;
        if entries.len() > MAX_ALPN_PROTOCOLS {
            return Err(PacketError::TooManyAlpnProtocols);
        }
    }

    Ok(entries)
}

/// Determine which ALPN value should be used given the client's offerings.
///
/// * If the client offered elocity/1, return [AlpnDecision::Accepted].
/// * Otherwise, offer the provided fallback protocol (typically h3).
/// * If no fallback is configured (empty string), reject.
pub fn negotiate_alpn(client_offered: &[String], fallback: &str) -> AlpnDecision {
    if let Some(match_idx) = client_offered
        .iter()
        .position(|value| value == VELOCITY_ALPN)
    {
        return AlpnDecision::Accepted(client_offered[match_idx].clone());
    }

    if fallback.is_empty() {
        AlpnDecision::Reject
    } else {
        AlpnDecision::Fallback(fallback.to_owned())
    }
}

/// Bind a UDP socket and execute a minimal receive loop.
///
/// The handler is synchronous on purpose so early experiments can keep the
/// lifetime of parsed packets simple. Future iterations can upgrade the API
/// to support asynchronous responders once buffering strategies are decided.
pub async fn run_udp_handshake_loop(
    bind_addr: &str,
    mut handler: impl FnMut(SocketAddr, ParsedPacket<'_>),
) -> io::Result<()> {
    let socket = UdpSocket::bind(bind_addr).await?;
    let mut buffer = vec![0u8; MAX_DATAGRAM_SIZE];

    loop {
        let (len, peer) = socket.recv_from(&mut buffer).await?;
        let datagram = &buffer[..len];

        if let Ok(packet) = parse_packet(datagram) {
            handler(peer, packet);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn build_datagram(packet_type: PacketType, payload: &[u8]) -> Vec<u8> {
        let mut datagram = Vec::new();
        datagram.push(packet_type as u8);
        datagram.extend_from_slice(&1u32.to_be_bytes());
        datagram.push(8); // dcid len
        datagram.push(8); // scid len
        datagram.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        datagram.extend_from_slice(&[0u8; 8]); // dcid
        datagram.extend_from_slice(&[1u8; 8]); // scid
        datagram.extend_from_slice(payload);
        datagram
    }

    #[test]
    fn parse_packet_round_trip() {
        let payload = b"ALPN\0velocity/1";
        let datagram = build_datagram(PacketType::Initial, payload);
        let parsed = parse_packet(&datagram).expect("packet parses");

        assert_eq!(parsed.header.version, 1);
        assert_eq!(parsed.header.packet_type, PacketType::Initial);
        assert_eq!(parsed.header.destination_connection_id, vec![0u8; 8]);
        assert_eq!(parsed.payload_offset, 9 + 8 + 8);
        assert_eq!(parsed.payload(), payload);
    }

    #[test]
    fn parse_packet_rejects_invalid_lengths() {
        let mut datagram = build_datagram(PacketType::Initial, b"payload");
        // Corrupt the payload length to exceed the datagram bounds.
        datagram[7] = 0xff;
        datagram[8] = 0xff;
        let err = parse_packet(&datagram).unwrap_err();
        assert_eq!(err, PacketError::PayloadOutOfBounds);
    }

    #[test]
    fn parse_alpn_payload_success() {
        let payload = [
            10, b'v', b'e', b'l', b'o', b'c', b'i', b't', b'y', b'/', b'1',
            2, b'h', b'3',
        ];
        let protocols = parse_alpn_payload(&payload).expect("alpn parsed");
        assert_eq!(protocols, vec!["velocity/1".to_string(), "h3".to_string()]);
    }

    #[test]
    fn parse_alpn_payload_rejects_non_utf8() {
        let payload = [1, 0xff];
        let err = parse_alpn_payload(&payload).unwrap_err();
        assert_eq!(err, PacketError::NonUtf8Alpn);
    }

    #[test]
    fn negotiate_prefers_velocity() {
        let protocols = vec!["h3".to_string(), VELOCITY_ALPN.to_string()];
        let decision = negotiate_alpn(&protocols, "h3");
        assert_eq!(decision, AlpnDecision::Accepted(VELOCITY_ALPN.to_string()));
    }

    #[test]
    fn negotiate_falls_back() {
        let protocols = vec!["h3".to_string()];
        let decision = negotiate_alpn(&protocols, "h3");
        assert_eq!(decision, AlpnDecision::Fallback("h3".to_string()));
    }

    #[test]
    fn negotiate_rejects_when_no_fallback() {
        let protocols = vec!["spdy/3".to_string()];
        let decision = negotiate_alpn(&protocols, "");
        assert_eq!(decision, AlpnDecision::Reject);
    }
}
