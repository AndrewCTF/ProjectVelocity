use crate::frame::{
    decode_frame, encode_chunked_payload, encode_frame, FrameError, FrameSequencer,
};
use crate::packet::{parse_packet, PacketDecodeError, PacketType};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlpnResolution {
    Supported(String),
    Fallback(String),
    Unsupported,
}

const ALPN_COMPACT_MAGIC: u8 = 0xA1;
const HANDSHAKE_COMPACT_MAGIC: u8 = 0xB0;
const HANDSHAKE_VERSION: u8 = 0x01;
const FLAG_RESOLUTION_MASK: u8 = 0b0000_0011;
const RESOLUTION_SUPPORTED: u8 = 0;
const RESOLUTION_FALLBACK: u8 = 1;
const RESOLUTION_UNSUPPORTED: u8 = 2;
const FLAG_FALLBACK_HOST: u8 = 0b0000_0100;
const FLAG_FALLBACK_IPV4: u8 = 0b0000_1000;
const FLAG_FALLBACK_NOTE: u8 = 0b0001_0000;
const FLAG_PQ_PAYLOAD: u8 = 0b0010_0000;
const FLAG_STRICT_TRANSPORT: u8 = 0b0100_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackDirective {
    pub alpn: String,
    pub host: String,
    pub port: u16,
    pub note: Option<String>,
}

/// Advertises a Velocity strict transport policy to clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrictTransportDirective {
    pub max_age: u64,
    #[serde(default)]
    pub include_subdomains: bool,
    #[serde(default)]
    pub preload: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub resolution: AlpnResolution,
    pub fallback: Option<FallbackDirective>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_payload: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict_transport: Option<StrictTransportDirective>,
}

#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    pub supported_alpns: Vec<String>,
    pub fallback_alpn: Option<String>,
    pub handshake_timeout: Duration,
    pub fallback_port: u16,
    pub advertise_host: Option<String>,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        HandshakeConfig {
            supported_alpns: vec!["pqq/1".to_string()],
            fallback_alpn: Some("h3".to_string()),
            handshake_timeout: Duration::from_secs(1),
            fallback_port: 443,
            advertise_host: None,
        }
    }
}

#[derive(Debug)]
pub struct HandshakeDriver {
    config: HandshakeConfig,
}

impl HandshakeDriver {
    pub fn new(config: HandshakeConfig) -> Self {
        Self { config }
    }

    /// Drive a minimal UDP-based handshake negotiation.
    ///
    /// The current prototype expects the client to send a QUIC long header with
    /// an ASCII payload beginning with `ALPN\0` followed by comma-separated
    /// protocol identifiers (e.g. `ALPN\0pqq/1,h3`). The server selects the
    /// first supported protocol or advertises a fallback.
    pub async fn run_once(
        &self,
        socket: &UdpSocket,
    ) -> Result<(SocketAddr, HandshakeResponse), HandshakeError> {
        let mut buf = [0u8; 1400];

        let (len, addr) = time::timeout(self.config.handshake_timeout, socket.recv_from(&mut buf))
            .await
            .map_err(|_| HandshakeError::Timeout)??;

        let peer_ip = addr.ip().to_string();
        let response = self.process_initial_datagram(&buf[..len], Some(&peer_ip))?;

        let encoded = encode_handshake_response(&response)?;
        let mut sequencer = FrameSequencer::new(0, 0);
        let frames =
            encode_chunked_payload(&mut sequencer, &encoded).map_err(HandshakeError::Frame)?;

        for frame in frames {
            socket.send_to(&frame, addr).await?;
        }
        Ok((addr, response))
    }

    pub fn process_initial_datagram(
        &self,
        datagram: &[u8],
        peer_host: Option<&str>,
    ) -> Result<HandshakeResponse, HandshakeError> {
        let parsed = parse_packet(datagram)?;
        if parsed.packet_type != PacketType::Initial {
            return Err(HandshakeError::UnexpectedPacket(parsed.packet_type));
        }

        let frame = parsed
            .framed_payload(datagram)
            .map_err(HandshakeError::Frame)?;
        if frame.packet_number != 0 {
            return Err(HandshakeError::PacketOutOfOrder {
                expected: 0,
                seen: frame.packet_number,
            });
        }

        let offered = decode_client_alpns(frame.payload)?;
        let resolution = self.negotiate_alpn(offered.iter());
        Ok(self.finalize_response(resolution, peer_host))
    }

    pub fn negotiate_alpn<I, S>(&self, client_alpns: I) -> AlpnResolution
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for client_proto in client_alpns {
            let client_proto = client_proto.as_ref();
            if self
                .config
                .supported_alpns
                .iter()
                .any(|supported| supported == client_proto)
            {
                return AlpnResolution::Supported(client_proto.to_string());
            }
        }

        if let Some(fallback) = &self.config.fallback_alpn {
            return AlpnResolution::Fallback(fallback.clone());
        }

        AlpnResolution::Unsupported
    }
}

impl HandshakeDriver {
    pub(crate) fn finalize_response(
        &self,
        resolution: AlpnResolution,
        peer_host: Option<&str>,
    ) -> HandshakeResponse {
        let fallback = match &resolution {
            AlpnResolution::Fallback(proto) => {
                let host = self
                    .config
                    .advertise_host
                    .clone()
                    .or_else(|| peer_host.map(|s| s.to_string()))
                    .unwrap_or_else(|| "vel-link".to_string());

                Some(FallbackDirective {
                    alpn: proto.clone(),
                    host,
                    port: self.config.fallback_port,
                    note: None,
                })
            }
            _ => None,
        };

        HandshakeResponse {
            resolution,
            fallback,
            pq_payload: None,
            strict_transport: None,
        }
    }
}

impl HandshakeConfig {
    /// Override the fallback ALPN along with the advertised endpoint.
    pub fn with_fallback_endpoint(
        mut self,
        alpn: impl Into<String>,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        self.fallback_alpn = Some(alpn.into());
        self.advertise_host = Some(host.into());
        self.fallback_port = port;
        self
    }

    /// Disable ALPN fallback handling entirely.
    pub fn without_fallback(mut self) -> Self {
        self.fallback_alpn = None;
        self.advertise_host = None;
        self
    }

    /// Replace the supported ALPN list.
    pub fn with_supported_alpns<I, S>(mut self, alpns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.supported_alpns = alpns.into_iter().map(Into::into).collect();
        self
    }
}

pub fn build_initial_packet<I, S>(alpns: I) -> Vec<u8>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let alpns_owned: Vec<String> = alpns.into_iter().map(|s| s.as_ref().to_string()).collect();
    let payload_bytes =
        encode_compact_alpns(&alpns_owned).unwrap_or_else(|_| encode_ascii_alpns(&alpns_owned));
    let framed = encode_frame(0, &payload_bytes).expect("frame encode");
    const CONN_ID_LEN: usize = 8;
    let mut packet = Vec::with_capacity(7 + (CONN_ID_LEN * 2) + framed.len());
    packet.push(0b1100_0000);
    packet.extend_from_slice(&0x0000_0001u32.to_be_bytes());

    const DEFAULT_CONN_ID: [u8; CONN_ID_LEN] = [0u8; CONN_ID_LEN];
    packet.push(DEFAULT_CONN_ID.len() as u8);
    packet.extend_from_slice(&DEFAULT_CONN_ID);
    packet.push(DEFAULT_CONN_ID.len() as u8);
    packet.extend_from_slice(&DEFAULT_CONN_ID);

    packet.extend_from_slice(&framed);
    packet
}

#[derive(thiserror::Error, Debug)]
pub enum HandshakeError {
    #[error("handshake timed out before receiving client initial")]
    Timeout,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("packet decode error: {0}")]
    Decode(#[from] PacketDecodeError),
    #[error("payload format did not match ALPN stub")]
    MalformedPayload,
    #[error("unexpected packet type {0}")]
    UnexpectedPacket(PacketType),
    #[error("failed to serialize handshake response: {0}")]
    Serialization(crate::cbor::Error),
    #[error("handshake field too long for compact encoding")]
    FieldTooLong,
    #[error("compact handshake payload truncated")]
    CompactTruncated,
    #[error("compact handshake payload invalid")]
    CompactInvalid,
    #[error("handshake framing error: {0}")]
    Frame(FrameError),
    #[error("packet number {seen} out of order (expected {expected})")]
    PacketOutOfOrder { expected: u64, seen: u64 },
}

pub fn encode_handshake_response(response: &HandshakeResponse) -> Result<Vec<u8>, HandshakeError> {
    match encode_compact_handshake(response) {
        Ok(bytes) => Ok(bytes),
        Err(HandshakeError::FieldTooLong) => {
            crate::cbor::to_vec(response).map_err(HandshakeError::Serialization)
        }
        Err(err) => Err(err),
    }
}

pub fn decode_handshake_response(data: &[u8]) -> Result<HandshakeResponse, HandshakeError> {
    let payload = match decode_frame(data) {
        Ok(frame) => {
            if frame.packet_number != 0 {
                return Err(HandshakeError::PacketOutOfOrder {
                    expected: 0,
                    seen: frame.packet_number,
                });
            }
            frame.payload
        }
        Err(_) => data,
    };

    decode_handshake_payload(payload)
}

fn decode_handshake_payload(bytes: &[u8]) -> Result<HandshakeResponse, HandshakeError> {
    if bytes.first() != Some(&HANDSHAKE_COMPACT_MAGIC) {
        return crate::cbor::from_slice(bytes).map_err(HandshakeError::Serialization);
    }

    if bytes.len() < 3 {
        return Err(HandshakeError::CompactTruncated);
    }

    if bytes[1] != HANDSHAKE_VERSION {
        return Err(HandshakeError::CompactInvalid);
    }

    let flags = bytes[2];
    let mut cursor = 3;

    let resolution = match flags & FLAG_RESOLUTION_MASK {
        RESOLUTION_SUPPORTED => {
            let proto = take_short_string(bytes, &mut cursor)?;
            AlpnResolution::Supported(proto)
        }
        RESOLUTION_FALLBACK => {
            let proto = take_short_string(bytes, &mut cursor)?;
            AlpnResolution::Fallback(proto)
        }
        RESOLUTION_UNSUPPORTED => AlpnResolution::Unsupported,
        _ => return Err(HandshakeError::CompactInvalid),
    };

    let mut fallback = None;
    if flags & FLAG_FALLBACK_HOST != 0 {
        let host = if flags & FLAG_FALLBACK_IPV4 != 0 {
            take_ipv4(bytes, &mut cursor)?
        } else {
            take_short_string(bytes, &mut cursor)?
        };
        let port = take_port(bytes, &mut cursor)?;
        let note = if flags & FLAG_FALLBACK_NOTE != 0 {
            Some(take_short_string(bytes, &mut cursor)?)
        } else {
            None
        };

        let alpn = match &resolution {
            AlpnResolution::Fallback(proto) => proto.clone(),
            _ => return Err(HandshakeError::CompactInvalid),
        };

        fallback = Some(FallbackDirective {
            alpn,
            host,
            port,
            note,
        });
    }

    let pq_payload = if flags & FLAG_PQ_PAYLOAD != 0 {
        Some(take_short_string(bytes, &mut cursor)?)
    } else {
        None
    };

    let strict_transport = if flags & FLAG_STRICT_TRANSPORT != 0 {
        Some(take_strict_transport(bytes, &mut cursor)?)
    } else {
        None
    };

    if bytes[cursor..].iter().any(|&b| b != 0) {
        return Err(HandshakeError::CompactInvalid);
    }

    Ok(HandshakeResponse {
        resolution,
        fallback,
        pq_payload,
        strict_transport,
    })
}

fn encode_compact_handshake(response: &HandshakeResponse) -> Result<Vec<u8>, HandshakeError> {
    let mut buf = Vec::with_capacity(48);
    buf.push(HANDSHAKE_COMPACT_MAGIC);
    buf.push(HANDSHAKE_VERSION);
    buf.push(0); // placeholder for flags
    let mut flags = 0u8;

    match &response.resolution {
        AlpnResolution::Supported(proto) => {
            push_short_str(&mut buf, proto)?;
        }
        AlpnResolution::Fallback(proto) => {
            flags |= RESOLUTION_FALLBACK;
            push_short_str(&mut buf, proto)?;
        }
        AlpnResolution::Unsupported => {
            flags |= RESOLUTION_UNSUPPORTED;
        }
    }

    if let Some(fallback) = &response.fallback {
        flags |= FLAG_FALLBACK_HOST;
        if let Ok(ipv4) = fallback.host.parse::<Ipv4Addr>() {
            flags |= FLAG_FALLBACK_IPV4;
            buf.extend_from_slice(&ipv4.octets());
        } else {
            push_short_str(&mut buf, &fallback.host)?;
        }
        buf.extend_from_slice(&fallback.port.to_be_bytes());
        if let Some(note) = &fallback.note {
            flags |= FLAG_FALLBACK_NOTE;
            push_short_str(&mut buf, note)?;
        }
    }

    if let Some(pq) = &response.pq_payload {
        flags |= FLAG_PQ_PAYLOAD;
        push_short_str(&mut buf, pq)?;
    }

    if let Some(policy) = &response.strict_transport {
        flags |= FLAG_STRICT_TRANSPORT;
        push_strict_transport(&mut buf, policy)?;
    }

    buf[2] = flags;
    Ok(buf)
}

fn decode_client_alpns(payload: &[u8]) -> Result<Vec<String>, HandshakeError> {
    if payload.first() == Some(&ALPN_COMPACT_MAGIC) {
        parse_compact_alpns(payload)
    } else {
        parse_ascii_alpns(payload)
    }
}

fn encode_compact_alpns(alpns: &[String]) -> Result<Vec<u8>, HandshakeError> {
    if alpns.len() > u8::MAX as usize {
        return Err(HandshakeError::FieldTooLong);
    }
    let mut buf = Vec::with_capacity(2 + alpns.iter().map(|s| 1 + s.len()).sum::<usize>());
    buf.push(ALPN_COMPACT_MAGIC);
    buf.push(alpns.len() as u8);
    for alpn in alpns {
        let bytes = alpn.as_bytes();
        if bytes.len() > u8::MAX as usize {
            return Err(HandshakeError::FieldTooLong);
        }
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    Ok(buf)
}

fn encode_ascii_alpns(alpns: &[String]) -> Vec<u8> {
    if alpns.is_empty() {
        return b"ALPN\0".to_vec();
    }
    let mut payload = String::from("ALPN\0");
    let mut first = true;
    for alpn in alpns {
        if !first {
            payload.push(',');
        }
        payload.push_str(alpn);
        first = false;
    }
    payload.into_bytes()
}

fn parse_compact_alpns(payload: &[u8]) -> Result<Vec<String>, HandshakeError> {
    if payload.len() < 2 {
        return Err(HandshakeError::CompactTruncated);
    }
    let count = payload[1] as usize;
    let mut cursor = 2;
    let mut alpns = Vec::with_capacity(count);
    for _ in 0..count {
        let value = take_short_string(payload, &mut cursor)?;
        alpns.push(value);
    }
    if payload[cursor..].iter().any(|&b| b != 0) {
        return Err(HandshakeError::CompactInvalid);
    }
    Ok(alpns)
}

fn parse_ascii_alpns(payload: &[u8]) -> Result<Vec<String>, HandshakeError> {
    let text = std::str::from_utf8(payload).map_err(|_| HandshakeError::MalformedPayload)?;
    let rest = text
        .strip_prefix("ALPN\0")
        .ok_or(HandshakeError::MalformedPayload)?;
    Ok(rest
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect())
}

fn push_short_str(buf: &mut Vec<u8>, value: &str) -> Result<(), HandshakeError> {
    let bytes = value.as_bytes();
    if bytes.len() > u8::MAX as usize {
        return Err(HandshakeError::FieldTooLong);
    }
    buf.push(bytes.len() as u8);
    buf.extend_from_slice(bytes);
    Ok(())
}

fn push_strict_transport(
    buf: &mut Vec<u8>,
    directive: &StrictTransportDirective,
) -> Result<(), HandshakeError> {
    buf.extend_from_slice(&directive.max_age.to_be_bytes());
    let mut flags = 0u8;
    if directive.include_subdomains {
        flags |= 0x01;
    }
    if directive.preload {
        flags |= 0x02;
    }
    buf.push(flags);
    Ok(())
}

fn take_short_string(bytes: &[u8], cursor: &mut usize) -> Result<String, HandshakeError> {
    if *cursor >= bytes.len() {
        return Err(HandshakeError::CompactTruncated);
    }
    let len = bytes[*cursor] as usize;
    *cursor += 1;
    if bytes.len() < *cursor + len {
        return Err(HandshakeError::CompactTruncated);
    }
    let slice = &bytes[*cursor..*cursor + len];
    *cursor += len;
    let value = std::str::from_utf8(slice).map_err(|_| HandshakeError::CompactInvalid)?;
    Ok(value.to_string())
}

fn take_ipv4(bytes: &[u8], cursor: &mut usize) -> Result<String, HandshakeError> {
    if bytes.len() < *cursor + 4 {
        return Err(HandshakeError::CompactTruncated);
    }
    let octets = [
        bytes[*cursor],
        bytes[*cursor + 1],
        bytes[*cursor + 2],
        bytes[*cursor + 3],
    ];
    *cursor += 4;
    Ok(Ipv4Addr::from(octets).to_string())
}

fn take_port(bytes: &[u8], cursor: &mut usize) -> Result<u16, HandshakeError> {
    if bytes.len() < *cursor + 2 {
        return Err(HandshakeError::CompactTruncated);
    }
    let port = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]);
    *cursor += 2;
    Ok(port)
}

fn take_strict_transport(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<StrictTransportDirective, HandshakeError> {
    if bytes.len() < *cursor + 9 {
        return Err(HandshakeError::CompactTruncated);
    }
    let mut max_age_bytes = [0u8; 8];
    max_age_bytes.copy_from_slice(&bytes[*cursor..*cursor + 8]);
    *cursor += 8;
    let flags = bytes[*cursor];
    *cursor += 1;
    Ok(StrictTransportDirective {
        max_age: u64::from_be_bytes(max_age_bytes),
        include_subdomains: flags & 0x01 != 0,
        preload: flags & 0x02 != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_initial_payload_roundtrip() {
        let alpns = vec!["pqq/1".to_string(), "h3".to_string()];
        let encoded = encode_compact_alpns(&alpns).expect("encode");
        assert_eq!(encoded.first(), Some(&ALPN_COMPACT_MAGIC));
        let decoded = parse_compact_alpns(&encoded).expect("decode");
        assert_eq!(decoded, alpns);
    }

    #[test]
    fn parses_legacy_ascii_payload() {
        let payload = b"ALPN\0pqq/1,h3";
        let decoded = decode_client_alpns(payload).expect("decode legacy");
        assert_eq!(decoded, vec!["pqq/1".to_string(), "h3".to_string()]);
    }

    #[test]
    fn compact_handshake_roundtrip_supported() {
        let response = HandshakeResponse {
            resolution: AlpnResolution::Supported("pqq/1".into()),
            fallback: None,
            pq_payload: None,
            strict_transport: None,
        };
        let encoded = encode_handshake_response(&response).expect("encode");
        assert_eq!(encoded.first(), Some(&HANDSHAKE_COMPACT_MAGIC));
        let framed = crate::frame::encode_frame(0, &encoded).expect("frame");
        let decoded = decode_handshake_response(&framed).expect("decode");
        assert_eq!(decoded, response);
    }

    #[test]
    fn compact_handshake_roundtrip_fallback_ipv4() {
        let response = HandshakeResponse {
            resolution: AlpnResolution::Fallback("h3".into()),
            fallback: Some(FallbackDirective {
                alpn: "h3".into(),
                host: "127.0.0.1".into(),
                port: 443,
                note: None,
            }),
            pq_payload: Some("mlkem768".into()),
            strict_transport: None,
        };
        let encoded = encode_handshake_response(&response).expect("encode");
        let framed = crate::frame::encode_frame(0, &encoded).expect("frame");
        let decoded = decode_handshake_response(&framed).expect("decode");
        assert_eq!(decoded, response);
    }

    #[test]
    fn compact_handshake_carries_strict_transport() {
        let response = HandshakeResponse {
            resolution: AlpnResolution::Supported("velocity/1".into()),
            fallback: None,
            pq_payload: None,
            strict_transport: Some(StrictTransportDirective {
                max_age: 31536000,
                include_subdomains: true,
                preload: true,
            }),
        };
        let encoded = encode_handshake_response(&response).expect("encode");
        let framed = crate::frame::encode_frame(0, &encoded).expect("frame");
        let decoded = decode_handshake_response(&framed).expect("decode");
        assert_eq!(decoded, response);
    }

    #[test]
    fn negotiates_preferred_alpn() {
        let config = HandshakeConfig::default();
        let driver = HandshakeDriver::new(config);
        let res = driver.negotiate_alpn(["pqq/1", "h3"]);
        assert!(matches!(res, AlpnResolution::Supported(proto) if proto == "pqq/1"));
    }

    #[test]
    fn falls_back_when_needed() {
        let config = HandshakeConfig {
            supported_alpns: vec!["pqq/1".into()],
            fallback_alpn: Some("h3".into()),
            ..HandshakeConfig::default()
        };
        let driver = HandshakeDriver::new(config);
        let res = driver.negotiate_alpn(["spdy/3", "h3"]);
        assert!(matches!(res, AlpnResolution::Fallback(proto) if proto == "h3"));
    }

    #[test]
    fn handles_no_common_protocol() {
        let config = HandshakeConfig {
            fallback_alpn: None,
            ..HandshakeConfig::default()
        };
        let driver = HandshakeDriver::new(config);

        let res = driver.negotiate_alpn(["legacy/1"]);
        assert!(matches!(res, AlpnResolution::Unsupported));
    }
}
