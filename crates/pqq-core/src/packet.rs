use crate::frame::{decode_frame, FrameError, FrameSlice, FRAME_HEADER_LEN, FRAME_MAX_PAYLOAD};
use bytes::Buf;
use std::fmt;

/// Identifies the high-level QUIC packet form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Initial,
    Handshake,
    ZeroRtt,
    OneRtt,
    Retry,
    VersionNegotiation,
    Unknown(u8),
}

/// Result of decoding a raw UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPacket {
    pub packet_type: PacketType,
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub payload_offset: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PacketDecodeError {
    #[error("packet is too short for QUIC long header")]
    Truncated,
    #[error("packet claims more data than provided")]
    LengthMismatch,
    #[error("unsupported packet format: {0:#x}")]
    Unsupported(u8),
    #[error("packet exceeds velocity size limits")]
    PacketTooLong,
    #[error("connection id length exceeds velocity limits")]
    ConnectionIdTooLong,
    #[error("connection id shorter than protocol minimum")]
    ConnectionIdTooShort,
    #[error("framed payload header missing")]
    MissingFrameHeader,
}

pub const MAX_HANDSHAKE_DATAGRAM: usize = FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD + 64;
const MIN_CONNECTION_ID_LEN: usize = 8;
const MAX_CONNECTION_ID_LEN: usize = 20;

/// Parse a QUIC-style long-header packet. PQ-QUIC currently restricts itself to
/// long headers during the handshake while reusing QUIC's short-header format
/// for 1-RTT data.
pub fn parse_packet(bytes: &[u8]) -> Result<ParsedPacket, PacketDecodeError> {
    if bytes.len() > MAX_HANDSHAKE_DATAGRAM {
        return Err(PacketDecodeError::PacketTooLong);
    }
    if bytes.len() < 5 {
        return Err(PacketDecodeError::Truncated);
    }

    let first = bytes[0];
    let is_long = first & 0b1000_0000 != 0;

    if !is_long {
        return Err(PacketDecodeError::Unsupported(first));
    }

    let packet_type = match (first >> 4) & 0b11 {
        0b00 => PacketType::Initial,
        0b01 => PacketType::ZeroRtt,
        0b10 => PacketType::Handshake,
        0b11 => PacketType::Retry,
        other => PacketType::Unknown(other),
    };

    let mut cursor = bytes;
    cursor.get_u8(); // consume first byte

    let version = cursor.get_u32();
    if version == 0 {
        return Ok(ParsedPacket {
            packet_type: PacketType::VersionNegotiation,
            version,
            dcid: Vec::new(),
            scid: Vec::new(),
            payload_offset: 1, // version negotiation doesn't include payload
        });
    }

    if cursor.remaining() < 1 {
        return Err(PacketDecodeError::Truncated);
    }
    let dcid_len = cursor.get_u8() as usize;
    if dcid_len < MIN_CONNECTION_ID_LEN {
        return Err(PacketDecodeError::ConnectionIdTooShort);
    }
    if dcid_len > MAX_CONNECTION_ID_LEN {
        return Err(PacketDecodeError::ConnectionIdTooLong);
    }
    if cursor.remaining() < dcid_len + 1 {
        return Err(PacketDecodeError::LengthMismatch);
    }
    let dcid = cursor.copy_to_bytes(dcid_len).to_vec();

    let scid_len = cursor.get_u8() as usize;
    if scid_len < MIN_CONNECTION_ID_LEN {
        return Err(PacketDecodeError::ConnectionIdTooShort);
    }
    if scid_len > MAX_CONNECTION_ID_LEN {
        return Err(PacketDecodeError::ConnectionIdTooLong);
    }
    if cursor.remaining() < scid_len {
        return Err(PacketDecodeError::LengthMismatch);
    }
    let scid = cursor.copy_to_bytes(scid_len).to_vec();

    let payload_offset = bytes.len() - cursor.remaining();
    let payload_len = bytes.len().saturating_sub(payload_offset);
    if payload_len < FRAME_HEADER_LEN {
        return Err(PacketDecodeError::MissingFrameHeader);
    }
    if payload_len - FRAME_HEADER_LEN > FRAME_MAX_PAYLOAD {
        return Err(PacketDecodeError::PacketTooLong);
    }

    Ok(ParsedPacket {
        packet_type,
        version,
        dcid,
        scid,
        payload_offset,
    })
}

impl ParsedPacket {
    pub fn framed_payload<'a>(&self, datagram: &'a [u8]) -> Result<FrameSlice<'a>, FrameError> {
        decode_frame(&datagram[self.payload_offset..])
    }
}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketType::Initial => write!(f, "Initial"),
            PacketType::Handshake => write!(f, "Handshake"),
            PacketType::ZeroRtt => write!(f, "0-RTT"),
            PacketType::OneRtt => write!(f, "1-RTT"),
            PacketType::Retry => write!(f, "Retry"),
            PacketType::VersionNegotiation => write!(f, "VersionNegotiation"),
            PacketType::Unknown(code) => write!(f, "Unknown({code})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_initial_packet(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let packet_type_bits = 0b00; // Initial
        let first = 0b1100_0000 | (packet_type_bits << 4);
        buf.push(first);
        buf.extend_from_slice(&0x0000_0001u32.to_be_bytes()); // version 1
        buf.push(dcid.len() as u8);
        buf.extend_from_slice(dcid);
        buf.push(scid.len() as u8);
        buf.extend_from_slice(scid);
        let framed = crate::frame::encode_frame(0, &[0u8; 4]).expect("frame");
        buf.extend_from_slice(&framed);
        buf
    }

    #[test]
    fn parses_minimal_initial_packet() {
        let packet = build_initial_packet(
            &[0x11; MIN_CONNECTION_ID_LEN],
            &[0xAA; MIN_CONNECTION_ID_LEN],
        );
        let parsed = parse_packet(&packet).expect("parser should succeed");

        assert_eq!(parsed.packet_type, PacketType::Initial);
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.dcid, vec![0x11; MIN_CONNECTION_ID_LEN]);
        assert_eq!(parsed.scid, vec![0xAA; MIN_CONNECTION_ID_LEN]);
        let frame = parsed
            .framed_payload(&packet)
            .expect("framed payload should decode");
        assert_eq!(frame.packet_number, 0);
        assert_eq!(frame.payload, &[0, 0, 0, 0]);
    }

    #[test]
    fn detects_truncated_packet() {
        let err = parse_packet(&[0xC0, 0x00]).unwrap_err();
        assert_eq!(err, PacketDecodeError::Truncated);
    }

    #[test]
    fn detects_length_mismatch() {
        let mut packet = build_initial_packet(
            &[0x01; MIN_CONNECTION_ID_LEN],
            &[0x02; MIN_CONNECTION_ID_LEN],
        );
        // Tamper with SCID length to claim more bytes than present
        let scid_len_index = 6 + packet[5] as usize;
        packet[scid_len_index] = 5;
        let err = parse_packet(&packet).unwrap_err();
        assert_eq!(err, PacketDecodeError::ConnectionIdTooShort);
    }
}
