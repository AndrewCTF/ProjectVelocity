use thiserror::Error;

/// Length of the frame header (packet number + payload length).
pub const FRAME_HEADER_LEN: usize = 12;

/// Maximum frame payload we accept on the wire. Align this with a conservative
/// UDP payload target so application data naturally respects common MTU limits.
pub const FRAME_MAX_PAYLOAD: usize = 1350;

/// Upper bound for a logical handshake message. These payloads may span
/// multiple frames via the chunking helpers below.
pub const HANDSHAKE_MESSAGE_MAX: usize = 16 * 1024;

/// Maximum size for an application data message that can be fragmented across
/// multiple Velocity frames. This keeps memory usage bounded while still
/// allowing multi-megabyte responses to traverse the transport.
pub const APPLICATION_MESSAGE_MAX: usize = 4 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame too short")]
    TooShort,
    #[error("frame payload length exceeds protocol limits")]
    PayloadTooLarge,
    #[error("frame length field does not match buffer size")]
    LengthMismatch,
    #[error("packet number {seen} out of order (expected {expected})")]
    OutOfOrder { expected: u64, seen: u64 },
    #[error("packet sequence number overflowed")]
    SequenceOverflow,
}

/// Lightweight view over a decoded frame.
#[derive(Debug, Clone, Copy)]
pub struct FrameSlice<'a> {
    pub packet_number: u64,
    pub payload: &'a [u8],
}

impl FrameSlice<'_> {
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

/// Encode a payload into a framed datagram with a monotonically increasing
/// packet number.
pub fn encode_frame(packet_number: u64, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > FRAME_MAX_PAYLOAD {
        return Err(FrameError::PayloadTooLarge);
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.extend_from_slice(&packet_number.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Encode a potentially large payload into multiple framed datagrams using the
/// provided sequencer. The payload is prefixed with its total length so the
/// receiver can reassemble chunks in order.
pub fn encode_chunked_payload(
    sequencer: &mut FrameSequencer,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>, FrameError> {
    encode_chunked_payload_with_limit(sequencer, payload, HANDSHAKE_MESSAGE_MAX)
}

/// Variant of [`encode_chunked_payload`] that allows the caller to specify a
/// custom maximum payload length. This is useful for application data, which
/// routinely exceeds the stricter handshake limits.
pub fn encode_chunked_payload_with_limit(
    sequencer: &mut FrameSequencer,
    payload: &[u8],
    max_len: usize,
) -> Result<Vec<Vec<u8>>, FrameError> {
    if payload.len() > max_len {
        return Err(FrameError::PayloadTooLarge);
    }

    if payload.len() > (u32::MAX as usize) {
        return Err(FrameError::PayloadTooLarge);
    }

    let mut length_prefixed = Vec::with_capacity(4 + payload.len());
    length_prefixed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    length_prefixed.extend_from_slice(payload);

    let mut frames = Vec::new();
    for chunk in length_prefixed.chunks(FRAME_MAX_PAYLOAD) {
        frames.push(sequencer.encode(chunk)?);
    }
    Ok(frames)
}

/// Incrementally reassembles a chunked payload emitted by
/// [`encode_chunked_payload`].
#[derive(Debug, Default)]
pub struct ChunkAssembler {
    header: [u8; 4],
    header_filled: usize,
    expected_len: Option<usize>,
    buffer: Vec<u8>,
    max_len: usize,
}

impl ChunkAssembler {
    pub fn new(max_len: usize) -> Self {
        Self {
            header: [0u8; 4],
            header_filled: 0,
            expected_len: None,
            buffer: Vec::new(),
            max_len,
        }
    }

    pub fn reset(&mut self) {
        self.header = [0u8; 4];
        self.header_filled = 0;
        self.expected_len = None;
        self.buffer.clear();
    }

    pub fn push_slice(&mut self, slice: FrameSlice<'_>) -> Result<Option<Vec<u8>>, FrameError> {
        let mut payload = slice.payload;

        if self.expected_len.is_none() {
            while self.header_filled < 4 && !payload.is_empty() {
                self.header[self.header_filled] = payload[0];
                self.header_filled += 1;
                payload = &payload[1..];
            }

            if self.header_filled < 4 {
                // Still waiting for the rest of the length prefix.
                return Ok(None);
            }

            let declared = u32::from_be_bytes(self.header) as usize;
            if declared > self.max_len {
                self.reset();
                return Err(FrameError::PayloadTooLarge);
            }

            self.expected_len = Some(declared);
            self.header_filled = 0;

            if declared == 0 {
                if !payload.is_empty() {
                    self.reset();
                    return Err(FrameError::LengthMismatch);
                }
                self.reset();
                return Ok(Some(Vec::new()));
            }
        }

        if !payload.is_empty() {
            self.buffer.extend_from_slice(payload);
        }

        if let Some(expected) = self.expected_len {
            if self.buffer.len() > expected {
                self.reset();
                return Err(FrameError::LengthMismatch);
            }

            if self.buffer.len() == expected {
                let mut out = Vec::with_capacity(expected);
                std::mem::swap(&mut out, &mut self.buffer);
                self.reset();
                return Ok(Some(out));
            }
        }

        Ok(None)
    }
}

/// Decode a framed payload, returning the packet number and payload slice.
pub fn decode_frame(frame: &[u8]) -> Result<FrameSlice<'_>, FrameError> {
    if frame.len() < FRAME_HEADER_LEN {
        return Err(FrameError::TooShort);
    }
    let (header, payload_bytes) = frame.split_at(FRAME_HEADER_LEN);
    let mut number_bytes = [0u8; 8];
    number_bytes.copy_from_slice(&header[..8]);
    let packet_number = u64::from_be_bytes(number_bytes);

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&header[8..]);
    let declared = u32::from_be_bytes(len_bytes) as usize;

    if declared > FRAME_MAX_PAYLOAD {
        return Err(FrameError::PayloadTooLarge);
    }
    if declared != payload_bytes.len() {
        return Err(FrameError::LengthMismatch);
    }

    Ok(FrameSlice {
        packet_number,
        payload: payload_bytes,
    })
}

/// State machine that tracks send and receive packet numbers for a connection.
#[derive(Debug, Clone, Copy)]
pub struct FrameSequencer {
    next_send: u64,
    expected_recv: u64,
}

impl FrameSequencer {
    pub const fn new(send_start: u64, expected_recv: u64) -> Self {
        Self {
            next_send: send_start,
            expected_recv,
        }
    }

    pub fn encode(&mut self, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
        let current = self.next_send;
        let framed = encode_frame(current, payload)?;
        self.next_send = self
            .next_send
            .checked_add(1)
            .ok_or(FrameError::SequenceOverflow)?;
        Ok(framed)
    }

    pub fn decode<'a>(&mut self, frame: &'a [u8]) -> Result<FrameSlice<'a>, FrameError> {
        let slice = decode_frame(frame)?;
        if slice.packet_number != self.expected_recv {
            return Err(FrameError::OutOfOrder {
                expected: self.expected_recv,
                seen: slice.packet_number,
            });
        }
        self.expected_recv = self
            .expected_recv
            .checked_add(1)
            .ok_or(FrameError::SequenceOverflow)?;
        Ok(slice)
    }

    pub fn next_send(&self) -> u64 {
        self.next_send
    }

    pub fn expected_recv(&self) -> u64 {
        self.expected_recv
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let payload = b"hello velocity";
        let encoded = encode_frame(42, payload).expect("encode");
        let decoded = decode_frame(&encoded).expect("decode");
        assert_eq!(decoded.packet_number, 42);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn rejects_length_mismatch() {
        let mut encoded = encode_frame(1, b"payload").expect("encode");
        // Truncate payload to create mismatch
        encoded.truncate(FRAME_HEADER_LEN + 3);
        let err = decode_frame(&encoded).unwrap_err();
        assert_eq!(err, FrameError::LengthMismatch);
    }

    #[test]
    fn sequencer_tracks_ordering() {
        let mut sequencer = FrameSequencer::new(0, 0);
        let frame = sequencer.encode(b"data").expect("encode");
        let slice = sequencer.decode(&frame).expect("decode");
        assert_eq!(slice.packet_number, 0);
        let out = sequencer.encode(b"next").expect("encode next");
        assert_eq!(decode_frame(&out).unwrap().packet_number, 1);
    }

    #[test]
    fn chunking_roundtrip_spans_multiple_frames() {
        let mut sender = FrameSequencer::new(0, 0);
        let mut receiver = FrameSequencer::new(0, 0);
        let payload = vec![0x42u8; FRAME_MAX_PAYLOAD * 2 + 17];
        let frames = encode_chunked_payload(&mut sender, &payload).expect("encode chunked");
        assert!(frames.len() >= 2);

        let mut assembler = ChunkAssembler::new(HANDSHAKE_MESSAGE_MAX);
        let mut reconstructed = None;
        for frame in frames {
            let slice = receiver.decode(&frame).expect("decode frame");
            if let Some(done) = assembler.push_slice(slice).expect("assemble") {
                reconstructed = Some(done);
            }
        }

        assert_eq!(reconstructed.expect("reconstructed"), payload);
    }

    #[test]
    fn chunking_with_extended_limit_handles_large_payload() {
        let mut small_limit = FrameSequencer::new(0, 0);
        let oversized = vec![0xAAu8; HANDSHAKE_MESSAGE_MAX + 1];
        let err = encode_chunked_payload(&mut small_limit, &oversized).unwrap_err();
        assert_eq!(err, FrameError::PayloadTooLarge);

        let mut sender = FrameSequencer::new(0, 0);
        let mut receiver = FrameSequencer::new(0, 0);
        let frames =
            encode_chunked_payload_with_limit(&mut sender, &oversized, APPLICATION_MESSAGE_MAX)
                .expect("encode with extended limit");
        assert!(frames.len() >= 2);

        let mut assembler = ChunkAssembler::new(APPLICATION_MESSAGE_MAX);
        let mut reconstructed = None;
        for frame in frames {
            let slice = receiver.decode(&frame).expect("decode frame");
            if let Some(done) = assembler.push_slice(slice).expect("assemble") {
                reconstructed = Some(done);
            }
        }

        assert_eq!(reconstructed.expect("reconstructed"), oversized);
    }

    #[test]
    fn malformed_frame_no_panic_and_expected_errors() {
        // deterministic LCG for pseudo-random bytes (test reproducible)
        let mut seed: u64 = 0xDEADBEEFCAFEBABE;
        fn lcg_next(s: &mut u64) -> u8 {
            // simple LCG: x = x * 6364136223846793005 + 1
            *s = s.wrapping_mul(6364136223846793005u64).wrapping_add(1);
            (*s >> 32) as u8
        }

        // Try a variety of random-length buffers and ensure decode_frame never panics
        for len in 0..256usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push(lcg_next(&mut seed));
            }

            // decode_frame should return Result, not panic. Use catch_unwind to be extra safe.
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decode_frame(&buf)));
            assert!(res.is_ok(), "decode_frame panicked on random buffer length={}", len);
        }

        // Craft specific malformed frames to validate error kinds
        // 1) Too short header
        let short = vec![0u8; FRAME_HEADER_LEN - 1];
        assert_eq!(decode_frame(&short).unwrap_err(), FrameError::TooShort);

        // 2) Declared length larger than actual -> LengthMismatch
        let mut good = encode_frame(7, b"hello").expect("encode");
        // corrupt length field to claim 100 bytes
        let claimed: u32 = 100;
        good[8..12].copy_from_slice(&claimed.to_be_bytes());
        assert_eq!(decode_frame(&good).unwrap_err(), FrameError::LengthMismatch);

        // 3) Declared length exceeds FRAME_MAX_PAYLOAD -> PayloadTooLarge
        let mut big = encode_frame(9, &vec![0u8; FRAME_MAX_PAYLOAD]).expect("encode big");
        let huge: u32 = (FRAME_MAX_PAYLOAD as u32) + 1;
        big[8..12].copy_from_slice(&huge.to_be_bytes());
        assert_eq!(decode_frame(&big).unwrap_err(), FrameError::PayloadTooLarge);

        // 4) Feed random payloads into ChunkAssembler and ensure no panic and correct errors
        let mut assembler = ChunkAssembler::new(HANDSHAKE_MESSAGE_MAX);
        // push a few random payload slices
        for _ in 0..128 {
            let mut payload = Vec::with_capacity(64);
            for _ in 0..(lcg_next(&mut seed) as usize % 64) {
                payload.push(lcg_next(&mut seed));
            }
            // Create a fake FrameSlice view (packet_number irrelevant for assembler)
            let slice = FrameSlice { packet_number: 0, payload: &payload };
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assembler.push_slice(slice)));
            assert!(res.is_ok(), "ChunkAssembler panicked on random payload");
        }
    }

    #[test]
    fn tampering_shows_transport_layer_limits() {
        // The framing layer only provides sequencing and length checks. If an on-path
        // attacker flips payload bytes but keeps the header length correct, the frame
        // decoder will happily return the modified payload. This test documents that
        // expectation so reviewers don't assume the frame layer provides integrity.
        let mut seq = FrameSequencer::new(10, 10);
        let payload = b"sensitive data";
        let mut frame = seq.encode(payload).expect("encode");

        // flip some payload bytes but preserve total length
        if frame.len() > FRAME_HEADER_LEN + 2 {
            let idx = FRAME_HEADER_LEN + 1;
            frame[idx] ^= 0xFF;
        }

        // decode_frame will not detect content tampering; it only checks header/length
        let decoded = decode_frame(&frame).expect("decode after tamper");
        assert_eq!(decoded.len(), payload.len());

        // The sequencer.decode enforces ordering (packet number). Out-of-order frames
        // should be rejected.
        let mut recv = FrameSequencer::new(0, 0);
        let good = recv.encode(b"a").expect("encode a");
        let bad = recv.encode(b"b").expect("encode b");
        // craft an out-of-order scenario by attempting to decode 'bad' before 'good'
        let mut other = FrameSequencer::new(0, 0);
        let err = other.decode(&bad).unwrap_err();
        assert!(matches!(err, FrameError::OutOfOrder { .. }));
        // now decode the correct first frame and then the second
        other.decode(&good).expect("decode good after out-of-order");
        other.decode(&bad).expect("decode bad in order now");
    }
}
