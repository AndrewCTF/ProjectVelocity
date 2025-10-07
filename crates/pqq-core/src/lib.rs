//! Core transport primitives for PQ-QUIC.
//!
//! This crate intentionally keeps the surface small during the prototype phase.
//! It exposes packet parsing routines plus a lightweight asynchronous handshake
//! driver that negotiates ALPN and prepares for the hybrid key exchange.

pub mod cbor;
pub mod entropy;
pub mod frame;
pub mod link;
pub mod packet;
pub mod resumption;
pub mod transport;

pub use cbor::{from_slice as cbor_from_slice, to_vec as cbor_to_vec, Error as CborError};
pub use entropy::LavaRand;
pub use frame::{
    decode_frame, encode_chunked_payload, encode_chunked_payload_with_limit, encode_frame,
    ChunkAssembler, FrameError, FrameSequencer, FrameSlice, APPLICATION_MESSAGE_MAX,
    FRAME_HEADER_LEN, FRAME_MAX_PAYLOAD, HANDSHAKE_MESSAGE_MAX,
};
pub use link::{
    memory_link_pair, ChannelEndpoint, LinkEndpoint, LinkError, LinkHandle, LinkHandshakeDriver,
    LinkHandshakeError,
};
pub use packet::{parse_packet, PacketDecodeError, PacketType, ParsedPacket};
pub use resumption::{InMemoryReplayGuard, ReplayError, ReplayGuard, ReplayToken};
pub use transport::{
    build_initial_packet, decode_handshake_response, encode_handshake_response, AlpnResolution,
    FallbackDirective, HandshakeConfig, HandshakeDriver, HandshakeError, HandshakeResponse,
    StrictTransportDirective,
};
