//! Client components for PQ-QUIC.
//!
//! The full implementation will multiplex HTTP semantics across PQ-QUIC
//! streams. For now we provide a minimal handshake probe against the server
//! stub to validate CI and developer workflows.

mod kem;

pub use kem::{extract_kem_public, parse_kem_payload};
use pqq_core::{
    build_initial_packet, cbor_from_slice, cbor_to_vec, decode_handshake_response,
    encode_chunked_payload, AlpnResolution, CborError, ChunkAssembler, FallbackDirective,
    FrameError, FrameSequencer, HandshakeConfig, HandshakeResponse, FRAME_HEADER_LEN,
    FRAME_MAX_PAYLOAD, HANDSHAKE_MESSAGE_MAX,
};
pub use pqq_tls::SecurityProfile;
use pqq_tls::{
    ClientHandshake, ClientHelloOptions, HybridHandshakeError, HybridSuite, KemProvider, MlKem1024,
    MlKem512, MlKem768, Perspective, ResumptionParams, ServerHelloPayload, SessionCrypto,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use url::Url;

const HANDSHAKE_FRAME_CAPACITY: usize = FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD;

#[derive(Debug, Clone)]
struct ResumptionState {
    ticket: Vec<u8>,
    secret: [u8; 32],
    max_early_data: u32,
}

struct ClientCryptoArtifacts {
    crypto: SessionCrypto,
    resumption_accepted: bool,
    early_data_attempted: Option<Vec<u8>>,
    framing: FrameSequencer,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub handshake: HandshakeConfig,
    pub server: SocketAddr,
    pub server_kem_public: Option<Vec<u8>>,
    pub security_profile: SecurityProfile,
}

impl ClientConfig {
    pub fn new(server: SocketAddr) -> Self {
        Self {
            handshake: HandshakeConfig::default(),
            server,
            server_kem_public: None,
            security_profile: SecurityProfile::Balanced,
        }
    }

    pub fn with_server(mut self, server: SocketAddr) -> Self {
        self.server = server;
        self
    }

    pub fn with_alpns<I, S>(mut self, alpns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.handshake = self.handshake.with_supported_alpns(alpns);
        self
    }

    pub fn with_server_kem_public(mut self, public_key: impl Into<Vec<u8>>) -> Self {
        self.server_kem_public = Some(public_key.into());
        self
    }

    pub fn with_security_profile(mut self, profile: SecurityProfile) -> Self {
        self.security_profile = profile;
        self
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self::new(SocketAddr::from(([127, 0, 0, 1], 443)))
    }
}

pub struct Client {
    config: ClientConfig,
    resumption: Arc<Mutex<Option<ResumptionState>>>,
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            resumption: Arc::new(Mutex::new(None)),
        }
    }

    /// Perform the Initial handshake and retain the connected UDP socket for
    /// further exchanges.
    pub async fn connect(&self) -> Result<ClientSession, ClientError> {
        match self.connect_or_fallback().await? {
            HandshakeOutcome::Established { session, .. } => Ok(session),
            HandshakeOutcome::Fallback(response) => Err(ClientError::AlpnFallback(response)),
            HandshakeOutcome::Unsupported(response) => Err(ClientError::AlpnUnsupported(response)),
        }
    }

    /// Convenience helper that performs a GET request against the configured
    /// server using HTTP/1.1 semantics.
    pub async fn get(&self, url: &str) -> Result<String, ClientError> {
        let parsed = Url::parse(url).map_err(|_| ClientError::InvalidUrl)?;
        let path = match parsed.path() {
            "" => "/",
            other => other,
        };
        let host = parsed.host_str().unwrap_or("localhost");
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, host
        );
        let request_bytes = request.as_bytes().to_vec();

        match self
            .connect_or_fallback_with_early(Some(request_bytes.clone()))
            .await?
        {
            HandshakeOutcome::Established {
                session,
                resumption_accepted,
                early_data,
            } => {
                if resumption_accepted && early_data.is_some() {
                    session.receive_response_string().await
                } else {
                    session.send_request_string(&request_bytes).await
                }
            }
            HandshakeOutcome::Fallback(response) => Err(ClientError::AlpnFallback(response)),
            HandshakeOutcome::Unsupported(response) => Err(ClientError::AlpnUnsupported(response)),
        }
    }

    /// Send a stub Initial packet carrying a comma-separated ALPN list.
    pub async fn probe(&self) -> Result<HandshakeResponse, ClientError> {
        let (_socket, response) = self.perform_initial_handshake().await?;
        Ok(response)
    }

    /// Perform the handshake and return either an established session or
    /// a fallback directive from the server.
    pub async fn connect_or_fallback(&self) -> Result<HandshakeOutcome, ClientError> {
        self.connect_or_fallback_with_early(None).await
    }

    async fn connect_or_fallback_with_early(
        &self,
        early_data: Option<Vec<u8>>,
    ) -> Result<HandshakeOutcome, ClientError> {
        let (socket, response) = self.perform_initial_handshake().await?;
        match response.resolution.clone() {
            AlpnResolution::Supported(_) => {
                let artifacts = self.perform_crypto_handshake(&socket, early_data).await?;
                Ok(HandshakeOutcome::Established {
                    session: ClientSession::new(
                        socket,
                        response,
                        artifacts.crypto,
                        artifacts.framing,
                    ),
                    resumption_accepted: artifacts.resumption_accepted,
                    early_data: artifacts.early_data_attempted,
                })
            }
            AlpnResolution::Fallback(_) => Ok(HandshakeOutcome::Fallback(response)),
            AlpnResolution::Unsupported => Ok(HandshakeOutcome::Unsupported(response)),
        }
    }

    async fn perform_initial_handshake(
        &self,
    ) -> Result<(UdpSocket, HandshakeResponse), ClientError> {
        let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
        socket.connect(self.config.server).await?;

        let packet = build_initial_packet(self.config.handshake.supported_alpns.clone());
        socket.send(&packet).await?;

        let mut frame_buf = [0u8; HANDSHAKE_FRAME_CAPACITY];
        let mut framing = FrameSequencer::new(0, 0);
        let mut assembler = ChunkAssembler::new(HANDSHAKE_MESSAGE_MAX);
        let response_bytes = loop {
            let len = socket.recv(&mut frame_buf).await?;
            let slice = framing
                .decode(&frame_buf[..len])
                .map_err(ClientError::Framing)?;
            if let Some(message) = assembler.push_slice(slice).map_err(ClientError::Framing)? {
                break message;
            }
        };
        let response = decode_handshake_response(&response_bytes)
            .map_err(|_| ClientError::MalformedResponse)?;

        Ok((socket, response))
    }

    async fn perform_crypto_handshake(
        &self,
        socket: &UdpSocket,
        early_data: Option<Vec<u8>>,
    ) -> Result<ClientCryptoArtifacts, ClientError> {
        let server_static = self
            .config
            .server_kem_public
            .clone()
            .ok_or(ClientError::MissingServerKey)?;

        let cached = {
            let guard = self.resumption.lock().await;
            guard.clone()
        };

        let mut options = ClientHelloOptions::default();
        let mut early_data_attempted = None;
        if let Some(cache) = cached.as_ref() {
            options.resumption = Some(ResumptionParams {
                ticket: cache.ticket.clone(),
                secret: cache.secret,
            });
            if let Some(data) = early_data.clone() {
                if (data.len() as u32) <= cache.max_early_data {
                    options.early_data = Some(data.clone());
                    early_data_attempted = Some(data);
                }
            }
        }

        let profile = self.config.security_profile;
        let suite = profile.suite();
        match profile {
            SecurityProfile::Turbo => {
                self.perform_crypto_handshake_with::<MlKem512>(
                    socket,
                    server_static.clone(),
                    options.clone(),
                    suite,
                    early_data_attempted.clone(),
                )
                .await
            }
            SecurityProfile::Balanced => {
                self.perform_crypto_handshake_with::<MlKem768>(
                    socket,
                    server_static.clone(),
                    options.clone(),
                    suite,
                    early_data_attempted.clone(),
                )
                .await
            }
            SecurityProfile::Fortress => {
                self.perform_crypto_handshake_with::<MlKem1024>(
                    socket,
                    server_static,
                    options,
                    suite,
                    early_data_attempted,
                )
                .await
            }
        }
    }

    async fn perform_crypto_handshake_with<K: KemProvider + Default + Send + 'static>(
        &self,
        socket: &UdpSocket,
        server_static: Vec<u8>,
        options: ClientHelloOptions,
        suite: HybridSuite,
        early_data_attempted: Option<Vec<u8>>,
    ) -> Result<ClientCryptoArtifacts, ClientError> {
        let state = ClientHandshake::new(K::default(), suite, server_static, options)
            .map_err(ClientError::Hybrid)?;
        let client_payload_bytes = state.client_payload_bytes().to_vec();
        let mut framing = FrameSequencer::new(1, 1);
        let client_frames = encode_chunked_payload(&mut framing, &client_payload_bytes)
            .map_err(ClientError::Framing)?;
        for frame in client_frames {
            socket.send(&frame).await?;
        }

        let mut frame_buf = vec![0u8; HANDSHAKE_FRAME_CAPACITY];
        let mut assembler = ChunkAssembler::new(HANDSHAKE_MESSAGE_MAX);
        let server_payload_bytes = loop {
            let len = socket.recv(&mut frame_buf[..]).await?;
            let slice = framing
                .decode(&frame_buf[..len])
                .map_err(ClientError::Framing)?;
            if let Some(message) = assembler.push_slice(slice).map_err(ClientError::Framing)? {
                break message;
            }
        };
        let server_payload: ServerHelloPayload =
            cbor_from_slice(&server_payload_bytes).map_err(ClientError::Decode)?;

        let completion = state
            .complete(&server_payload)
            .map_err(ClientError::Hybrid)?;
        let client_finished_encoded =
            cbor_to_vec(&completion.client_finished).map_err(ClientError::Encode)?;
        let finished_frames = encode_chunked_payload(&mut framing, &client_finished_encoded)
            .map_err(ClientError::Framing)?;
        for frame in finished_frames {
            socket.send(&frame).await?;
        }

        let resumption_secret = completion.key_schedule.resumption_secret();
        let keys = completion.key_schedule.session_keys(Perspective::Client);
        let crypto = SessionCrypto::new(keys).map_err(ClientError::Crypto)?;
        let new_state = completion
            .session_ticket
            .clone()
            .map(|ticket| ResumptionState {
                ticket,
                secret: resumption_secret,
                max_early_data: completion.max_early_data,
            });
        {
            let mut guard = self.resumption.lock().await;
            *guard = new_state;
        }
        let attempted = completion.early_data.clone().or(early_data_attempted);

        Ok(ClientCryptoArtifacts {
            crypto,
            resumption_accepted: completion.resumption_accepted,
            early_data_attempted: attempted,
            framing,
        })
    }
}

#[derive(Debug)]
pub enum HandshakeOutcome {
    Established {
        session: ClientSession,
        resumption_accepted: bool,
        early_data: Option<Vec<u8>>,
    },
    Fallback(HandshakeResponse),
    Unsupported(HandshakeResponse),
}

/// Represents a connected client session that can exchange application data
/// over the negotiated UDP path.
#[derive(Debug)]
pub struct ClientSession {
    socket: UdpSocket,
    handshake_response: HandshakeResponse,
    crypto: Arc<Mutex<SessionCrypto>>,
    framing: Arc<Mutex<FrameSequencer>>,
}

impl ClientSession {
    fn new(
        socket: UdpSocket,
        handshake_response: HandshakeResponse,
        crypto: SessionCrypto,
        framing: FrameSequencer,
    ) -> Self {
        Self {
            socket,
            handshake_response,
            crypto: Arc::new(Mutex::new(crypto)),
            framing: Arc::new(Mutex::new(framing)),
        }
    }

    pub fn handshake_response(&self) -> &HandshakeResponse {
        &self.handshake_response
    }

    pub fn alpn_resolution(&self) -> &AlpnResolution {
        &self.handshake_response.resolution
    }

    pub fn fallback_directive(&self) -> Option<&FallbackDirective> {
        self.handshake_response.fallback.as_ref()
    }

    pub async fn send_request(&self, payload: &[u8]) -> Result<Vec<u8>, ClientError> {
        let ciphertext = {
            let mut crypto = self.crypto.lock().await;
            crypto.seal(payload).map_err(ClientError::Crypto)?
        };
        let framed = {
            let mut framing = self.framing.lock().await;
            framing.encode(&ciphertext).map_err(ClientError::Framing)?
        };
        self.socket.send(&framed).await?;

        self.receive_response().await
    }

    pub async fn send_request_string(&self, payload: &[u8]) -> Result<String, ClientError> {
        let bytes = self.send_request(payload).await?;
        String::from_utf8(bytes).map_err(|_| ClientError::MalformedResponse)
    }

    pub async fn receive_response(&self) -> Result<Vec<u8>, ClientError> {
        let mut buf = vec![0u8; 4096];
        let len = self.socket.recv(&mut buf).await?;
        buf.truncate(len);

        let payload = {
            let mut framing = self.framing.lock().await;
            let slice = framing.decode(&buf).map_err(ClientError::Framing)?;
            slice.payload.to_vec()
        };

        let plaintext = {
            let mut crypto = self.crypto.lock().await;
            crypto.open(&payload).map_err(ClientError::Crypto)?
        };
        Ok(plaintext)
    }

    pub async fn receive_response_string(&self) -> Result<String, ClientError> {
        let bytes = self.receive_response().await?;
        String::from_utf8(bytes).map_err(|_| ClientError::MalformedResponse)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("server replied with malformed handshake payload")]
    MalformedResponse,
    #[error("server requested ALPN fallback")]
    AlpnFallback(HandshakeResponse),
    #[error("server does not support any requested ALPNs")]
    AlpnUnsupported(HandshakeResponse),
    #[error("invalid URL provided")]
    InvalidUrl,
    #[error("failed to encode handshake payload: {0}")]
    Encode(CborError),
    #[error("failed to decode handshake payload: {0}")]
    Decode(CborError),
    #[error("frame error: {0}")]
    Framing(FrameError),
    #[error("hybrid handshake error: {0}")]
    Hybrid(HybridHandshakeError),
    #[error("session crypto error: {0}")]
    Crypto(#[from] pqq_tls::CryptoError),
    #[error("server static KEM public key is required before initiating Velocity handshake")]
    MissingServerKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_initial_packet_has_expected_prefix() {
        let packet = build_initial_packet(["pqq/1", "h3"]);
        assert_eq!(packet[0] & 0b1100_0000, 0b1100_0000); // long header flag
        assert_eq!(&packet[1..5], &[0, 0, 0, 1]); // version
        assert_eq!(packet[5], 8); // dcid len
        assert_eq!(&packet[6..14], &[0u8; 8]);
        assert_eq!(packet[14], 8); // scid len
        assert_eq!(&packet[15..23], &[0u8; 8]);
    }
}
