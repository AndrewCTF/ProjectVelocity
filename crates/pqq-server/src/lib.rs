//! High-level PQ-QUIC server façade.
//!
//! The production design will expose HTTP-like semantics layered atop the
//! hybrid TLS core. The current implementation provides a sequential accept
//! loop, lightweight request/response helpers, and integrates the handshake
//! driver from `pqq-core`.

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::{stream::BoxStream, StreamExt};
use pqq_core::{
    cbor_from_slice, cbor_to_vec, encode_chunked_payload, encode_chunked_payload_with_limit,
    encode_handshake_response, AlpnResolution, CborError, ChunkAssembler, FallbackDirective,
    FrameError, FrameSequencer, HandshakeConfig, HandshakeDriver, HandshakeError,
    HandshakeResponse, InMemoryReplayGuard, ReplayGuard, StrictTransportDirective,
    APPLICATION_MESSAGE_MAX, FRAME_HEADER_LEN, FRAME_MAX_PAYLOAD, HANDSHAKE_MESSAGE_MAX,
};
pub use pqq_tls::SecurityProfile;
use pqq_tls::{
    ClientFinishedPayload, ClientHelloPayload, HybridHandshakeError, Perspective, ServerHandshake,
    SessionCrypto, SessionTicketManager, StaticKemKeyPair,
};
use pqq_tls::{HybridSuite, HybridTlsEngine, KemProvider, MlKem1024, MlKem512, MlKem768};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time;
use tracing::{error, warn};

const HANDSHAKE_FRAME_CAPACITY: usize = FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD;
const DEFAULT_TICKET_LIFETIME_SECS: u64 = 60 * 60;
const DEFAULT_MAX_EARLY_DATA: u32 = 16 * 1024;
const HANDSHAKE_QUEUE_SIZE: usize = 1024;
const PEER_CHANNEL_CAPACITY: usize = 32;

#[derive(Serialize)]
struct ServerTicketContext<'a> {
    kind: &'static str,
    alpns: &'a [String],
    max_early_data: u32,
    security_profile: &'static str,
    strict_transport: Option<&'a StrictTransportDirective>,
    publish_kem_public: bool,
}

fn security_profile_label(profile: SecurityProfile) -> &'static str {
    match profile {
        SecurityProfile::Turbo => "turbo",
        SecurityProfile::Balanced => "balanced",
        SecurityProfile::Fortress => "fortress",
    }
}

fn encode_server_ticket_context(
    alpns: &[String],
    max_early_data: u32,
    profile: SecurityProfile,
    strict_transport: Option<&StrictTransportDirective>,
    publish_kem_public: bool,
) -> Vec<u8> {
    let context = ServerTicketContext {
        kind: "pqq-server",
        alpns,
        max_early_data,
        security_profile: security_profile_label(profile),
        strict_transport,
        publish_kem_public,
    };
    serde_json::to_vec(&context).expect("serialize ticket context")
}

#[derive(Debug)]
struct HandshakeInbox {
    peer: SocketAddr,
    inbox: mpsc::Receiver<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct DatagramRouterHandle {
    peers: Arc<DashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>,
}

impl DatagramRouterHandle {
    fn new(peers: Arc<DashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>) -> Self {
        Self { peers }
    }

    fn drop_peer(&self, peer: SocketAddr) {
        self.peers.remove(&peer);
    }
}

fn start_datagram_router(
    socket: Arc<UdpSocket>,
) -> (DatagramRouterHandle, mpsc::Receiver<HandshakeInbox>) {
    let peers = Arc::new(DashMap::new());
    let handle = DatagramRouterHandle::new(Arc::clone(&peers));
    let (handshake_tx, handshake_rx) = mpsc::channel(HANDSHAKE_QUEUE_SIZE);

    tokio::spawn(async move {
        let mut buf = vec![0u8; HANDSHAKE_FRAME_CAPACITY];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let payload = buf[..len].to_vec();
                    if let Some(sender) = peers.get(&addr) {
                        if sender.send(payload).await.is_err() {
                            peers.remove(&addr);
                        }
                        continue;
                    }

                    let (tx, rx) = mpsc::channel::<Vec<u8>>(PEER_CHANNEL_CAPACITY);
                    peers.insert(addr, tx.clone());
                    if tx.send(payload).await.is_err() {
                        peers.remove(&addr);
                        continue;
                    }
                    if handshake_tx
                        .send(HandshakeInbox {
                            peer: addr,
                            inbox: rx,
                        })
                        .await
                        .is_err()
                    {
                        peers.remove(&addr);
                        break;
                    }
                }
                Err(err) => {
                    error!(target: "velocity::router", error = %err, "udp receive failed; retrying");
                    time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    });

    (handle, handshake_rx)
}

async fn recv_datagram_with_timeout(
    inbox: &mut mpsc::Receiver<Vec<u8>>,
    timeout: Duration,
) -> Result<Vec<u8>, ServerError> {
    match time::timeout(timeout, inbox.recv()).await {
        Ok(Some(buf)) => Ok(buf),
        Ok(None) => Err(ServerError::PeerClosed),
        Err(_) => Err(ServerError::Handshake(HandshakeError::Timeout)),
    }
}

/// Builder-style server configuration helper.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub handshake: HandshakeConfig,
    pub security_profile: SecurityProfile,
    pub certificate_path: Option<PathBuf>,
    pub private_key_path: Option<PathBuf>,
    pub session_ticket_master_key: Option<[u8; 32]>,
    pub session_ticket_lifetime: Duration,
    pub max_early_data: u32,
    pub telemetry: Option<Arc<dyn HandshakeTelemetryCollector>>,
    pub replay_guard: Option<Arc<dyn ReplayGuard>>,
    pub max_concurrent_sessions: usize,
    pub strict_transport: Option<StrictTransportDirective>,
    pub publish_kem_public: bool,
}

impl ServerConfig {
    /// Construct a configuration referencing a certificate chain and private key.
    ///
    /// The files are not parsed yet; the paths are stored so future TLS wiring can
    /// load them lazily.
    pub fn from_cert_chain<P, Q>(certificate: P, private_key: Q) -> Self
    where
        P: Into<PathBuf>,
        Q: Into<PathBuf>,
    {
        Self {
            certificate_path: Some(certificate.into()),
            private_key_path: Some(private_key.into()),
            ..Default::default()
        }
    }

    /// Override the supported ALPN list.
    pub fn with_alpn<I, S>(mut self, alpns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.handshake.supported_alpns = alpns.into_iter().map(Into::into).collect();
        self
    }

    /// Advertise fallback endpoint metadata.
    pub fn with_fallback(
        mut self,
        alpn: impl Into<String>,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        self.handshake = self
            .handshake
            .clone()
            .with_fallback_endpoint(alpn.into(), host, port);
        self
    }

    /// Merge an existing [`HandshakeConfig`].
    pub fn with_handshake(mut self, handshake: HandshakeConfig) -> Self {
        self.handshake = handshake;
        self
    }

    /// Select the Velocity security profile.
    pub fn with_security_profile(mut self, profile: SecurityProfile) -> Self {
        self.security_profile = profile;
        self.max_early_data = profile.max_early_data();
        self
    }

    /// Override the stateless session ticket master key.
    pub fn with_ticket_master_key(mut self, master_key: [u8; 32]) -> Self {
        self.session_ticket_master_key = Some(master_key);
        self
    }

    /// Configure the session ticket lifetime.
    pub fn with_ticket_lifetime(mut self, lifetime: Duration) -> Self {
        self.session_ticket_lifetime = lifetime;
        self
    }

    /// Configure the maximum amount of 0-RTT early data the server will accept.
    pub fn with_max_early_data(mut self, max: u32) -> Self {
        self.max_early_data = max;
        self
    }

    /// Include the server's ML-KEM public key in the handshake payload.
    pub fn publish_kem_public(mut self, enable: bool) -> Self {
        self.publish_kem_public = enable;
        self
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            handshake: HandshakeConfig::default(),
            security_profile: SecurityProfile::Balanced,
            certificate_path: None,
            private_key_path: None,
            session_ticket_master_key: None,
            session_ticket_lifetime: Duration::from_secs(DEFAULT_TICKET_LIFETIME_SECS),
            max_early_data: DEFAULT_MAX_EARLY_DATA,
            telemetry: None,
            replay_guard: None,
            max_concurrent_sessions: 1024,
            strict_transport: None,
            publish_kem_public: false,
        }
    }
}

impl ServerConfig {
    /// Attach a telemetry collector that will receive handshake summaries.
    pub fn with_telemetry(mut self, collector: Arc<dyn HandshakeTelemetryCollector>) -> Self {
        self.telemetry = Some(collector);
        self
    }

    /// Override the replay guard used to protect 0-RTT resumption.
    pub fn with_replay_guard(mut self, guard: Arc<dyn ReplayGuard>) -> Self {
        self.replay_guard = Some(guard);
        self
    }

    /// Limit the number of concurrent application sessions served in parallel.
    pub fn with_max_concurrent_sessions(mut self, limit: usize) -> Self {
        self.max_concurrent_sessions = limit.max(1);
        self
    }

    /// Advertise a strict transport policy to clients, mirroring HSTS semantics.
    pub fn with_strict_transport(mut self, directive: StrictTransportDirective) -> Self {
        self.strict_transport = Some(directive);
        self
    }
}

/// Receives privacy-preserving summaries for each negotiated handshake.
pub trait HandshakeTelemetryCollector: Send + Sync + std::fmt::Debug {
    fn record(&self, event: &HandshakeTelemetryEvent);
}

/// Minimal event payload describing a Velocity handshake outcome.
#[derive(Debug, Clone)]
pub struct HandshakeTelemetryEvent {
    pub peer_hash: [u8; 32],
    pub resolution: AlpnResolution,
    pub fallback: Option<FallbackDirective>,
    pub suite: HybridSuite,
    pub resumption_accepted: bool,
    pub session_ticket_issued: bool,
    pub client_hello_len: usize,
    pub server_hello_len: usize,
    pub client_finished_len: usize,
    pub early_data_len: Option<usize>,
    pub max_early_data: u32,
}

/// Convenience collector that forwards telemetry to the tracing subsystem.
#[derive(Debug, Default)]
pub struct TracingTelemetryCollector;

impl HandshakeTelemetryCollector for TracingTelemetryCollector {
    fn record(&self, event: &HandshakeTelemetryEvent) {
        let peer_b64 = BASE64_STANDARD.encode(event.peer_hash);
        tracing::info!(
            target: "velocity::handshake",
            peer_hash = %peer_b64,
            resolution = ?event.resolution,
            fallback = ?event.fallback,
            suite = ?event.suite,
            resumption_accepted = event.resumption_accepted,
            session_ticket_issued = event.session_ticket_issued,
            client_hello_len = event.client_hello_len,
            server_hello_len = event.server_hello_len,
            client_finished_len = event.client_finished_len,
            early_data_len = ?event.early_data_len,
            max_early_data = event.max_early_data,
            "velocity handshake telemetry"
        );
    }
}

fn create_server_handshake<P: KemProvider>(
    kem: P,
    suite: HybridSuite,
    manager: Arc<SessionTicketManager>,
    max_early_data: u32,
    static_keypair: StaticKemKeyPair,
    replay_guard: Arc<dyn ReplayGuard>,
    application_context: &[u8],
) -> ServerHandshake<P> {
    ServerHandshake::new(kem, suite, manager, static_keypair, replay_guard)
        .with_max_early_data(max_early_data)
        .with_application_context(application_context.to_vec())
}

/// Minimal async server that accepts Initial packets, negotiates ALPN, and
/// provides the resulting session for application handlers.
pub struct Server {
    socket: Arc<UdpSocket>,
    driver: HandshakeDriver,
    tls: Arc<Mutex<HybridTlsEngine>>,
    ticket_manager: Arc<SessionTicketManager>,
    max_early_data: u32,
    application_context: Vec<u8>,
    static_keypair: StaticKemKeyPair,
    suite: HybridSuite,
    security_profile: SecurityProfile,
    telemetry: Option<Arc<dyn HandshakeTelemetryCollector>>,
    telemetry_salt: Option<[u8; 32]>,
    replay_guard: Arc<dyn ReplayGuard>,
    strict_transport: Option<StrictTransportDirective>,
    publish_kem_public: bool,
    router: DatagramRouterHandle,
    handshake_rx: Mutex<mpsc::Receiver<HandshakeInbox>>,
    handshake_timeout: Duration,
    session_semaphore: Arc<Semaphore>,
}

struct CryptoHandshakeArtifacts {
    crypto: SessionCrypto,
    transcript: HandshakeTranscript,
    session_ticket: Option<Vec<u8>>,
    resumption_accepted: bool,
    early_data: Option<Vec<u8>>,
    max_early_data: u32,
    framing: FrameSequencer,
}

#[derive(Debug)]
struct CombinedHandshake {
    response: HandshakeResponse,
    crypto: Option<Arc<Mutex<SessionCrypto>>>,
    transcript: Option<HandshakeTranscript>,
    session_ticket: Option<Vec<u8>>,
    resumption_accepted: bool,
    early_data: Option<Vec<u8>>,
    max_early_data: u32,
    framing: Option<FrameSequencer>,
}

impl CombinedHandshake {
    fn session_ticket_issued(&self) -> bool {
        self.session_ticket.is_some()
    }

    fn early_data_len(&self) -> Option<usize> {
        self.early_data.as_ref().map(|data| data.len())
    }
}

impl Server {
    /// Bind a UDP socket and prepare the handshake driver.
    pub async fn bind(
        addr: impl Into<SocketAddr>,
        config: ServerConfig,
    ) -> Result<Self, ServerError> {
        let addr = addr.into();
        let raw_socket = UdpSocket::bind(addr).await?;
        raw_socket.set_broadcast(false)?;
        let socket = Arc::new(raw_socket);
        let (router, handshake_rx) = start_datagram_router(Arc::clone(&socket));
        let profile = config.security_profile;
        let suite = profile.suite();
        let lifetime = config.session_ticket_lifetime;
        let max_early_data = config.max_early_data.min(profile.max_early_data());
        let strict_transport = config.strict_transport.clone();
        let publish_kem_public = config.publish_kem_public;
        let handshake_config = config.handshake;
        let master_key = config.session_ticket_master_key.unwrap_or_else(|| {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            key
        });
        let ticket_manager = Arc::new(SessionTicketManager::new(master_key, lifetime));
        let replay_guard = config
            .replay_guard
            .clone()
            .unwrap_or_else(|| Arc::new(InMemoryReplayGuard::default()));
        let (static_public, static_secret) = match profile {
            SecurityProfile::Turbo => MlKem512.generate_keypair().map_err(ServerError::Hybrid)?,
            SecurityProfile::Balanced => {
                MlKem768.generate_keypair().map_err(ServerError::Hybrid)?
            }
            SecurityProfile::Fortress => {
                MlKem1024.generate_keypair().map_err(ServerError::Hybrid)?
            }
        };
        let static_keypair = StaticKemKeyPair::new(static_public, static_secret);
        let telemetry = config.telemetry.clone();
        let telemetry_salt = telemetry.as_ref().map(|_| {
            let mut salt = [0u8; 32];
            OsRng.fill_bytes(&mut salt);
            salt
        });
        let handshake_timeout = handshake_config.handshake_timeout;
        let session_semaphore = Arc::new(Semaphore::new(config.max_concurrent_sessions));
        let application_context = encode_server_ticket_context(
            &handshake_config.supported_alpns,
            max_early_data,
            profile,
            strict_transport.as_ref(),
            publish_kem_public,
        );
        let driver = HandshakeDriver::new(handshake_config);
        Ok(Self {
            socket,
            driver,
            tls: Arc::new(Mutex::new(HybridTlsEngine::new())),
            ticket_manager,
            max_early_data,
            application_context,
            static_keypair,
            suite,
            security_profile: profile,
            telemetry,
            telemetry_salt,
            replay_guard,
            strict_transport,
            publish_kem_public,
            router,
            handshake_rx: Mutex::new(handshake_rx),
            handshake_timeout,
            session_semaphore,
        })
    }

    /// Expose the server's static KEM public key for clients.
    pub fn kem_public_key(&self) -> &[u8] {
        &self.static_keypair.public
    }

    /// Returns the socket address the server is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, ServerError> {
        Ok(self.socket.local_addr()?)
    }

    /// Accept a single handshake and return the session context.
    pub async fn accept(&self) -> Result<ServerSession, ServerError> {
        let mut handshake_rx = self.handshake_rx.lock().await;
        let HandshakeInbox { peer, inbox } = match handshake_rx.recv().await {
            Some(job) => job,
            None => return Err(ServerError::Shutdown),
        };
        drop(handshake_rx);

        let mut inbox = inbox;
        let initial = match recv_datagram_with_timeout(&mut inbox, self.handshake_timeout).await {
            Ok(buf) => buf,
            Err(err) => {
                self.router.drop_peer(peer);
                return Err(err);
            }
        };

        let peer_host = peer.ip().to_string();
        let mut response = match self
            .driver
            .process_initial_datagram(&initial, Some(&peer_host))
        {
            Ok(res) => res,
            Err(err) => {
                self.router.drop_peer(peer);
                return Err(ServerError::Handshake(err));
            }
        };

        if response.strict_transport.is_none() {
            response.strict_transport = self.strict_transport.clone();
        }

        if self.publish_kem_public && matches!(response.resolution, AlpnResolution::Supported(_)) {
            let key_b64 = BASE64_STANDARD.encode(&self.static_keypair.public);
            response.pq_payload = Some(key_b64);
        }

        let encoded = match encode_handshake_response(&response) {
            Ok(vec) => vec,
            Err(err) => {
                self.router.drop_peer(peer);
                return Err(ServerError::Handshake(err));
            }
        };

        let mut sequencer = FrameSequencer::new(0, 0);
        let frames = match encode_chunked_payload(&mut sequencer, &encoded) {
            Ok(frames) => frames,
            Err(err) => {
                self.router.drop_peer(peer);
                return Err(ServerError::Framing(err));
            }
        };

        for frame in frames {
            if let Err(err) = self.socket.send_to(&frame, peer).await {
                self.router.drop_peer(peer);
                return Err(ServerError::Io(err));
            }
        }

        {
            let mut tls = self.tls.lock().await;
            tls.set_negotiated(response.resolution.clone());
        }

        let mut session_inbox: Option<Mutex<mpsc::Receiver<Vec<u8>>>> = None;
        let mut crypto: Option<Arc<Mutex<SessionCrypto>>> = None;
        let mut transcript: Option<HandshakeTranscript> = None;
        let mut session_ticket: Option<Vec<u8>> = None;
        let mut resumption_accepted = false;
        let mut early_data: Option<Vec<u8>> = None;
        let mut max_early_data = self.max_early_data;
        let mut framing_state: Option<FrameSequencer> = None;

        if matches!(response.resolution, AlpnResolution::Supported(_)) {
            match self.perform_crypto_handshake(peer, &mut inbox).await {
                Ok(artifacts) => {
                    let CryptoHandshakeArtifacts {
                        crypto: session_crypto,
                        transcript: session_transcript,
                        session_ticket: ticket,
                        resumption_accepted: accepted,
                        early_data: received_early_data,
                        max_early_data: advertised_early,
                        framing,
                    } = artifacts;

                    max_early_data = advertised_early;
                    resumption_accepted = accepted;
                    early_data = received_early_data;
                    session_ticket = ticket;
                    transcript = Some(session_transcript);
                    crypto = Some(Arc::new(Mutex::new(session_crypto)));
                    session_inbox = Some(Mutex::new(inbox));
                    framing_state = Some(framing);
                }
                Err(err) => {
                    self.router.drop_peer(peer);
                    return Err(err);
                }
            }
        } else {
            self.router.drop_peer(peer);
        }

        if let Some(transcript) = &transcript {
            let mut payload = json!({
                "client_hello_b64": transcript.client_base64(),
                "server_hello_b64": transcript.server_base64(),
                "client_finished_b64": transcript.client_finished_base64(),
                "resumption_accepted": resumption_accepted,
                "max_early_data": max_early_data,
                "issued_ticket_b64": session_ticket
                    .as_ref()
                    .map(|ticket| BASE64_STANDARD.encode(ticket)),
            });
            if self.publish_kem_public {
                if let serde_json::Value::Object(ref mut map) = payload {
                    map.insert(
                        "kem_public_b64".to_string(),
                        json!(BASE64_STANDARD.encode(&self.static_keypair.public)),
                    );
                }
            }
            response.pq_payload = Some(payload.to_string());
        }
        let combined = CombinedHandshake {
            response,
            crypto,
            transcript,
            session_ticket,
            resumption_accepted,
            early_data,
            max_early_data,
            framing: framing_state,
        };

        self.publish_telemetry(peer, &combined);

        Ok(ServerSession::from_combined(
            Arc::clone(&self.socket),
            peer,
            combined,
            session_inbox,
            self.router.clone(),
        ))
    }

    /// Run the provided handler for every accepted session until an error occurs
    /// or the task is cancelled.
    pub async fn serve<H>(&self, handler: H) -> Result<(), ServerError>
    where
        H: RequestHandler,
    {
        let handler = Arc::new(handler);
        loop {
            let session = match self.accept().await {
                Ok(session) => session,
                Err(ServerError::Handshake(HandshakeError::Timeout)) => {
                    continue;
                }
                Err(err) => return Err(err),
            };

            if !session.is_application_ready() {
                warn!(peer = %session.peer(), "handshake negotiated fallback; skipping handler");
                continue;
            }

            let permit = match Arc::clone(&self.session_semaphore).acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return Err(ServerError::Shutdown),
            };
            let handler = Arc::clone(&handler);

            tokio::spawn(async move {
                let peer = session.peer();
                let result = async {
                    let request = session.recv_request().await?;
                    let response = handler.handle(request).await;
                    session.send_response(response).await
                }
                .await;

                drop(permit);

                if let Err(err) = result {
                    warn!(peer = %peer, error = %err, "session handling failed");
                }
            });
        }
    }

    /// Access the underlying TLS engine snapshot.
    pub async fn tls_engine(&self) -> HybridTlsEngine {
        self.tls.lock().await.clone()
    }

    fn publish_telemetry(&self, peer: SocketAddr, combined: &CombinedHandshake) {
        let (Some(collector), Some(salt)) = (self.telemetry.as_ref(), self.telemetry_salt.as_ref())
        else {
            return;
        };

        let response = &combined.response;
        let transcript = combined.transcript.as_ref();
        let resumption_accepted = combined.resumption_accepted;
        let session_ticket_issued = combined.session_ticket_issued();
        let early_data_len = combined.early_data_len();
        let max_early_data = combined.max_early_data;

        let peer_hash = hash_peer(salt, peer.ip());
        let event = HandshakeTelemetryEvent {
            peer_hash,
            resolution: response.resolution.clone(),
            fallback: response.fallback.clone(),
            suite: self.suite,
            resumption_accepted,
            session_ticket_issued,
            client_hello_len: transcript.map(|t| t.client_raw().len()).unwrap_or(0),
            server_hello_len: transcript.map(|t| t.server_raw().len()).unwrap_or(0),
            client_finished_len: transcript
                .map(|t| t.client_finished_raw().len())
                .unwrap_or(0),
            early_data_len,
            max_early_data,
        };

        collector.record(&event);
    }

    async fn perform_crypto_handshake(
        &self,
        peer: SocketAddr,
        inbox: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<CryptoHandshakeArtifacts, ServerError> {
        match self.security_profile {
            SecurityProfile::Turbo => {
                self.perform_crypto_handshake_with(MlKem512, peer, inbox)
                    .await
            }
            SecurityProfile::Balanced => {
                self.perform_crypto_handshake_with(MlKem768, peer, inbox)
                    .await
            }
            SecurityProfile::Fortress => {
                self.perform_crypto_handshake_with(MlKem1024, peer, inbox)
                    .await
            }
        }
    }

    async fn perform_crypto_handshake_with<P: KemProvider + Copy>(
        &self,
        kem: P,
        peer: SocketAddr,
        inbox: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<CryptoHandshakeArtifacts, ServerError> {
        let mut framing = FrameSequencer::new(1, 1);
        let mut client_assembler = ChunkAssembler::new(HANDSHAKE_MESSAGE_MAX);

        let client_hello_bytes = loop {
            let client_buf = recv_datagram_with_timeout(inbox, self.handshake_timeout).await?;
            let client_slice = framing.decode(&client_buf).map_err(ServerError::Framing)?;
            if let Some(message) = client_assembler
                .push_slice(client_slice)
                .map_err(ServerError::Framing)?
            {
                break message;
            }
        };
        let client_payload: ClientHelloPayload =
            cbor_from_slice(&client_hello_bytes).map_err(ServerError::Decode)?;

        let mut handshake = create_server_handshake(
            kem,
            self.suite,
            Arc::clone(&self.ticket_manager),
            self.max_early_data,
            self.static_keypair.clone(),
            Arc::clone(&self.replay_guard),
            &self.application_context,
        );
        let peer_label = peer.to_string();
        let result = handshake
            .respond(
                &client_payload,
                &client_hello_bytes,
                Some(peer_label.as_bytes()),
            )
            .map_err(ServerError::Hybrid)?;
        let server_payload = result.payload.clone();
        let encoded = cbor_to_vec(&server_payload).map_err(ServerError::Encode)?;
        let server_frames =
            encode_chunked_payload(&mut framing, &encoded).map_err(ServerError::Framing)?;
        for frame in server_frames {
            self.socket.send_to(&frame, peer).await?;
        }

        let mut fin_assembler = ChunkAssembler::new(HANDSHAKE_MESSAGE_MAX);
        let client_finished_bytes = loop {
            let fin_buf = recv_datagram_with_timeout(inbox, self.handshake_timeout).await?;
            let fin_slice = framing.decode(&fin_buf).map_err(ServerError::Framing)?;
            if let Some(message) = fin_assembler
                .push_slice(fin_slice)
                .map_err(ServerError::Framing)?
            {
                break message;
            }
        };
        let client_finished: ClientFinishedPayload =
            cbor_from_slice(&client_finished_bytes).map_err(ServerError::Decode)?;

        let schedule = handshake
            .finalize(
                &client_payload,
                &server_payload,
                &client_finished,
                &client_finished_bytes,
            )
            .map_err(ServerError::Hybrid)?;
        debug_assert_eq!(
            schedule.handshake_secret,
            result.key_schedule.handshake_secret
        );
        let keys = schedule.session_keys(Perspective::Server);
        let crypto = SessionCrypto::new(keys).map_err(ServerError::Crypto)?;
        let transcript =
            HandshakeTranscript::new(client_hello_bytes, encoded.clone(), client_finished_bytes);
        let resumption_accepted = result.resumption_accepted;
        let early_data = result.early_data.clone();
        Ok(CryptoHandshakeArtifacts {
            crypto,
            transcript,
            session_ticket: server_payload.session_ticket.clone(),
            resumption_accepted,
            early_data,
            max_early_data: server_payload.max_early_data,
            framing,
        })
    }
}

fn hash_peer(salt: &[u8; 32], ip: IpAddr) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    match ip {
        IpAddr::V4(v4) => hasher.update(v4.octets()),
        IpAddr::V6(v6) => hasher.update(v6.octets()),
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// An accepted session representing a negotiated handshake with a specific peer.
pub struct ServerSession {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    handshake: HandshakeResponse,
    crypto: Option<Arc<Mutex<SessionCrypto>>>,
    transcript: Option<HandshakeTranscript>,
    session_ticket: Option<Vec<u8>>,
    resumption_accepted: bool,
    max_early_data: u32,
    early_data: Mutex<Option<Vec<u8>>>,
    router: DatagramRouterHandle,
    inbox: Option<Mutex<mpsc::Receiver<Vec<u8>>>>,
    framing: Option<Arc<Mutex<FrameSequencer>>>,
    assembler: Option<Arc<Mutex<ChunkAssembler>>>,
}

impl ServerSession {
    fn from_combined(
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        combined: CombinedHandshake,
        inbox: Option<Mutex<mpsc::Receiver<Vec<u8>>>>,
        router: DatagramRouterHandle,
    ) -> Self {
        let CombinedHandshake {
            response,
            crypto,
            transcript,
            session_ticket,
            resumption_accepted,
            early_data,
            max_early_data,
            framing,
        } = combined;

        let framing = framing.map(|seq| Arc::new(Mutex::new(seq)));
        let assembler = framing
            .as_ref()
            .map(|_| Arc::new(Mutex::new(ChunkAssembler::new(APPLICATION_MESSAGE_MAX))));

        Self {
            socket,
            peer,
            handshake: response,
            crypto,
            transcript,
            session_ticket,
            resumption_accepted,
            max_early_data,
            early_data: Mutex::new(early_data),
            router,
            inbox,
            framing,
            assembler,
        }
    }

    /// Peek at the negotiated handshake response.
    pub fn handshake(&self) -> &HandshakeResponse {
        &self.handshake
    }

    /// Peer socket address for logging.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Returns true when the session has negotiated PQ crypto keys for application data.
    pub fn is_application_ready(&self) -> bool {
        self.crypto.is_some() && self.inbox.is_some() && self.framing.is_some()
    }

    /// Returns the raw PQ handshake transcript if the session negotiated PQ crypto.
    pub fn handshake_transcript(&self) -> Option<&HandshakeTranscript> {
        self.transcript.as_ref()
    }

    /// Returns true if the server accepted 0-RTT resumption for this session.
    pub fn resumption_accepted(&self) -> bool {
        self.resumption_accepted
    }

    /// Borrow the issued session ticket, if any.
    pub fn session_ticket(&self) -> Option<&[u8]> {
        self.session_ticket.as_deref()
    }

    /// Maximum early data advertised to the client during the handshake.
    pub fn max_early_data(&self) -> u32 {
        self.max_early_data
    }

    /// Receive a single datagram from the connected peer and surface it as a request.
    pub async fn recv_request(&self) -> Result<Request, ServerError> {
        if let Some(early) = {
            let mut guard = self.early_data.lock().await;
            guard.take()
        } {
            return Ok(Request {
                peer: self.peer,
                payload: early,
                handshake: self.handshake.clone(),
                early: true,
            });
        }

        let inbox = self.inbox.as_ref().ok_or(ServerError::MissingCrypto)?;
        let mut inbox = inbox.lock().await;
        let framing = self.framing.as_ref().ok_or(ServerError::MissingFraming)?;
        let assembler = self.assembler.as_ref().ok_or(ServerError::MissingFraming)?;

        loop {
            let buf = match inbox.recv().await {
                Some(buf) => buf,
                None => return Err(ServerError::PeerClosed),
            };

            let slice = {
                let mut framing = framing.lock().await;
                framing.decode(&buf).map_err(ServerError::Framing)?
            };

            if let Some(ciphertext) = {
                let mut assembler = assembler.lock().await;
                assembler.push_slice(slice).map_err(ServerError::Framing)?
            } {
                let plaintext = match &self.crypto {
                    Some(crypto) => {
                        let mut guard = crypto.lock().await;
                        guard.open(&ciphertext).map_err(ServerError::Crypto)?
                    }
                    None => return Err(ServerError::MissingCrypto),
                };

                return Ok(Request {
                    peer: self.peer,
                    payload: plaintext,
                    handshake: self.handshake.clone(),
                    early: false,
                });
            }
        }
    }

    /// Send a response payload back to the peer.
    pub async fn send_response(&self, response: Response) -> Result<(), ServerError> {
        match response.into_body() {
            ResponseBody::Complete(payload) => self.send_payload(&payload).await,
            ResponseBody::Chunked(chunked) => {
                let ChunkedBody { head, mut chunks } = chunked;
                self.send_payload(&head).await?;

                while let Some(chunk) = chunks.next().await {
                    let bytes = match chunk {
                        Ok(bytes) => bytes,
                        Err(err) => return Err(ServerError::ResponseStream(err)),
                    };

                    if !bytes.is_empty() {
                        self.send_payload(bytes.as_ref()).await?;
                    }
                }

                Ok(())
            }
        }
    }

    async fn send_payload(&self, payload: &[u8]) -> Result<(), ServerError> {
        if payload.is_empty() {
            return Ok(());
        }

        let ciphertext = match &self.crypto {
            Some(crypto) => {
                let mut guard = crypto.lock().await;
                let ct = guard.seal(payload).map_err(ServerError::Crypto)?;
                tracing::debug!(
                    target = "velocity::server::session",
                    peer = %self.peer,
                    ciphertext_len = ct.len(),
                    plaintext_len = payload.len(),
                    "sending encrypted response chunk"
                );
                ct
            }
            None => return Err(ServerError::MissingCrypto),
        };
        let frames = {
            let framing = self.framing.as_ref().ok_or(ServerError::MissingFraming)?;
            let mut framing = framing.lock().await;
            encode_chunked_payload_with_limit(&mut framing, &ciphertext, APPLICATION_MESSAGE_MAX)
                .map_err(ServerError::Framing)?
        };

        for frame in frames {
            tracing::debug!(
                target = "velocity::server::session",
                peer = %self.peer,
                framed_len = frame.len(),
                "sending framed ciphertext"
            );
            self.socket.send_to(&frame, self.peer).await?;
        }
        Ok(())
    }
}

impl Drop for ServerSession {
    fn drop(&mut self) {
        self.router.drop_peer(self.peer);
    }
}

/// Represents a raw application request carried over PQ-QUIC.
#[derive(Debug, Clone)]
pub struct Request {
    peer: SocketAddr,
    payload: Vec<u8>,
    handshake: HandshakeResponse,
    early: bool,
}

impl Request {
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn handshake(&self) -> &HandshakeResponse {
        &self.handshake
    }

    /// Returns true if the request body arrived as 0-RTT early data.
    pub fn is_early_data(&self) -> bool {
        self.early
    }

    /// Interpret the payload as an HTTP/1.1 request and extract the method, path, and version.
    pub fn http_request_line(&self) -> Option<HttpRequestLine<'_>> {
        let text = std::str::from_utf8(&self.payload).ok()?;
        let mut lines = text.lines();
        let first = lines.next()?.trim();
        let mut parts = first.split_whitespace();
        let method = parts.next()?;
        let target = parts.next()?;
        let version = parts.next()?;
        Some(HttpRequestLine {
            method,
            target,
            version,
        })
    }
}

/// Parsed HTTP/1.1 request line fields.
#[derive(Debug, Clone, Copy)]
pub struct HttpRequestLine<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub version: &'a str,
}

/// Builder for application responses.
pub struct Response {
    body: ResponseBody,
}

enum ResponseBody {
    Complete(Vec<u8>),
    Chunked(ChunkedBody),
}

struct ChunkedBody {
    head: Vec<u8>,
    chunks: BoxStream<'static, Result<Bytes, ResponseStreamError>>,
}

pub struct ResponseStreamError {
    message: Cow<'static, str>,
    source: Option<Box<dyn StdError + Send + Sync + 'static>>,
}

impl ResponseStreamError {
    pub fn message(message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    pub fn with_source(
        message: impl Into<Cow<'static, str>>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    pub fn from_error(source: impl StdError + Send + Sync + 'static) -> Self {
        let message = source.to_string();
        Self {
            message: Cow::Owned(message),
            source: Some(Box::new(source)),
        }
    }
}

impl std::fmt::Display for ResponseStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl StdError for ResponseStreamError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|inner| inner.as_ref() as &(dyn StdError + 'static))
    }
}

impl fmt::Debug for ResponseStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseStreamError")
            .field("message", &self.message)
            .field("has_source", &self.source.is_some())
            .finish()
    }
}

impl fmt::Debug for ChunkedBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkedBody")
            .field("head_len", &self.head.len())
            .finish()
    }
}

impl fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseBody::Complete(payload) => f
                .debug_struct("ResponseBody::Complete")
                .field("len", &payload.len())
                .finish(),
            ResponseBody::Chunked(body) => {
                f.debug_tuple("ResponseBody::Chunked").field(body).finish()
            }
        }
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("body", &self.body)
            .finish()
    }
}

impl Response {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            body: ResponseBody::Complete(bytes.into()),
        }
    }

    pub fn text(body: impl AsRef<str>) -> Self {
        let body = body.as_ref();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        Self::from_bytes(response)
    }

    pub fn json(body: &serde_json::Value) -> Self {
        let payload = body.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            payload.len(),
            payload
        );
        Self::from_bytes(response)
    }

    pub fn html(body: impl AsRef<str>) -> Self {
        let body = body.as_ref();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        Self::from_bytes(response)
    }

    pub fn chunked(
        head: Vec<u8>,
        chunks: BoxStream<'static, Result<Bytes, ResponseStreamError>>,
    ) -> Self {
        Self {
            body: ResponseBody::Chunked(ChunkedBody { head, chunks }),
        }
    }

    fn into_body(self) -> ResponseBody {
        self.body
    }
}

#[async_trait]
pub trait RequestHandler: Send + Sync + 'static {
    async fn handle(&self, request: Request) -> Response;
}

#[async_trait]
impl<F, Fut> RequestHandler for F
where
    F: Send + Sync + 'static + Fn(Request) -> Fut,
    Fut: Future<Output = Response> + Send,
{
    async fn handle(&self, request: Request) -> Response {
        (self)(request).await
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ServerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("handshake error: {0}")]
    Handshake(#[from] pqq_core::HandshakeError),
    #[error("server is shutting down")]
    Shutdown,
    #[error("peer closed datagram stream")]
    PeerClosed,
    #[error("failed to decode handshake payload: {0}")]
    Decode(CborError),
    #[error("failed to encode handshake payload: {0}")]
    Encode(CborError),
    #[error("hybrid handshake error: {0}")]
    Hybrid(HybridHandshakeError),
    #[error("session crypto error: {0}")]
    Crypto(#[from] pqq_tls::CryptoError),
    #[error("session missing negotiated crypto keys")]
    MissingCrypto,
    #[error("frame sequencing error: {0}")]
    Framing(FrameError),
    #[error("session missing framing state")]
    MissingFraming,
    #[error("response stream failure: {0}")]
    ResponseStream(#[source] ResponseStreamError),
}

/// Captures the CBOR-encoded payloads exchanged during the hybrid PQ handshake.
#[derive(Debug, Clone)]
pub struct HandshakeTranscript {
    client_hello: Vec<u8>,
    server_hello: Vec<u8>,
    client_finished: Vec<u8>,
}

impl HandshakeTranscript {
    fn new(client_hello: Vec<u8>, server_hello: Vec<u8>, client_finished: Vec<u8>) -> Self {
        Self {
            client_hello,
            server_hello,
            client_finished,
        }
    }

    /// Returns the client handshake payload encoded as base64 for logging.
    pub fn client_base64(&self) -> String {
        BASE64_STANDARD.encode(&self.client_hello)
    }

    /// Returns the server handshake payload encoded as base64 for logging.
    pub fn server_base64(&self) -> String {
        BASE64_STANDARD.encode(&self.server_hello)
    }

    /// Borrow the raw client hello bytes.
    pub fn client_raw(&self) -> &[u8] {
        &self.client_hello
    }

    /// Borrow the raw server hello bytes.
    pub fn server_raw(&self) -> &[u8] {
        &self.server_hello
    }

    /// Returns the client finished payload encoded as base64.
    pub fn client_finished_base64(&self) -> String {
        BASE64_STANDARD.encode(&self.client_finished)
    }

    /// Borrow the raw client finished bytes.
    pub fn client_finished_raw(&self) -> &[u8] {
        &self.client_finished
    }
}
