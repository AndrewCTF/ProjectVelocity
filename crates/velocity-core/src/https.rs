use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{http::StatusCode, Response};
use hyper_util::rt::TokioIo;
use pqq_core::{cbor_from_slice, cbor_to_vec, InMemoryReplayGuard, ReplayGuard};
use pqq_tls::{
    ClientFinishedPayload, ClientHelloPayload, CryptoError, HybridHandshakeError, HybridSuite,
    KemProvider, MlKem1024, MlKem512, MlKem768, Perspective, SecurityProfile, ServerHandshake,
    SessionCrypto, SessionTicketManager, StaticKemKeyPair,
};
use rand::{rngs::OsRng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use velocity_edge::{EdgeError, EdgeRequest, EdgeResponse, EdgeResult, ServeRouterHandle};

const MAX_HANDSHAKE_LEN: usize = 32 * 1024;
const HELLO_BODY: &[u8] = b"Hello from Velocity HTTPS preview\n";

/// Configuration for the built-in HTTPS listener.
#[derive(Debug, Clone)]
pub struct HttpsConfig {
    pub bind_addr: SocketAddr,
    pub security_profile: SecurityProfile,
    pub ticket_lifetime: Duration,
}

impl Default for HttpsConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 8443)),
            security_profile: SecurityProfile::Balanced,
            ticket_lifetime: Duration::from_secs(6 * 60 * 60),
        }
    }
}

/// Handle returned by [`HttpsServer::spawn_hello`] that allows triggering shutdown.
#[derive(Debug)]
pub struct HttpsHandle {
    shutdown: watch::Sender<bool>,
    join: JoinHandle<Result<(), HttpsError>>,
}

impl HttpsHandle {
    /// Signal the HTTPS task to terminate and wait for completion.
    pub async fn shutdown(self) -> Result<(), HttpsError> {
        let _ = self.shutdown.send(true);
        match self.join.await {
            Ok(res) => res,
            Err(err) => Err(HttpsError::Join(err)),
        }
    }
}

/// Top-level HTTPS listener that performs FLASH-KEM handshake before upgrading to HTTP.
#[derive(Debug)]
pub struct HttpsServer {
    listener: TcpListener,
    state: Arc<HttpsState>,
}

impl HttpsServer {
    /// Bind a TCP listener and prepare shared handshake state.
    pub async fn bind(config: HttpsConfig) -> Result<Self, HttpsError> {
        Self::bind_with_router(config, None).await
    }

    /// Bind a TCP listener and prepare shared handshake state with shared router.
    pub async fn bind_with_router(
        config: HttpsConfig,
        router: Option<ServeRouterHandle>,
    ) -> Result<Self, HttpsError> {
        let listener = TcpListener::bind(config.bind_addr).await?;
        let state = Arc::new(HttpsState::new(
            config.security_profile,
            config.ticket_lifetime,
            router,
        )?);
        Ok(Self { listener, state })
    }

    /// Return the socket address the listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, HttpsError> {
        Ok(self.listener.local_addr()?)
    }

    /// Expose the static ML-KEM public key advertised by this listener.
    pub fn kem_public_key(&self) -> &[u8] {
        &self.state.static_keypair.public
    }

    /// Expose the negotiated hybrid suite implied by the configured security profile.
    pub fn suite(&self) -> HybridSuite {
        self.state.suite
    }

    /// Expose the configured security profile.
    pub fn profile(&self) -> SecurityProfile {
        self.state.security_profile
    }

    /// Spawn an accept loop that responds with a static "Hello" response for every connection.
    pub fn spawn_hello(self) -> HttpsHandle {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let state = Arc::clone(&self.state);
        let listener = self.listener;

        let join: JoinHandle<Result<(), HttpsError>> = tokio::spawn(async move {
            loop {
                let accept_fut = listener.accept();
                tokio::pin!(accept_fut);

                let shutdown_fut = shutdown_rx.changed();
                tokio::pin!(shutdown_fut);

                tokio::select! {
                    biased;
                    res = shutdown_fut => {
                        match res {
                            Ok(_) => {
                                debug!("https listener received shutdown signal");
                                break;
                            }
                            Err(_) => {
                                debug!("https shutdown channel closed; terminating listener");
                                break;
                            }
                        }
                    }
                    res = accept_fut => {
                        match res {
                            Ok((stream, peer)) => {
                                let state = Arc::clone(&state);
                                tokio::spawn(async move {
                                    if let Err(err) = handle_connection(stream, state).await {
                                        warn!(target: "velocity::https", %peer, error = %err, "https session ended with error");
                                    }
                                });
                            }
                            Err(err) => {
                                warn!(target: "velocity::https", error = %err, "tcp accept failed");
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                        }
                    }
                }
            }
            Ok(())
        });

        HttpsHandle {
            shutdown: shutdown_tx,
            join,
        }
    }
}

struct HttpsState {
    suite: HybridSuite,
    security_profile: SecurityProfile,
    ticket_manager: Arc<SessionTicketManager>,
    replay_guard: Arc<dyn ReplayGuard>,
    static_keypair: StaticKemKeyPair,
    max_early_data: u32,
    router: Option<ServeRouterHandle>,
}

impl fmt::Debug for HttpsState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsState")
            .field("suite", &self.suite)
            .field("security_profile", &self.security_profile)
            .field("max_early_data", &self.max_early_data)
            .field("has_router", &self.router.is_some())
            .finish()
    }
}

impl HttpsState {
    fn new(
        profile: SecurityProfile,
        ticket_lifetime: Duration,
        router: Option<ServeRouterHandle>,
    ) -> Result<Self, HttpsError> {
        let suite = profile.suite();
        let (public, secret) = match profile {
            SecurityProfile::Turbo => MlKem512.generate_keypair()?,
            SecurityProfile::Balanced => MlKem768.generate_keypair()?,
            SecurityProfile::Fortress => MlKem1024.generate_keypair()?,
        };
        let static_keypair = StaticKemKeyPair::new(public, secret);

        let mut master_key = [0u8; 32];
        OsRng.fill_bytes(&mut master_key);
        let ticket_manager = Arc::new(SessionTicketManager::new(master_key, ticket_lifetime));
        let replay_guard: Arc<dyn ReplayGuard> = Arc::new(InMemoryReplayGuard::default());
        let max_early_data = profile.max_early_data();

        Ok(Self {
            suite,
            security_profile: profile,
            ticket_manager,
            replay_guard,
            static_keypair,
            max_early_data,
            router,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HttpsError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CBOR decode error: {0}")]
    Decode(#[from] pqq_core::CborError),
    #[error("handshake failure: {0}")]
    Handshake(#[from] HybridHandshakeError),
    #[error("crypto failure: {0}")]
    Crypto(#[from] CryptoError),
    #[error("handshake message exceeded limit ({0} bytes)")]
    HandshakeTooLarge(usize),
    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
}

async fn handle_connection(stream: TcpStream, state: Arc<HttpsState>) -> Result<(), HttpsError> {
    let peer = stream.peer_addr().ok();
    debug!(target: "velocity::https", ?peer, "accepted https connection");

    match state.security_profile {
        SecurityProfile::Turbo => {
            handshake_and_serve(
                stream,
                Arc::clone(&state),
                MlKem512,
                state.router.clone(),
                peer,
            )
            .await
        }
        SecurityProfile::Balanced => {
            handshake_and_serve(
                stream,
                Arc::clone(&state),
                MlKem768,
                state.router.clone(),
                peer,
            )
            .await
        }
        SecurityProfile::Fortress => {
            handshake_and_serve(
                stream,
                Arc::clone(&state),
                MlKem1024,
                state.router.clone(),
                peer,
            )
            .await
        }
    }
}

async fn handshake_and_serve<P: KemProvider + Copy + Send + Sync + 'static>(
    mut stream: TcpStream,
    state: Arc<HttpsState>,
    kem: P,
    router: Option<ServeRouterHandle>,
    peer: Option<SocketAddr>,
) -> Result<(), HttpsError> {
    let handshake = perform_handshake(&mut stream, &state, kem).await?;
    debug!(
        target: "velocity::https",
        resumption = handshake.resumption_accepted,
        early_data = handshake.early_data_len,
        "https handshake completed"
    );
    if let Some(router) = router {
        let peer = peer.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        serve_with_router(stream, router, peer).await
    } else {
        serve_plain_http(stream).await
    }
}

struct HandshakeSummary {
    #[allow(dead_code)]
    crypto: SessionCrypto,
    resumption_accepted: bool,
    early_data_len: Option<usize>,
}

async fn perform_handshake<P: KemProvider + Copy>(
    stream: &mut TcpStream,
    state: &HttpsState,
    kem: P,
) -> Result<HandshakeSummary, HttpsError> {
    let client_bytes = read_framed_message(stream).await?;
    let client_payload: ClientHelloPayload = cbor_from_slice(&client_bytes)?;

    let mut handshake = ServerHandshake::new(
        kem,
        state.suite,
        Arc::clone(&state.ticket_manager),
        state.static_keypair.clone(),
        Arc::clone(&state.replay_guard),
    )
    .with_max_early_data(state.max_early_data);

    let response = handshake.respond(&client_payload, &client_bytes)?;
    let server_bytes = cbor_to_vec(&response.payload)?;
    write_framed_message(stream, &server_bytes).await?;

    let finished_bytes = read_framed_message(stream).await?;
    let client_finished: ClientFinishedPayload = cbor_from_slice(&finished_bytes)?;
    let schedule = handshake.finalize(
        &client_payload,
        &response.payload,
        &client_finished,
        &finished_bytes,
    )?;

    let keys = schedule.session_keys(Perspective::Server);
    let crypto = SessionCrypto::new(keys)?;
    let early_data_len = response.early_data.as_ref().map(|data| data.len());

    Ok(HandshakeSummary {
        crypto,
        resumption_accepted: response.resumption_accepted,
        early_data_len,
    })
}

async fn read_framed_message(stream: &mut TcpStream) -> Result<Vec<u8>, HttpsError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_HANDSHAKE_LEN {
        return Err(HttpsError::HandshakeTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_framed_message(stream: &mut TcpStream, payload: &[u8]) -> Result<(), HttpsError> {
    let len = payload.len();
    if len > MAX_HANDSHAKE_LEN {
        return Err(HttpsError::HandshakeTooLarge(len));
    }
    stream.write_all(&(len as u32).to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn serve_plain_http(stream: TcpStream) -> Result<(), HttpsError> {
    let service = service_fn(|_req: hyper::Request<Incoming>| async move {
        let body: Full<Bytes> = Full::new(Bytes::from_static(HELLO_BODY));
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; charset=utf-8")
            .header("connection", "close")
            .body(body)
            .expect("static response");
        Ok::<_, std::convert::Infallible>(response)
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await?;
    Ok(())
}

async fn serve_with_router(
    stream: TcpStream,
    router: ServeRouterHandle,
    peer: SocketAddr,
) -> Result<(), HttpsError> {
    let service = service_fn(move |req: hyper::Request<Incoming>| {
        let router = router.clone();
        async move {
            let edge_request = convert_hyper_request(req, peer).await;
            let response = match edge_request {
                Ok(edge_request) => {
                    let router_state = router.current();
                    if let Some(route) = router_state.resolve(
                        edge_request.host(),
                        edge_request.method(),
                        edge_request.path(),
                    ) {
                        if let Some(rebased) = edge_request.strip_prefix(&route.prefix) {
                            match route.handler.handle(rebased).await {
                                Ok(edge_response) => edge_response,
                                Err(err) => EdgeResponse::from(err),
                            }
                        } else {
                            EdgeResponse::from(EdgeError::NotFound {
                                method: edge_request.method().to_string(),
                                path: edge_request.path().to_string(),
                            })
                        }
                    } else {
                        EdgeResponse::from(EdgeError::NotFound {
                            method: edge_request.method().to_string(),
                            path: edge_request.path().to_string(),
                        })
                    }
                }
                Err(err) => EdgeResponse::from(err),
            };
            Ok::<_, hyper::Error>(convert_edge_to_hyper(response))
        }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await?;
    Ok(())
}

async fn convert_hyper_request(
    request: hyper::Request<Incoming>,
    peer: SocketAddr,
) -> EdgeResult<EdgeRequest> {
    let (parts, body) = request.into_parts();
    let bytes = body
        .collect()
        .await
        .map_err(|err| EdgeError::Internal(format!("failed to read request body: {err}")))?
        .to_bytes();
    let target = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| parts.uri.path().to_string());
    EdgeRequest::from_http_parts(
        parts.method,
        target,
        parts.headers,
        Bytes::from(bytes),
        peer,
    )
}

fn convert_edge_to_hyper(response: EdgeResponse) -> Response<Full<Bytes>> {
    let (status, headers, body) = response.into_parts();
    let mut hyper_response = Response::builder()
        .status(status)
        .body(Full::new(body))
        .expect("failed to build https response");
    *hyper_response.headers_mut() = headers;
    hyper_response
}
