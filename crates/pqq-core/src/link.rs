use crate::frame::{encode_chunked_payload, FrameSequencer};
use crate::transport::{
    encode_handshake_response, HandshakeDriver, HandshakeError, HandshakeResponse,
};

#[cfg(test)]
use crate::frame::{ChunkAssembler, FRAME_HEADER_LEN, FRAME_MAX_PAYLOAD, HANDSHAKE_MESSAGE_MAX};
#[cfg(test)]
use crate::transport::decode_handshake_response;
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("link channel closed")]
    Closed,
    #[error("frame of size {0} exceeds buffer capacity")]
    FrameTooLarge(usize),
}

#[async_trait]
pub trait LinkEndpoint: Send + Sync {
    async fn recv_frame(&self, buffer: &mut [u8]) -> Result<usize, LinkError>;
    async fn send_frame(&self, frame: &[u8]) -> Result<(), LinkError>;
}

#[derive(Clone)]
pub struct ChannelEndpoint {
    tx: mpsc::Sender<Bytes>,
    rx: Arc<Mutex<mpsc::Receiver<Bytes>>>,
}

impl ChannelEndpoint {
    fn new(tx: mpsc::Sender<Bytes>, rx: mpsc::Receiver<Bytes>) -> Self {
        Self {
            tx,
            rx: Arc::new(Mutex::new(rx)),
        }
    }
}

#[async_trait]
impl LinkEndpoint for ChannelEndpoint {
    async fn recv_frame(&self, buffer: &mut [u8]) -> Result<usize, LinkError> {
        let mut rx = self.rx.lock().await;
        let frame = rx.recv().await.ok_or(LinkError::Closed)?;
        if frame.len() > buffer.len() {
            return Err(LinkError::FrameTooLarge(frame.len()));
        }
        buffer[..frame.len()].copy_from_slice(&frame);
        Ok(frame.len())
    }

    async fn send_frame(&self, frame: &[u8]) -> Result<(), LinkError> {
        self.tx
            .send(Bytes::copy_from_slice(frame))
            .await
            .map_err(|_| LinkError::Closed)
    }
}

pub type LinkHandle = Arc<dyn LinkEndpoint>;

pub fn memory_link_pair(capacity: usize) -> (LinkHandle, LinkHandle) {
    let (tx_ab, rx_ab) = mpsc::channel(capacity);
    let (tx_ba, rx_ba) = mpsc::channel(capacity);

    let endpoint_a: LinkHandle = Arc::new(ChannelEndpoint::new(tx_ab, rx_ba));
    let endpoint_b: LinkHandle = Arc::new(ChannelEndpoint::new(tx_ba, rx_ab));

    (endpoint_a, endpoint_b)
}

#[derive(Debug)]
pub struct LinkHandshakeDriver {
    inner: HandshakeDriver,
}

impl LinkHandshakeDriver {
    pub fn new(config: crate::transport::HandshakeConfig) -> Self {
        Self {
            inner: HandshakeDriver::new(config),
        }
    }

    pub async fn run_once(
        &self,
        endpoint: &dyn LinkEndpoint,
    ) -> Result<HandshakeResponse, LinkHandshakeError> {
        let mut buf = [0u8; 1400];
        let len = endpoint.recv_frame(&mut buf).await?;
        let response = self.process_frame(&buf[..len])?;

        let encoded = encode_handshake_response(&response)?;
        let mut sequencer = FrameSequencer::new(0, 0);
        let frames = encode_chunked_payload(&mut sequencer, &encoded)
            .map_err(|err| HandshakeError::Frame(err))?;
        for frame in frames {
            endpoint.send_frame(&frame).await?;
        }
        Ok(response)
    }

    fn process_frame(&self, frame: &[u8]) -> Result<HandshakeResponse, HandshakeError> {
        self.inner.process_initial_datagram(frame, None)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LinkHandshakeError {
    #[error("link error: {0}")]
    Link(#[from] LinkError),
    #[error("handshake error: {0}")]
    Handshake(#[from] HandshakeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{build_initial_packet, AlpnResolution, HandshakeConfig};

    #[tokio::test]
    async fn memory_link_negotiates_supported_alpn() {
        let config = HandshakeConfig::default().with_supported_alpns(["pqq/1"]);
        let driver = LinkHandshakeDriver::new(config);
        let (server, client) = memory_link_pair(4);

        let driver_ref = &driver;
        let server_future = {
            let server_handle = server.clone();
            async move { driver_ref.run_once(server_handle.as_ref()).await }
        };

        let client_future = {
            let client_handle = client.clone();
            async move {
                let initial = build_initial_packet(["pqq/1", "h3"]);
                client_handle.send_frame(&initial).await.unwrap();
                let mut buf = [0u8; FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD];
                let mut framing = FrameSequencer::new(0, 0);
                let mut assembler = ChunkAssembler::new(HANDSHAKE_MESSAGE_MAX);
                loop {
                    let len = client_handle.recv_frame(&mut buf).await.unwrap();
                    let slice = framing.decode(&buf[..len]).unwrap();
                    if let Some(message) = assembler.push_slice(slice).unwrap() {
                        break decode_handshake_response(&message).unwrap();
                    }
                }
            }
        };

        let (server_res, client_response) = tokio::join!(server_future, client_future);
        let server_response = server_res.expect("server handshake succeeded");

        assert!(matches!(
            server_response.resolution,
            AlpnResolution::Supported(ref proto) if proto == "pqq/1"
        ));
        assert!(matches!(
            client_response.resolution,
            AlpnResolution::Supported(ref proto) if proto == "pqq/1"
        ));
        assert!(server_response.fallback.is_none());
        assert!(client_response.fallback.is_none());
    }

    #[tokio::test]
    async fn memory_link_advises_fallback() {
        let config = HandshakeConfig::default()
            .with_supported_alpns(["pqq/1"])
            .with_fallback_endpoint("h3", "downgrade.velo", 8443);
        let driver = LinkHandshakeDriver::new(config);
        let (server, client) = memory_link_pair(4);

        let driver_ref = &driver;
        let server_future = {
            let server_handle = server.clone();
            async move { driver_ref.run_once(server_handle.as_ref()).await }
        };

        let client_future = {
            let client_handle = client.clone();
            async move {
                let initial = build_initial_packet(["spdy/3"]);
                client_handle.send_frame(&initial).await.unwrap();
                let mut buf = [0u8; FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD];
                let mut framing = FrameSequencer::new(0, 0);
                let mut assembler = ChunkAssembler::new(HANDSHAKE_MESSAGE_MAX);
                loop {
                    let len = client_handle.recv_frame(&mut buf).await.unwrap();
                    let slice = framing.decode(&buf[..len]).unwrap();
                    if let Some(message) = assembler.push_slice(slice).unwrap() {
                        break decode_handshake_response(&message).unwrap();
                    }
                }
            }
        };

        let (server_res, client_response) = tokio::join!(server_future, client_future);
        let server_response = server_res.expect("server handshake succeeded");

        assert!(matches!(
            server_response.resolution,
            AlpnResolution::Fallback(ref proto) if proto == "h3"
        ));
        let server_fallback = server_response
            .fallback
            .as_ref()
            .expect("server returned fallback directive");
        assert_eq!(server_fallback.host, "downgrade.velo");
        assert_eq!(server_fallback.port, 8443);

        assert!(matches!(
            client_response.resolution,
            AlpnResolution::Fallback(ref proto) if proto == "h3"
        ));
        let client_fallback = client_response
            .fallback
            .as_ref()
            .expect("client decoded fallback directive");
        assert_eq!(client_fallback.host, "downgrade.velo");
        assert_eq!(client_fallback.port, 8443);
    }
}
