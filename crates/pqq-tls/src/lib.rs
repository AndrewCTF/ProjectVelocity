//! Hybrid TLS stack for PQ-QUIC.
//!
//! The real implementation will embed ML-KEM key exchange, ML-DSA signatures,
//! and PQ-aware session tickets. For now we expose a small facade so dependent
//! crates can compile while development iterates.

mod crypto;
mod handshake;
mod profiles;
mod session;

#[cfg(all(not(feature = "mlkem"), not(test)))]
compile_error!("The `mlkem` feature must be enabled for secure builds; disable it only in test configurations.");

use pqq_core::{AlpnResolution, HandshakeDriver};

pub use handshake::{
    ClientFinishedPayload, ClientHandshake, ClientHelloOptions, ClientHelloPayload,
    HybridHandshakeError, HybridKeySchedule, HybridSuite, KemProvider, ResumptionParams,
    ServerHandshake, ServerHandshakeResult, ServerHelloPayload, StaticKemKeyPair,
};

#[cfg(feature = "mlkem")]
pub use handshake::{MlKem1024, MlKem512, MlKem768};

pub use profiles::SecurityProfile;

pub use crypto::{CryptoError, Perspective, SessionCrypto, SessionKeySet};
pub use session::{SessionTicket, SessionTicketError, SessionTicketManager};

/// TLS engine placeholder that delegates initial ALPN negotiation to `pqq-core`
/// and records decisions for higher layers.
#[derive(Debug, Default, Clone)]
pub struct HybridTlsEngine {
    negotiated: Option<AlpnResolution>,
}

impl HybridTlsEngine {
    pub fn new() -> Self {
        Self { negotiated: None }
    }

    pub fn set_negotiated(&mut self, resolution: AlpnResolution) {
        self.negotiated = Some(resolution);
    }

    pub fn negotiated(&self) -> Option<&AlpnResolution> {
        self.negotiated.as_ref()
    }

    /// Construct a driver instance bound to this TLS engine.
    pub fn handshake_driver(&self) -> HandshakeDriver {
        HandshakeDriver::new(Default::default())
    }
}
