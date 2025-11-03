use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::handshake::HybridSuite;

/// Minimum ticket payload size once encrypted (nonce + tag overhead).
pub const MIN_TICKET_LEN: usize = 12 + 16 + 32;

#[derive(Debug, Error)]
pub enum SessionTicketError {
    #[error("ticket lifetime exhausted")]
    Expired,
    #[error("ticket not yet valid")]
    NotYetValid,
    #[error("malformed session ticket payload")]
    Malformed,
    #[error("decryption error")]
    Decrypt,
    #[error("ticket not valid for current configuration")]
    ContextMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionTicketInner {
    ticket_id: [u8; 16],
    resumption_secret: [u8; 32],
    issued_at: u64,
    not_before: u64,
    expires_at: u64,
    max_early_data: u32,
    protocol_version: u16,
    cipher_suite: u16,
    kem_suite: u16,
    context_hash: [u8; 32],
}

/// Decrypted session ticket contents recognised by the stateless server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTicket {
    pub ticket_id: [u8; 16],
    pub resumption_secret: [u8; 32],
    pub issued_at: SystemTime,
    pub not_before: SystemTime,
    pub expires_at: SystemTime,
    pub max_early_data: u32,
    pub protocol_version: u16,
    pub cipher_suite: u16,
    pub kem_suite: u16,
    context_hash: [u8; 32],
}

impl SessionTicket {
    pub fn allows_0rtt(
        &self,
        now: SystemTime,
        requested: usize,
        suite: HybridSuite,
        context: &[u8],
    ) -> Result<(), SessionTicketError> {
        if now < self.not_before {
            return Err(SessionTicketError::NotYetValid);
        }
        if now > self.expires_at {
            return Err(SessionTicketError::Expired);
        }
        if requested as u32 > self.max_early_data {
            return Err(SessionTicketError::Expired);
        }
        if !self.matches_suite(suite) {
            return Err(SessionTicketError::ContextMismatch);
        }
        if !self.matches_context(context) {
            return Err(SessionTicketError::ContextMismatch);
        }
        Ok(())
    }

    pub fn matches_suite(&self, suite: HybridSuite) -> bool {
        self.protocol_version == suite.protocol_version
            && self.cipher_suite == suite.cipher_suite
            && self.kem_suite == suite.kem_suite
    }

    pub fn matches_context(&self, context: &[u8]) -> bool {
        self.context_hash == hash_context(context)
    }
}

/// Stateless session ticket manager using a server-wide AEAD key.
#[derive(Clone)]
pub struct SessionTicketManager {
    aead: ChaCha20Poly1305,
    lifetime: Duration,
    early_data_delay: Duration,
}

impl SessionTicketManager {
    pub fn new(master_key: [u8; 32], lifetime: Duration) -> Self {
        Self {
            aead: ChaCha20Poly1305::new(Key::from_slice(&master_key)),
            lifetime,
            early_data_delay: Duration::from_millis(5),
        }
    }

    pub fn with_early_data_delay(mut self, delay: Duration) -> Self {
        self.early_data_delay = delay;
        self
    }

    pub fn issue(
        &self,
        resumption_secret: [u8; 32],
        max_early_data: u32,
        suite: HybridSuite,
        context: &[u8],
    ) -> Vec<u8> {
        let issued_at = SystemTime::now();
        let not_before = issued_at + self.early_data_delay;
        let expires_at = issued_at + self.lifetime;
        let mut ticket_id = [0u8; 16];
        OsRng.fill_bytes(&mut ticket_id);
        let context_hash = hash_context(context);
        let inner = SessionTicketInner {
            ticket_id,
            resumption_secret,
            issued_at: to_unix(issued_at),
            not_before: to_unix(not_before),
            expires_at: to_unix(expires_at),
            max_early_data,
            protocol_version: suite.protocol_version,
            cipher_suite: suite.cipher_suite,
            kem_suite: suite.kem_suite,
            context_hash,
        };
        let serialized = bincode::serialize(&inner).expect("ticket serialize");
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        // Encrypt the serialized ticket with the ticket_id as AAD, and include the ticket_id
        // unencrypted after the nonce so the server can verify AAD during decrypt.
        let ciphertext = self
            .aead
            .encrypt(nonce, Payload { msg: serialized.as_ref(), aad: ticket_id.as_ref() })
            .expect("ticket encrypt");
        // wire format: nonce (12) || ticket_id (16) || ciphertext
        let mut payload = Vec::with_capacity(12 + 16 + ciphertext.len());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ticket_id);
        payload.extend_from_slice(&ciphertext);
        payload
    }

    pub fn decrypt(&self, ticket: &[u8]) -> Result<SessionTicket, SessionTicketError> {
        if ticket.len() < MIN_TICKET_LEN {
            return Err(SessionTicketError::Malformed);
        }
        // Expected wire: nonce (12) || ticket_id (16) || ciphertext
        let (nonce_bytes, rest) = ticket.split_at(12);
        if rest.len() < 16 {
            return Err(SessionTicketError::Malformed);
        }
        let (ticket_id_bytes, ciphertext) = rest.split_at(16);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .aead
            .decrypt(nonce, Payload { msg: ciphertext, aad: ticket_id_bytes })
            .map_err(|_| SessionTicketError::Decrypt)?;
        let inner: SessionTicketInner =
            bincode::deserialize(&plaintext).map_err(|_| SessionTicketError::Malformed)?;

        Ok(SessionTicket {
            ticket_id: inner.ticket_id,
            resumption_secret: inner.resumption_secret,
            issued_at: from_unix(inner.issued_at),
            not_before: from_unix(inner.not_before),
            expires_at: from_unix(inner.expires_at),
            max_early_data: inner.max_early_data,
            protocol_version: inner.protocol_version,
            cipher_suite: inner.cipher_suite,
            kem_suite: inner.kem_suite,
            context_hash: inner.context_hash,
        })
    }
}

impl fmt::Debug for SessionTicketManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionTicketManager")
            .field("lifetime", &self.lifetime)
            .field("early_data_delay", &self.early_data_delay)
            .finish()
    }
}

fn to_unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .expect("time before unix epoch")
        .as_secs()
}

fn from_unix(ts: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(ts)
}

fn hash_context(context: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(context);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_and_decrypts_ticket() {
        let suite = HybridSuite::BALANCED;
        let manager = SessionTicketManager::new([7u8; 32], Duration::from_secs(60));
        let ticket = manager.issue([9u8; 32], 1024, suite, b"ctx");
        let parsed = manager.decrypt(&ticket).expect("decrypt");
        assert_ne!(parsed.ticket_id, [0u8; 16]);
        assert_eq!(parsed.resumption_secret, [9u8; 32]);
        assert_eq!(parsed.max_early_data, 1024);
        assert!(parsed.matches_suite(suite));
        assert!(parsed.matches_context(b"ctx"));
    }
}
