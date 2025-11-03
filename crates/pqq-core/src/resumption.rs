use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Mutex;
use std::time::SystemTime;

use sha3::{Digest, Sha3_256};

/// Errors that can occur while checking or registering replay tokens.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplayError {
    #[error("0-RTT token has already been consumed")]
    AlreadySeen,
    #[error("0-RTT token has expired")]
    Expired,
    #[error("replay token not yet valid")]
    NotYetValid,
    #[error("replay cache error: {0}")]
    Storage(String),
    #[error("replay token used from different peer than bound peer")]
    PeerMismatch,
}

/// Borrowed metadata describing a prospective 0-RTT attempt.
#[derive(Debug, Clone, Copy)]
pub struct ReplayToken<'a> {
    pub ticket_id: &'a [u8],
    pub client_nonce: &'a [u8],
    /// Optional opaque peer identifier (e.g. client IP or connection id) used for binding
    /// the first use of a ticket to a particular peer. If None, no binding is performed.
    pub peer_id: Option<&'a [u8]>,
    pub not_before: SystemTime,
    pub expires_at: SystemTime,
}

impl ReplayToken<'_> {
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(self.ticket_id);
        hasher.update(self.client_nonce);
        if let Some(peer) = self.peer_id {
            // include peer_id in digest to make the recorded "seen" value unique per peer
            hasher.update(peer);
        }
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

pub trait ReplayGuard: Send + Sync + fmt::Debug {
    fn check(&self, token: ReplayToken<'_>) -> Result<(), ReplayError>;
    fn register(&self, token: ReplayToken<'_>) -> Result<(), ReplayError>;
}

#[derive(Debug)]
struct TicketState {
    expires_at: SystemTime,
    seen: HashSet<[u8; 32]>,
    /// If set, the ticket is bound to this peer_id on first use and subsequent uses
    /// must come from the same peer to be accepted.
    bound_peer: Option<Vec<u8>>,
}

/// In-memory replay guard suitable for single-process deployments.
#[derive(Debug)]
pub struct InMemoryReplayGuard {
    inner: Mutex<HashMap<Vec<u8>, TicketState>>,
    capacity: usize,
    /// Maximum number of distinct seen digests to record per ticket. Prevents unbounded
    /// memory growth if many unique attempts use the same ticket_id.
    per_ticket_limit: usize,
    /// If true, bind the first registered use of a ticket to the provided peer_id (if any)
    /// and reject subsequent attempts from a different peer.
    bind_peer_on_first_use: bool,
}

impl Default for InMemoryReplayGuard {
    fn default() -> Self {
        Self::new_with_options(4096, 1024, true)
    }
}

impl InMemoryReplayGuard {
    pub fn new(capacity: usize) -> Self {
        Self::new_with_options(capacity, 1024, true)
    }

    /// Create a guard with explicit limits and binding option.
    pub fn new_with_options(capacity: usize, per_ticket_limit: usize, bind_peer_on_first_use: bool) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            capacity: capacity.max(16),
            per_ticket_limit: per_ticket_limit.max(1),
            bind_peer_on_first_use,
        }
    }

    /// Constructor retained for callers that intentionally disable peer binding.
    pub fn new_unbound(capacity: usize, per_ticket_limit: usize) -> Self {
        Self::new_with_options(capacity, per_ticket_limit, false)
    }

    fn purge_expired(states: &mut HashMap<Vec<u8>, TicketState>) {
        let now = SystemTime::now();
        states.retain(|_, state| state.expires_at > now);
    }

    fn enforce_capacity(states: &mut HashMap<Vec<u8>, TicketState>, capacity: usize) {
        if states.len() <= capacity {
            return;
        }
        let mut entries: Vec<(Vec<u8>, SystemTime)> = states
            .iter()
            .map(|(k, v)| (k.clone(), v.expires_at))
            .collect();
        entries.sort_by_key(|(_, expires)| *expires);
        while states.len() > capacity {
            if let Some((oldest, _)) = entries.first() {
                states.remove(oldest);
                entries.remove(0);
            } else {
                break;
            }
        }
    }
}

impl ReplayGuard for InMemoryReplayGuard {
    fn check(&self, token: ReplayToken<'_>) -> Result<(), ReplayError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|err| ReplayError::Storage(err.to_string()))?;
        Self::purge_expired(&mut guard);
        if token.not_before > SystemTime::now() {
            return Err(ReplayError::NotYetValid);
        }
        if token.expires_at <= SystemTime::now() {
            return Err(ReplayError::Expired);
        }
        if let Some(state) = guard.get(token.ticket_id) {
            // If the token was bound to a peer on first use, ensure the peer matches.
            if let (Some(bound), Some(peer)) = (state.bound_peer.as_ref(), token.peer_id) {
                if bound.as_slice() != peer {
                    return Err(ReplayError::PeerMismatch);
                }
            }
            if state.seen.contains(&token.digest()) {
                return Err(ReplayError::AlreadySeen);
            }
        }
        Ok(())
    }

    fn register(&self, token: ReplayToken<'_>) -> Result<(), ReplayError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|err| ReplayError::Storage(err.to_string()))?;
        Self::purge_expired(&mut guard);
        if token.expires_at <= SystemTime::now() {
            return Err(ReplayError::Expired);
        }
        if token.not_before > SystemTime::now() {
            return Err(ReplayError::NotYetValid);
        }
        let digest = token.digest();
        let state = guard
            .entry(token.ticket_id.to_vec())
            .or_insert_with(|| TicketState {
                expires_at: token.expires_at,
                seen: HashSet::new(),
                bound_peer: None,
            });
        if state.expires_at < token.expires_at {
            state.expires_at = token.expires_at;
        }
        // If configured, bind the ticket to the first peer that registers it.
        if self.bind_peer_on_first_use {
            if state.bound_peer.is_none() {
                if let Some(peer) = token.peer_id {
                    state.bound_peer = Some(peer.to_vec());
                }
            } else if let (Some(bound), Some(peer)) = (state.bound_peer.as_ref(), token.peer_id) {
                if bound.as_slice() != peer {
                    return Err(ReplayError::PeerMismatch);
                }
            }
        }
        if state.seen.len() >= self.per_ticket_limit {
            return Err(ReplayError::Storage("per-ticket seen limit exceeded".into()));
        }
        if !state.seen.insert(digest) {
            return Err(ReplayError::AlreadySeen);
        }
        Self::enforce_capacity(&mut guard, self.capacity);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn guard_allows_first_use_blocks_second() {
        let guard = InMemoryReplayGuard::default();
        let now = SystemTime::now();
        let token = ReplayToken {
            ticket_id: b"ticket-123",
            client_nonce: b"nonce-abc",
            peer_id: None,
            not_before: now,
            expires_at: now + Duration::from_secs(60),
        };
        guard.check(token).expect("first check");
        guard.register(token).expect("first register");
        assert_eq!(guard.check(token), Err(ReplayError::AlreadySeen));
        assert_eq!(guard.register(token), Err(ReplayError::AlreadySeen));
    }

    #[test]
    fn guard_purges_expired_entries() {
        let guard = InMemoryReplayGuard::default();
        let now = SystemTime::now();
        let expired = ReplayToken {
            ticket_id: b"ticket-expired",
            client_nonce: b"nonce-expired",
            peer_id: None,
            not_before: now - Duration::from_secs(120),
            expires_at: now - Duration::from_secs(60),
        };
        assert_eq!(guard.register(expired), Err(ReplayError::Expired));
    }

    #[test]
    fn guard_rejects_different_peer_when_bound() {
        let guard = InMemoryReplayGuard::new_with_options(1024, 16, true);
        let now = SystemTime::now();
        let token1 = ReplayToken {
            ticket_id: b"ticket-bind",
            client_nonce: b"nonce-1",
            peer_id: Some(b"peer-A"),
            not_before: now,
            expires_at: now + Duration::from_secs(60),
        };
        // first use binds to peer-A
        guard.check(token1).expect("first check");
        guard.register(token1).expect("first register");

        // same ticket+nonce from different peer should be rejected
        let token2 = ReplayToken {
            ticket_id: b"ticket-bind",
            client_nonce: b"nonce-1",
            peer_id: Some(b"peer-B"),
            not_before: now,
            expires_at: now + Duration::from_secs(60),
        };
        assert_eq!(guard.check(token2), Err(ReplayError::PeerMismatch));
        assert_eq!(guard.register(token2), Err(ReplayError::PeerMismatch));
    }
}
