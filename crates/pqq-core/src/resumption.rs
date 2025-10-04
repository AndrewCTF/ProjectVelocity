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
}

/// Borrowed metadata describing a prospective 0-RTT attempt.
#[derive(Debug, Clone, Copy)]
pub struct ReplayToken<'a> {
    pub ticket_id: &'a [u8],
    pub client_nonce: &'a [u8],
    pub not_before: SystemTime,
    pub expires_at: SystemTime,
}

impl ReplayToken<'_> {
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(self.ticket_id);
        hasher.update(self.client_nonce);
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
}

/// In-memory replay guard suitable for single-process deployments.
#[derive(Debug)]
pub struct InMemoryReplayGuard {
    inner: Mutex<HashMap<Vec<u8>, TicketState>>,
    capacity: usize,
}

impl Default for InMemoryReplayGuard {
    fn default() -> Self {
        Self::new(4096)
    }
}

impl InMemoryReplayGuard {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            capacity: capacity.max(16),
        }
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
            });
        if state.expires_at < token.expires_at {
            state.expires_at = token.expires_at;
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
            not_before: now - Duration::from_secs(120),
            expires_at: now - Duration::from_secs(60),
        };
        assert_eq!(guard.register(expired), Err(ReplayError::Expired));
    }
}
