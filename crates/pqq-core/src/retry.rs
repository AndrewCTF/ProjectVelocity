use hmac::{Hmac, Mac};
use sha3::Sha3_256;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// Errors returned when validating stateless retry tokens.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RetryTokenError {
    #[error("retry token was truncated")]
    Truncated,
    #[error("retry token version is unsupported")]
    Version,
    #[error("retry token integrity check failed")]
    Integrity,
    #[error("retry token not yet valid")]
    NotYetValid,
    #[error("retry token expired")]
    Expired,
    #[error("retry token bound to different peer address")]
    AddressMismatch,
    #[error("retry token bound to different client nonce")]
    NonceMismatch,
}

const TOKEN_VERSION: u8 = 1;
const TAG_LEN: usize = 32;
const NONCE_DIGEST_LEN: usize = 32;

/// Stateless retry token manager that binds tokens to client address and nonce.
#[derive(Clone, Debug)]
pub struct RetryTokenManager {
    secret: [u8; 32],
    lifetime: Duration,
}

type TokenMac = Hmac<Sha3_256>;

impl RetryTokenManager {
    pub fn new(secret: [u8; 32], lifetime: Duration) -> Self {
        Self { secret, lifetime }
    }

    pub fn issue(&self, peer: SocketAddr, client_nonce: &[u8]) -> Vec<u8> {
        let issued_at = SystemTime::now();
        let expires_at = issued_at + self.lifetime;
        let mut buf = Vec::with_capacity(1 + 8 + 8 + 1 + 16 + 2 + NONCE_DIGEST_LEN);
        buf.push(TOKEN_VERSION);
        buf.extend_from_slice(&to_unix(issued_at).to_be_bytes());
        buf.extend_from_slice(&to_unix(expires_at).to_be_bytes());
        match peer.ip() {
            IpAddr::V4(v4) => {
                buf.push(4);
                buf.extend_from_slice(&v4.octets());
                buf.extend_from_slice(&[0u8; 12]);
            }
            IpAddr::V6(v6) => {
                buf.push(6);
                buf.extend_from_slice(&v6.octets());
            }
        }
        buf.extend_from_slice(&peer.port().to_be_bytes());
        let nonce_digest = Sha3_256::digest(client_nonce);
        buf.extend_from_slice(&nonce_digest);
        let mut mac = TokenMac::new_from_slice(&self.secret).expect("mac init");
        mac.update(&buf);
        let tag = mac.finalize().into_bytes();
        let mut token = buf;
        token.extend_from_slice(&tag);
        token
    }

    pub fn validate(
        &self,
        token: &[u8],
        peer: SocketAddr,
        client_nonce: &[u8],
        now: SystemTime,
    ) -> Result<(), RetryTokenError> {
        if token.len() < minimum_token_len() {
            return Err(RetryTokenError::Truncated);
        }
        let (body, tag) = token.split_at(token.len() - TAG_LEN);
        let mut mac = TokenMac::new_from_slice(&self.secret).expect("mac init");
        mac.update(body);
        let expected = mac.finalize().into_bytes();
        if expected.ct_eq(tag).unwrap_u8() == 0 {
            return Err(RetryTokenError::Integrity);
        }
        let mut cursor = 0usize;
        let version = body[cursor];
        cursor += 1;
        if version != TOKEN_VERSION {
            return Err(RetryTokenError::Version);
        }
        let issued_at = from_unix(read_u64(body, &mut cursor)?);
        let expires_at = from_unix(read_u64(body, &mut cursor)?);
        if issued_at > now + self.lifetime {
            return Err(RetryTokenError::NotYetValid);
        }
        if expires_at < now {
            return Err(RetryTokenError::Expired);
        }
        let family = body[cursor];
        cursor += 1;
        let peer_ip = match family {
            4 => {
                let octets = read_bytes(body, &mut cursor, 4)?;
                IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
            }
            6 => {
                let octets = read_bytes(body, &mut cursor, 16)?;
                let mut array = [0u8; 16];
                array.copy_from_slice(octets);
                IpAddr::V6(Ipv6Addr::from(array))
            }
            _ => return Err(RetryTokenError::Version),
        };
        // Skip padding when IPv4 (12 zero bytes)
        if family == 4 {
            read_bytes(body, &mut cursor, 12)?;
        }
        let port_bytes = read_bytes(body, &mut cursor, 2)?;
        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
        if peer_ip != peer.ip() || port != peer.port() {
            return Err(RetryTokenError::AddressMismatch);
        }
        let received_nonce = read_bytes(body, &mut cursor, NONCE_DIGEST_LEN)?;
        let expected_nonce = Sha3_256::digest(client_nonce);
        if expected_nonce.ct_eq(received_nonce).unwrap_u8() == 0 {
            return Err(RetryTokenError::NonceMismatch);
        }
        Ok(())
    }
}

fn read_u64(body: &[u8], cursor: &mut usize) -> Result<u64, RetryTokenError> {
    let bytes = read_bytes(body, cursor, 8)?;
    let mut array = [0u8; 8];
    array.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(array))
}

fn read_bytes<'a>(body: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], RetryTokenError> {
    let end = *cursor + len;
    if end > body.len() {
        return Err(RetryTokenError::Truncated);
    }
    let slice = &body[*cursor..end];
    *cursor = end;
    Ok(slice)
}

fn to_unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .expect("time before unix epoch")
        .as_secs()
}

fn from_unix(ts: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(ts)
}

fn minimum_token_len() -> usize {
    1 + 8 + 8 + 1 + 16 + 2 + NONCE_DIGEST_LEN + TAG_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_retry_token_v4() {
        let manager = RetryTokenManager::new([9u8; 32], Duration::from_secs(60));
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 4433);
        let nonce = [0xAA; 32];
        let token = manager.issue(peer, &nonce);
        manager
            .validate(&token, peer, &nonce, SystemTime::now())
            .expect("validate");
    }

    #[test]
    fn rejects_modified_token() {
        let manager = RetryTokenManager::new([1u8; 32], Duration::from_secs(60));
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 8443);
        let nonce = [0x55; 32];
        let mut token = manager.issue(peer, &nonce);
        // Flip a bit in ciphertext portion
        let len = token.len();
        token[len - TAG_LEN - 1] ^= 0xFF;
        let err = manager
            .validate(&token, peer, &nonce, SystemTime::now())
            .unwrap_err();
        assert_eq!(err, RetryTokenError::Integrity);
    }

    #[test]
    fn rejects_wrong_address() {
        let manager = RetryTokenManager::new([4u8; 32], Duration::from_secs(60));
        let peer = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
        let nonce = [0x33; 32];
        let token = manager.issue(peer, &nonce);
        let other = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 444);
        let err = manager
            .validate(&token, other, &nonce, SystemTime::now())
            .unwrap_err();
        assert_eq!(err, RetryTokenError::AddressMismatch);
    }
}
