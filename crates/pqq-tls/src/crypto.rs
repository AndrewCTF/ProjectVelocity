use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit as GcmKeyInit},
    Aes256Gcm,
};
use chacha20poly1305::Nonce as ChaChaNonce;
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey};
use std::{env, fmt};
use thiserror::Error;
use zeroize::Zeroize;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
cpufeatures::new!(aes_hw, "aes", "pclmulqdq");

/// Identifies which direction a session is operating from when deriving keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Perspective {
    Client,
    Server,
}

/// Symmetric keys and IVs for a single PQ-QUIC session.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct SessionKeySet {
    pub send_key: [u8; 32],
    pub send_iv: [u8; 12],
    pub recv_key: [u8; 32],
    pub recv_iv: [u8; 12],
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("nonce space exhausted for session")]
    NonceExhausted,
    #[error("failed to encrypt payload with session AEAD")]
    Encrypt,
    #[error("failed to decrypt payload with session AEAD")]
    Decrypt,
}

enum AeadImpl {
    ChaCha(ChaCha20Poly1305),
    Aes(Box<Aes256Gcm>),
}

impl AeadImpl {
    fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            AeadImpl::ChaCha(cipher) => cipher
                .encrypt(ChaChaNonce::from_slice(nonce), plaintext)
                .map_err(|_| CryptoError::Encrypt),
            AeadImpl::Aes(cipher) => cipher
                .encrypt(GenericArray::from_slice(nonce), plaintext)
                .map_err(|_| CryptoError::Encrypt),
        }
    }

    fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            AeadImpl::ChaCha(cipher) => cipher
                .decrypt(ChaChaNonce::from_slice(nonce), ciphertext)
                .map_err(|_| CryptoError::Decrypt),
            AeadImpl::Aes(cipher) => cipher
                .decrypt(GenericArray::from_slice(nonce), ciphertext)
                .map_err(|_| CryptoError::Decrypt),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            AeadImpl::ChaCha(_) => "chacha20-poly1305",
            AeadImpl::Aes(_) => "aes-256-gcm",
        }
    }
}

/// Stateful AEAD context wrapping the preferred cipher for a session.
pub struct SessionCrypto {
    send_aead: AeadImpl,
    recv_aead: AeadImpl,
    send_iv: [u8; 12],
    recv_iv: [u8; 12],
    send_counter: u64,
    recv_counter: u64,
}

impl fmt::Debug for SessionCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionCrypto")
            .field("send_counter", &self.send_counter)
            .field("recv_counter", &self.recv_counter)
            .field("send_aead", &self.send_aead.label())
            .field("recv_aead", &self.recv_aead.label())
            .finish()
    }
}

impl SessionCrypto {
    pub fn new(mut keys: SessionKeySet) -> Result<Self, CryptoError> {
        let send_key = keys.send_key;
        let recv_key = keys.recv_key;
        let send_iv = keys.send_iv;
        let recv_iv = keys.recv_iv;

        let prefer_aes = prefer_aes_gcm();

        let send_aead = if prefer_aes {
            AeadImpl::Aes(Box::new(Aes256Gcm::new(GenericArray::from_slice(
                &send_key,
            ))))
        } else {
            AeadImpl::ChaCha(ChaCha20Poly1305::new(ChaChaKey::from_slice(&send_key)))
        };

        let recv_aead = if prefer_aes {
            AeadImpl::Aes(Box::new(Aes256Gcm::new(GenericArray::from_slice(
                &recv_key,
            ))))
        } else {
            AeadImpl::ChaCha(ChaCha20Poly1305::new(ChaChaKey::from_slice(&recv_key)))
        };

        keys.zeroize();

        Ok(Self {
            send_aead,
            recv_aead,
            send_iv,
            recv_iv,
            send_counter: 0,
            recv_counter: 0,
        })
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.send_counter == u64::MAX {
            return Err(CryptoError::NonceExhausted);
        }
        let nonce_bytes = compose_nonce(&self.send_iv, self.send_counter);
        let ciphertext = self.send_aead.encrypt(&nonce_bytes, plaintext)?;
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .ok_or(CryptoError::NonceExhausted)?;
        Ok(ciphertext)
    }

    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.recv_counter == u64::MAX {
            return Err(CryptoError::NonceExhausted);
        }
        let nonce_bytes = compose_nonce(&self.recv_iv, self.recv_counter);
        let plaintext = self.recv_aead.decrypt(&nonce_bytes, ciphertext)?;
        self.recv_counter = self
            .recv_counter
            .checked_add(1)
            .ok_or(CryptoError::NonceExhausted)?;
        Ok(plaintext)
    }
}

impl Drop for SessionCrypto {
    fn drop(&mut self) {
        self.send_iv.zeroize();
        self.recv_iv.zeroize();
        self.send_counter.zeroize();
        self.recv_counter.zeroize();
    }
}

fn compose_nonce(iv: &[u8; 12], counter: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let ctr = counter.to_be_bytes();
    for (idx, byte) in ctr.iter().enumerate() {
        nonce[4 + idx] ^= byte;
    }
    nonce
}

fn prefer_aes_gcm() -> bool {
    if env::var_os("VELOCITY_DISABLE_AES").is_some() {
        return false;
    }
    if env::var_os("VELOCITY_FORCE_AES").is_some() {
        return true;
    }
    supports_aes_gcm()
}

fn supports_aes_gcm() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        aes_hw::get()
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_and_decrypts_roundtrip() {
        let key_set = SessionKeySet {
            send_key: [1u8; 32],
            send_iv: [2u8; 12],
            recv_key: [1u8; 32],
            recv_iv: [2u8; 12],
        };

        let mut sender = SessionCrypto::new(key_set.clone()).expect("sender");
        let mut receiver = SessionCrypto::new(SessionKeySet {
            send_key: key_set.recv_key,
            send_iv: key_set.recv_iv,
            recv_key: key_set.send_key,
            recv_iv: key_set.send_iv,
        })
        .expect("receiver");

        let message = b"post-quantum hello";
        let cipher = sender.seal(message).expect("encrypt");
        let plain = receiver.open(&cipher).expect("decrypt");
        assert_eq!(plain, message);
    }
}
