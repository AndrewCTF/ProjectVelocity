use crate::crypto::{Perspective, SessionKeySet};
use crate::session::{SessionTicketError, SessionTicketManager};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pqq_core::{cbor_to_vec, LavaRand, ReplayError, ReplayGuard, ReplayToken};
#[cfg(test)]
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::Sha256;
use sha2::{Digest, Sha384};
use std::sync::Arc;
use std::time::SystemTime;
use subtle::ConstantTimeEq;

#[cfg(test)]
use std::time::Duration;

#[cfg(feature = "mlkem")]
use pqcrypto_mlkem::{
    mlkem1024, mlkem512,
    mlkem768::{self, Ciphertext, PublicKey, SecretKey},
};
#[cfg(feature = "mlkem")]
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

const CLIENT_RANDOM_LEN: usize = 32;
const CLIENT_NONCE_LEN: usize = 32;
const SHA384_OUTPUT_LEN: usize = 48;
const FINISHED_KEY_LEN: usize = SHA384_OUTPUT_LEN;
pub(crate) const DEFAULT_MAX_EARLY_DATA: u32 = 16 * 1024;
const LABEL_AUTH: &[u8] = b"flash/auth";
const LABEL_FS: &[u8] = b"flash/fs";
const LABEL_HANDSHAKE_SECRET: &[u8] = b"flash/handshake secret";
const LABEL_APPLICATION_SECRET: &[u8] = b"flash/application secret";
const LABEL_CLIENT_WRITE_KEY: &[u8] = b"flash/client write key";
const LABEL_CLIENT_WRITE_IV: &[u8] = b"flash/client write iv";
const LABEL_SERVER_WRITE_KEY: &[u8] = b"flash/server write key";
const LABEL_SERVER_WRITE_IV: &[u8] = b"flash/server write iv";
const LABEL_RESUMPTION_SECRET: &[u8] = b"flash/resumption secret";
const LABEL_FINISHED_CLIENT: &[u8] = b"flash/finished client";
const LABEL_FINISHED_SERVER: &[u8] = b"flash/finished server";
const PROTOCOL_VERSION_DRAFT1: u16 = 0x0001;
const CIPHER_SUITE_AES_128_GCM_SHA256: u16 = 0x1301;
const CIPHER_SUITE_CHACHA20_POLY1305_SHA384: u16 = 0x1303;
const CIPHER_SUITE_AES_256_GCM_SHA384: u16 = 0x1302;
const KEM_SUITE_ML_KEM_512: u16 = 0x0200;
const KEM_SUITE_ML_KEM_768: u16 = 0x0201;
const KEM_SUITE_ML_KEM_1024: u16 = 0x0202;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HybridSuite {
    pub protocol_version: u16,
    pub cipher_suite: u16,
    pub kem_suite: u16,
}

impl HybridSuite {
    pub const TURBO: Self = Self {
        protocol_version: PROTOCOL_VERSION_DRAFT1,
        cipher_suite: CIPHER_SUITE_AES_128_GCM_SHA256,
        kem_suite: KEM_SUITE_ML_KEM_512,
    };

    pub const BALANCED: Self = Self {
        protocol_version: PROTOCOL_VERSION_DRAFT1,
        cipher_suite: CIPHER_SUITE_CHACHA20_POLY1305_SHA384,
        kem_suite: KEM_SUITE_ML_KEM_768,
    };

    pub const FORTRESS: Self = Self {
        protocol_version: PROTOCOL_VERSION_DRAFT1,
        cipher_suite: CIPHER_SUITE_AES_256_GCM_SHA384,
        kem_suite: KEM_SUITE_ML_KEM_1024,
    };
}

type HmacSha384 = Hmac<Sha384>;

/// Describes errors that can occur while running the FLASH-KEM handshake.
#[derive(Debug, thiserror::Error)]
pub enum HybridHandshakeError {
    #[error("kem operation failed: {0}")]
    Kem(String),
    #[error("handshake serialization error: {0}")]
    Serialization(String),
    #[error("invalid handshake payload")]
    InvalidPayload,
    #[error("session ticket error: {0}")]
    Ticket(SessionTicketError),
    #[error("handshake state not ready for finalization")]
    PendingStateMissing,
    #[error("finished message verification failed")]
    FinishedVerification,
    #[error("0-RTT replay detected: {0}")]
    Replay(ReplayError),
}

/// Trait abstracting over the PQ KEM implementation (e.g., Kyber).
pub trait KemProvider: Send + Sync {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), HybridHandshakeError>;
    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HybridHandshakeError>;
    fn decapsulate(
        &self,
        ciphertext: &[u8],
        secret_key: &[u8],
    ) -> Result<Vec<u8>, HybridHandshakeError>;
}

/// ML-KEM (Kyber) provider backed by pqcrypto bindings.
#[cfg(feature = "mlkem")]
#[derive(Debug, Default, Clone, Copy)]
pub struct MlKem768;

#[cfg(feature = "mlkem")]
impl KemProvider for MlKem768 {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), HybridHandshakeError> {
        let (public, secret) = mlkem768::keypair();
        Ok((public.as_bytes().to_vec(), secret.as_bytes().to_vec()))
    }

    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HybridHandshakeError> {
        let public_key = PublicKey::from_bytes(public_key)
            .map_err(|_| HybridHandshakeError::Kem("invalid public key".into()))?;
        let (shared_raw, ciphertext_raw) = mlkem768::encapsulate(&public_key);
        Ok((
            ciphertext_raw.as_bytes().to_vec(),
            shared_raw.as_bytes().to_vec(),
        ))
    }

    fn decapsulate(
        &self,
        ciphertext: &[u8],
        secret_key: &[u8],
    ) -> Result<Vec<u8>, HybridHandshakeError> {
        let secret_key = SecretKey::from_bytes(secret_key)
            .map_err(|_| HybridHandshakeError::Kem("invalid secret key".into()))?;
        let ciphertext = Ciphertext::from_bytes(ciphertext)
            .map_err(|_| HybridHandshakeError::Kem("invalid ciphertext".into()))?;
        let shared = mlkem768::decapsulate(&ciphertext, &secret_key);
        Ok(shared.as_bytes().to_vec())
    }
}

#[cfg(feature = "mlkem")]
#[derive(Debug, Default, Clone, Copy)]
pub struct MlKem512;

#[cfg(feature = "mlkem")]
impl KemProvider for MlKem512 {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), HybridHandshakeError> {
        let (public, secret) = mlkem512::keypair();
        Ok((public.as_bytes().to_vec(), secret.as_bytes().to_vec()))
    }

    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HybridHandshakeError> {
        let public_key = mlkem512::PublicKey::from_bytes(public_key)
            .map_err(|_| HybridHandshakeError::Kem("invalid public key".into()))?;
        let (shared_raw, ciphertext_raw) = mlkem512::encapsulate(&public_key);
        Ok((
            ciphertext_raw.as_bytes().to_vec(),
            shared_raw.as_bytes().to_vec(),
        ))
    }

    fn decapsulate(
        &self,
        ciphertext: &[u8],
        secret_key: &[u8],
    ) -> Result<Vec<u8>, HybridHandshakeError> {
        let secret_key = mlkem512::SecretKey::from_bytes(secret_key)
            .map_err(|_| HybridHandshakeError::Kem("invalid secret key".into()))?;
        let ciphertext = mlkem512::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| HybridHandshakeError::Kem("invalid ciphertext".into()))?;
        let shared = mlkem512::decapsulate(&ciphertext, &secret_key);
        Ok(shared.as_bytes().to_vec())
    }
}

#[cfg(feature = "mlkem")]
#[derive(Debug, Default, Clone, Copy)]
pub struct MlKem1024;

#[cfg(feature = "mlkem")]
impl KemProvider for MlKem1024 {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), HybridHandshakeError> {
        let (public, secret) = mlkem1024::keypair();
        Ok((public.as_bytes().to_vec(), secret.as_bytes().to_vec()))
    }

    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HybridHandshakeError> {
        let public_key = mlkem1024::PublicKey::from_bytes(public_key)
            .map_err(|_| HybridHandshakeError::Kem("invalid public key".into()))?;
        let (shared_raw, ciphertext_raw) = mlkem1024::encapsulate(&public_key);
        Ok((
            ciphertext_raw.as_bytes().to_vec(),
            shared_raw.as_bytes().to_vec(),
        ))
    }

    fn decapsulate(
        &self,
        ciphertext: &[u8],
        secret_key: &[u8],
    ) -> Result<Vec<u8>, HybridHandshakeError> {
        let secret_key = mlkem1024::SecretKey::from_bytes(secret_key)
            .map_err(|_| HybridHandshakeError::Kem("invalid secret key".into()))?;
        let ciphertext = mlkem1024::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| HybridHandshakeError::Kem("invalid ciphertext".into()))?;
        let shared = mlkem1024::decapsulate(&ciphertext, &secret_key);
        Ok(shared.as_bytes().to_vec())
    }
}

/// Static server KEM key material published via DNS SVCB/DANE or similar.
#[derive(Debug, Clone)]
pub struct StaticKemKeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

impl StaticKemKeyPair {
    pub fn new(public: Vec<u8>, secret: Vec<u8>) -> Self {
        Self { public, secret }
    }
}

/// Resumption parameters selected by the client.
#[derive(Debug, Clone)]
pub struct ResumptionParams {
    pub ticket: Vec<u8>,
    pub secret: [u8; 32],
}

/// Optional knobs influencing the client hello construction.
#[derive(Debug, Clone, Default)]
pub struct ClientHelloOptions {
    pub resumption: Option<ResumptionParams>,
    pub early_data: Option<Vec<u8>>,
    pub cookie: Option<Vec<u8>>,
}

/// Client -> Server handshake payload following the FLASH-KEM design.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientHelloPayload {
    pub protocol_version: u16,
    pub cipher_suites: Vec<u16>,
    pub kem_suites: Vec<u16>,
    pub grease: u16,
    pub client_random: [u8; CLIENT_RANDOM_LEN],
    pub client_nonce: [u8; CLIENT_NONCE_LEN],
    pub client_kem_public: Vec<u8>,
    pub auth_ciphertext: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk_identity: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binder: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub early_data: Option<Vec<u8>>,
}

impl ClientHelloPayload {
    fn encode_without_auth(&self) -> Result<Vec<u8>, HybridHandshakeError> {
        #[derive(Serialize)]
        struct WithoutAuth<'a> {
            protocol_version: u16,
            #[serde(with = "serde_compact_u16_vec")]
            cipher_suites: &'a [u16],
            #[serde(with = "serde_compact_u16_vec")]
            kem_suites: &'a [u16],
            grease: u16,
            client_random: &'a [u8; CLIENT_RANDOM_LEN],
            client_nonce: &'a [u8; CLIENT_NONCE_LEN],
            client_kem_public: &'a [u8],
            #[serde(skip_serializing_if = "Option::is_none")]
            cookie: Option<&'a Vec<u8>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            psk_identity: Option<&'a Vec<u8>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            binder: Option<&'a Vec<u8>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            early_data: Option<&'a Vec<u8>>,
        }

        cbor_to_vec(&WithoutAuth {
            protocol_version: self.protocol_version,
            cipher_suites: &self.cipher_suites,
            kem_suites: &self.kem_suites,
            grease: self.grease,
            client_random: &self.client_random,
            client_nonce: &self.client_nonce,
            client_kem_public: &self.client_kem_public,
            cookie: self.cookie.as_ref(),
            psk_identity: self.psk_identity.as_ref(),
            binder: self.binder.as_ref(),
            early_data: self.early_data.as_ref(),
        })
        .map_err(|err| HybridHandshakeError::Serialization(err.to_string()))
    }

    fn encode_full(&self) -> Result<Vec<u8>, HybridHandshakeError> {
        cbor_to_vec(self).map_err(|err| HybridHandshakeError::Serialization(err.to_string()))
    }
}

/// Server -> Client handshake payload for FLASH-KEM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerHelloPayload {
    pub selected_version: u16,
    pub selected_cipher: u16,
    pub selected_kem: u16,
    pub fs_ciphertext: Vec<u8>,
    pub server_finished: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ticket: Option<Vec<u8>>,
    #[serde(default)]
    pub resumption_accepted: bool,
    #[serde(default)]
    pub max_early_data: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_cookie: Option<Vec<u8>>,
}

impl ServerHelloPayload {
    fn encode_core(&self) -> Result<Vec<u8>, HybridHandshakeError> {
        #[derive(Serialize)]
        struct Core<'a> {
            selected_version: u16,
            selected_cipher: u16,
            selected_kem: u16,
            fs_ciphertext: &'a [u8],
            #[serde(skip_serializing_if = "Option::is_none")]
            session_ticket: Option<&'a Vec<u8>>,
            resumption_accepted: bool,
            max_early_data: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            retry_cookie: Option<&'a Vec<u8>>,
        }

        cbor_to_vec(&Core {
            selected_version: self.selected_version,
            selected_cipher: self.selected_cipher,
            selected_kem: self.selected_kem,
            fs_ciphertext: &self.fs_ciphertext,
            session_ticket: self.session_ticket.as_ref(),
            resumption_accepted: self.resumption_accepted,
            max_early_data: self.max_early_data,
            retry_cookie: self.retry_cookie.as_ref(),
        })
        .map_err(|err| HybridHandshakeError::Serialization(err.to_string()))
    }

    fn encode_finished(&self) -> Result<Vec<u8>, HybridHandshakeError> {
        #[derive(Serialize)]
        struct Finished<'a> {
            server_finished: &'a [u8],
        }

        cbor_to_vec(&Finished {
            server_finished: &self.server_finished,
        })
        .map_err(|err| HybridHandshakeError::Serialization(err.to_string()))
    }
}

/// Client -> Server Finished payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientFinishedPayload {
    pub verify_data: Vec<u8>,
}

impl ClientFinishedPayload {
    fn encode(&self) -> Result<Vec<u8>, HybridHandshakeError> {
        cbor_to_vec(self).map_err(|err| HybridHandshakeError::Serialization(err.to_string()))
    }
}

/// Output of the FLASH-KEM key schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridKeySchedule {
    pub handshake_secret: [u8; 32],
    pub application_secret: [u8; 32],
    resumption_secret: [u8; 32],
    client_write_key: [u8; 32],
    server_write_key: [u8; 32],
    client_write_iv: [u8; 12],
    server_write_iv: [u8; 12],
    client_finished_key: [u8; FINISHED_KEY_LEN],
    server_finished_key: [u8; FINISHED_KEY_LEN],
}

impl HybridKeySchedule {
    pub fn derive(secret0: &[u8]) -> Result<Self, HybridHandshakeError> {
        let hkdf = Hkdf::<Sha384>::new(None, secret0);

        let mut handshake_secret = [0u8; 32];
        hkdf.expand(LABEL_HANDSHAKE_SECRET, &mut handshake_secret)
            .map_err(|_| HybridHandshakeError::Kem("hkdf handshake".into()))?;

        let mut application_secret = [0u8; 32];
        hkdf.expand(LABEL_APPLICATION_SECRET, &mut application_secret)
            .map_err(|_| HybridHandshakeError::Kem("hkdf application".into()))?;

        let mut client_write_key = [0u8; 32];
        hkdf.expand(LABEL_CLIENT_WRITE_KEY, &mut client_write_key)
            .map_err(|_| HybridHandshakeError::Kem("hkdf client key".into()))?;

        let mut server_write_key = [0u8; 32];
        hkdf.expand(LABEL_SERVER_WRITE_KEY, &mut server_write_key)
            .map_err(|_| HybridHandshakeError::Kem("hkdf server key".into()))?;

        let mut client_write_iv = [0u8; 12];
        hkdf.expand(LABEL_CLIENT_WRITE_IV, &mut client_write_iv)
            .map_err(|_| HybridHandshakeError::Kem("hkdf client iv".into()))?;

        let mut server_write_iv = [0u8; 12];
        hkdf.expand(LABEL_SERVER_WRITE_IV, &mut server_write_iv)
            .map_err(|_| HybridHandshakeError::Kem("hkdf server iv".into()))?;

        let mut resumption_secret = [0u8; 32];
        hkdf.expand(LABEL_RESUMPTION_SECRET, &mut resumption_secret)
            .map_err(|_| HybridHandshakeError::Kem("hkdf resumption".into()))?;

        let mut client_finished_key = [0u8; FINISHED_KEY_LEN];
        hkdf.expand(LABEL_FINISHED_CLIENT, &mut client_finished_key)
            .map_err(|_| HybridHandshakeError::Kem("hkdf finished client".into()))?;

        let mut server_finished_key = [0u8; FINISHED_KEY_LEN];
        hkdf.expand(LABEL_FINISHED_SERVER, &mut server_finished_key)
            .map_err(|_| HybridHandshakeError::Kem("hkdf finished server".into()))?;

        Ok(Self {
            handshake_secret,
            application_secret,
            resumption_secret,
            client_write_key,
            server_write_key,
            client_write_iv,
            server_write_iv,
            client_finished_key,
            server_finished_key,
        })
    }

    pub fn session_keys(&self, perspective: Perspective) -> SessionKeySet {
        match perspective {
            Perspective::Client => SessionKeySet {
                send_key: self.client_write_key,
                send_iv: self.client_write_iv,
                recv_key: self.server_write_key,
                recv_iv: self.server_write_iv,
            },
            Perspective::Server => SessionKeySet {
                send_key: self.server_write_key,
                send_iv: self.server_write_iv,
                recv_key: self.client_write_key,
                recv_iv: self.client_write_iv,
            },
        }
    }

    pub fn resumption_secret(&self) -> [u8; 32] {
        self.resumption_secret
    }

    pub fn finished_key(&self, perspective: Perspective) -> &[u8; FINISHED_KEY_LEN] {
        match perspective {
            Perspective::Client => &self.client_finished_key,
            Perspective::Server => &self.server_finished_key,
        }
    }
}

/// Client-side handshake driver that works with a [`KemProvider`].
#[derive(Debug, Clone)]
pub struct ClientHandshake<P: KemProvider> {
    kem: P,
    suite: HybridSuite,
    client_secret: Vec<u8>,
    resumption_secret: Option<[u8; 32]>,
    transcript: Transcript,
    client_payload: ClientHelloPayload,
    client_payload_bytes: Vec<u8>,
    k_auth: Vec<u8>,
    options: ClientHelloOptions,
}

/// Outcome of processing the server flight on the client.
#[derive(Debug, Clone)]
pub struct ClientCompletion {
    pub key_schedule: HybridKeySchedule,
    pub client_finished: ClientFinishedPayload,
    pub client_finished_bytes: Vec<u8>,
    pub session_ticket: Option<Vec<u8>>,
    pub resumption_accepted: bool,
    pub max_early_data: u32,
    pub early_data: Option<Vec<u8>>,
}

impl<P: KemProvider> ClientHandshake<P> {
    pub fn new(
        kem: P,
        suite: HybridSuite,
        server_static_public: Vec<u8>,
        options: ClientHelloOptions,
    ) -> Result<Self, HybridHandshakeError> {
        let (client_kem_public, client_secret) = kem.generate_keypair()?;

        let mut client_random = [0u8; CLIENT_RANDOM_LEN];
        LavaRand::fill_bytes(&mut client_random);

        let mut client_nonce = [0u8; CLIENT_NONCE_LEN];
        LavaRand::fill_bytes(&mut client_nonce);

        let mut grease_bytes = [0u8; 2];
        LavaRand::fill_bytes(&mut grease_bytes);
        let grease = u16::from_le_bytes(grease_bytes);

        let mut payload = ClientHelloPayload {
            protocol_version: suite.protocol_version,
            cipher_suites: vec![suite.cipher_suite],
            kem_suites: vec![suite.kem_suite],
            grease,
            client_random,
            client_nonce,
            client_kem_public,
            auth_ciphertext: Vec::new(),
            cookie: options.cookie.clone(),
            psk_identity: options.resumption.as_ref().map(|r| r.ticket.clone()),
            binder: None,
            early_data: options.early_data.clone(),
        };

        let context_bytes = payload.encode_without_auth()?;
        let context_digest = sha384_digest(&context_bytes);
        let context = [&b"auth"[..], &context_digest[..]].concat();

        let (auth_ciphertext, auth_shared) = kem.encapsulate(&server_static_public)?;
        let k_auth = derive_labeled_secret(LABEL_AUTH, &context, &auth_shared)?;
        payload.auth_ciphertext = auth_ciphertext;

        let client_payload_bytes = payload.encode_full()?;
        let mut transcript = Transcript::new();
        transcript.update(&client_payload_bytes);

        Ok(Self {
            kem,
            suite,
            client_secret,
            resumption_secret: options.resumption.as_ref().map(|r| r.secret),
            transcript,
            client_payload: payload,
            client_payload_bytes,
            k_auth,
            options,
        })
    }

    pub fn client_payload(&self) -> &ClientHelloPayload {
        &self.client_payload
    }

    pub fn client_payload_bytes(&self) -> &[u8] {
        &self.client_payload_bytes
    }

    pub fn complete(
        mut self,
        server_payload: &ServerHelloPayload,
    ) -> Result<ClientCompletion, HybridHandshakeError> {
        if server_payload.selected_cipher != self.suite.cipher_suite
            || server_payload.selected_kem != self.suite.kem_suite
            || server_payload.selected_version != self.suite.protocol_version
        {
            return Err(HybridHandshakeError::InvalidPayload);
        }
        let transcript_before_server = self.transcript.current_hash();
        let fs_context = [&b"fs"[..], &transcript_before_server[..]].concat();

        let fs_shared = self
            .kem
            .decapsulate(&server_payload.fs_ciphertext, &self.client_secret)?;
        let k_fs = derive_labeled_secret(LABEL_FS, &fs_context, &fs_shared)?;

        let secret0 = compose_secret0(&self.k_auth, &k_fs, self.resumption_secret.as_ref());
        let schedule = HybridKeySchedule::derive(&secret0)?;

        let server_core = server_payload.encode_core()?;
        self.transcript.update(&server_core);

        let handshake_hash_for_server = self.transcript.current_hash();
        let expected_server_finished = hmac_sha384(
            schedule.finished_key(Perspective::Server),
            &handshake_hash_for_server,
        )?;

        if expected_server_finished.len() != server_payload.server_finished.len()
            || expected_server_finished
                .ct_eq(server_payload.server_finished.as_slice())
                .unwrap_u8()
                == 0
        {
            return Err(HybridHandshakeError::FinishedVerification);
        }

        let server_finished = server_payload.encode_finished()?;
        self.transcript.update(&server_finished);

        let handshake_hash_for_client = self.transcript.current_hash();
        let client_finished_bytes = hmac_sha384(
            schedule.finished_key(Perspective::Client),
            &handshake_hash_for_client,
        )?;
        let client_finished = ClientFinishedPayload {
            verify_data: client_finished_bytes.clone(),
        };
        let client_finished_encoded = client_finished.encode()?;
        self.transcript.update(&client_finished_encoded);

        let resumption_accepted = server_payload.resumption_accepted;
        let early_data = if resumption_accepted {
            self.options.early_data.clone()
        } else {
            None
        };

        Ok(ClientCompletion {
            key_schedule: schedule,
            client_finished,
            client_finished_bytes,
            session_ticket: server_payload.session_ticket.clone(),
            resumption_accepted,
            max_early_data: server_payload.max_early_data,
            early_data,
        })
    }
}

/// Result of the server responding to a client hello.
#[derive(Debug, Clone)]
pub struct ServerHandshakeResult {
    pub payload: ServerHelloPayload,
    pub key_schedule: HybridKeySchedule,
    pub resumption_accepted: bool,
    pub early_data: Option<Vec<u8>>,
    pub suite: HybridSuite,
}

#[derive(Debug)]
struct ServerPendingState {
    transcript: Transcript,
    key_schedule: HybridKeySchedule,
    client_finished_key: [u8; FINISHED_KEY_LEN],
    replay_token: Option<PendingReplay>,
}

#[derive(Debug, Clone)]
struct PendingReplay {
    ticket_id: [u8; 16],
    client_nonce: [u8; CLIENT_NONCE_LEN],
    not_before: SystemTime,
    expires_at: SystemTime,
}

impl PendingReplay {
    fn as_token(&self) -> ReplayToken<'_> {
        ReplayToken {
            ticket_id: &self.ticket_id,
            client_nonce: &self.client_nonce,
            not_before: self.not_before,
            expires_at: self.expires_at,
        }
    }
}

/// Server-side handshake driver.
#[derive(Debug)]
pub struct ServerHandshake<P: KemProvider> {
    kem: P,
    suite: HybridSuite,
    ticket_manager: Arc<SessionTicketManager>,
    static_keypair: StaticKemKeyPair,
    accepted_resumption: Option<[u8; 32]>,
    max_early_data: u32,
    pending: Option<ServerPendingState>,
    replay_guard: Arc<dyn ReplayGuard>,
}

impl<P: KemProvider> ServerHandshake<P> {
    pub fn new(
        kem: P,
        suite: HybridSuite,
        ticket_manager: Arc<SessionTicketManager>,
        static_keypair: StaticKemKeyPair,
        replay_guard: Arc<dyn ReplayGuard>,
    ) -> Self {
        Self {
            kem,
            suite,
            ticket_manager,
            static_keypair,
            accepted_resumption: None,
            max_early_data: DEFAULT_MAX_EARLY_DATA,
            pending: None,
            replay_guard,
        }
    }

    pub fn with_max_early_data(mut self, max: u32) -> Self {
        self.max_early_data = max;
        self
    }

    pub fn respond(
        &mut self,
        client_payload: &ClientHelloPayload,
        client_raw: &[u8],
    ) -> Result<ServerHandshakeResult, HybridHandshakeError> {
        let mut transcript = Transcript::new();
        transcript.update(client_raw);

        let context_bytes = client_payload.encode_without_auth()?;
        let context_digest = sha384_digest(&context_bytes);
        let auth_context = [&b"auth"[..], &context_digest[..]].concat();

        let k_auth_raw = self
            .kem
            .decapsulate(&client_payload.auth_ciphertext, &self.static_keypair.secret)?;
        let k_auth = derive_labeled_secret(LABEL_AUTH, &auth_context, &k_auth_raw)?;

        let fs_context = [&b"fs"[..], &transcript.current_hash()[..]].concat();
        let (fs_ciphertext, fs_shared) = self.kem.encapsulate(&client_payload.client_kem_public)?;
        let k_fs = derive_labeled_secret(LABEL_FS, &fs_context, &fs_shared)?;

        let mut resumption_secret = None;
        let mut resumption_accepted = false;
        let mut pending_replay: Option<PendingReplay> = None;

        if let Some(identity) = &client_payload.psk_identity {
            match self.ticket_manager.decrypt(identity) {
                Ok(ticket) => {
                    let early_len = client_payload
                        .early_data
                        .as_ref()
                        .map(|d| d.len())
                        .unwrap_or(0);
                    if ticket.allows_0rtt(SystemTime::now(), early_len).is_ok()
                        && ticket.max_early_data >= early_len as u32
                    {
                        resumption_secret = Some(ticket.resumption_secret);
                        if let Some(_early) = client_payload.early_data.as_ref() {
                            let token = ReplayToken {
                                ticket_id: &ticket.ticket_id,
                                client_nonce: &client_payload.client_nonce,
                                not_before: ticket.not_before,
                                expires_at: ticket.expires_at,
                            };
                            match self.replay_guard.check(token) {
                                Ok(()) => {
                                    resumption_accepted = true;
                                    pending_replay = Some(PendingReplay {
                                        ticket_id: ticket.ticket_id,
                                        client_nonce: client_payload.client_nonce,
                                        not_before: ticket.not_before,
                                        expires_at: ticket.expires_at,
                                    });
                                }
                                Err(ReplayError::AlreadySeen)
                                | Err(ReplayError::Expired)
                                | Err(ReplayError::NotYetValid) => {
                                    resumption_accepted = false;
                                    resumption_secret = None;
                                    pending_replay = None;
                                }
                                Err(ReplayError::Storage(_)) => {
                                    resumption_secret = None;
                                    resumption_accepted = false;
                                    pending_replay = None;
                                }
                            }
                        }
                    }
                }
                Err(_err) => {
                    // Decryption errors are handled by falling back to a fresh handshake.
                }
            }
        }
        self.accepted_resumption = resumption_secret;

        let secret0 = compose_secret0(&k_auth, &k_fs, self.accepted_resumption.as_ref());
        let schedule = HybridKeySchedule::derive(&secret0)?;

        let server_finished_key = *schedule.finished_key(Perspective::Server);
        let client_finished_key = *schedule.finished_key(Perspective::Client);

        let ticket = self
            .ticket_manager
            .issue(schedule.resumption_secret(), self.max_early_data);

        let mut server_payload = ServerHelloPayload {
            selected_version: self.suite.protocol_version,
            selected_cipher: self.suite.cipher_suite,
            selected_kem: self.suite.kem_suite,
            fs_ciphertext,
            server_finished: Vec::new(),
            session_ticket: Some(ticket),
            resumption_accepted,
            max_early_data: self.max_early_data,
            retry_cookie: None,
        };

        let server_core = server_payload.encode_core()?;
        transcript.update(&server_core);

        let handshake_hash = transcript.current_hash();
        let server_finished = hmac_sha384(&server_finished_key, &handshake_hash)?;

        server_payload.server_finished = server_finished.clone();

        let server_finished_encoded = server_payload.encode_finished()?;
        transcript.update(&server_finished_encoded);

        let early_data = if resumption_accepted {
            client_payload.early_data.clone()
        } else {
            None
        };

        self.pending = Some(ServerPendingState {
            transcript,
            key_schedule: schedule.clone(),
            client_finished_key,
            replay_token: pending_replay,
        });

        Ok(ServerHandshakeResult {
            payload: server_payload,
            key_schedule: schedule,
            resumption_accepted,
            early_data,
            suite: self.suite,
        })
    }

    pub fn finalize(
        &mut self,
        _client_payload: &ClientHelloPayload,
        _server_payload: &ServerHelloPayload,
        client_finished: &ClientFinishedPayload,
        client_finished_raw: &[u8],
    ) -> Result<HybridKeySchedule, HybridHandshakeError> {
        let mut state = self
            .pending
            .take()
            .ok_or(HybridHandshakeError::PendingStateMissing)?;

        let expected = hmac_sha384(&state.client_finished_key, &state.transcript.current_hash())?;
        if expected.len() != client_finished.verify_data.len()
            || expected
                .ct_eq(client_finished.verify_data.as_slice())
                .unwrap_u8()
                == 0
        {
            return Err(HybridHandshakeError::FinishedVerification);
        }

        state.transcript.update(client_finished_raw);
        let schedule = state.key_schedule.clone();

        if let Some(replay) = state.replay_token.take() {
            self.replay_guard
                .register(replay.as_token())
                .map_err(HybridHandshakeError::Replay)?;
        }

        self.pending = Some(state);

        Ok(schedule)
    }
}

fn compose_secret0(k_auth: &[u8], k_fs: &[u8], resumption: Option<&[u8; 32]>) -> Vec<u8> {
    let mut combined = Vec::with_capacity(k_auth.len() + k_fs.len() + 32);
    combined.extend_from_slice(k_auth);
    combined.extend_from_slice(k_fs);
    if let Some(secret) = resumption {
        combined.extend_from_slice(secret);
    }
    combined
}

fn derive_labeled_secret(
    label: &[u8],
    context: &[u8],
    shared: &[u8],
) -> Result<Vec<u8>, HybridHandshakeError> {
    let hkdf = Hkdf::<Sha384>::new(Some(context), shared);
    let mut out = vec![0u8; SHA384_OUTPUT_LEN];
    hkdf.expand(label, &mut out)
        .map_err(|_| HybridHandshakeError::Kem("hkdf expand".into()))?;
    Ok(out)
}

fn hmac_sha384(key: &[u8], data: &[u8]) -> Result<Vec<u8>, HybridHandshakeError> {
    let mut mac = HmacSha384::new_from_slice(key)
        .map_err(|_| HybridHandshakeError::Kem("invalid finished key".into()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn sha384_digest(input: &[u8]) -> [u8; SHA384_OUTPUT_LEN] {
    let mut hasher = Sha384::new();
    hasher.update(input);
    let digest = hasher.finalize();
    let mut out = [0u8; SHA384_OUTPUT_LEN];
    out.copy_from_slice(&digest);
    out
}

#[derive(Debug, Clone)]
struct Transcript {
    hasher: Sha384,
}

impl Transcript {
    fn new() -> Self {
        Self {
            hasher: Sha384::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    fn current_hash(&self) -> [u8; SHA384_OUTPUT_LEN] {
        let mut clone = self.hasher.clone();
        let digest = clone.finalize_reset();
        let mut out = [0u8; SHA384_OUTPUT_LEN];
        out.copy_from_slice(&digest);
        out
    }
}

mod serde_compact_u16_vec {
    use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for item in value {
            seq.serialize_element(&item)?;
        }
        seq.end()
    }

    #[allow(dead_code)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u16>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u16>::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqq_core::{cbor_from_slice, InMemoryReplayGuard, ReplayGuard};

    #[derive(Debug, Default, Clone)]
    struct TestKem;

    impl KemProvider for TestKem {
        fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), HybridHandshakeError> {
            let mut secret = vec![0u8; 32];
            OsRng.fill_bytes(&mut secret);
            Ok((secret.clone(), secret))
        }

        fn encapsulate(
            &self,
            public_key: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), HybridHandshakeError> {
            let mut nonce = vec![0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            let hkdf = Hkdf::<Sha256>::new(None, &[public_key, &nonce].concat());
            let mut shared = vec![0u8; SHA384_OUTPUT_LEN];
            hkdf.expand(b"test-shared", &mut shared)
                .map_err(|_| HybridHandshakeError::Kem("hkdf expand".into()))?;
            Ok((nonce, shared))
        }

        fn decapsulate(
            &self,
            ciphertext: &[u8],
            secret_key: &[u8],
        ) -> Result<Vec<u8>, HybridHandshakeError> {
            let hkdf = Hkdf::<Sha256>::new(None, &[secret_key, ciphertext].concat());
            let mut shared = vec![0u8; SHA384_OUTPUT_LEN];
            hkdf.expand(b"test-shared", &mut shared)
                .map_err(|_| HybridHandshakeError::Kem("hkdf expand".into()))?;
            Ok(shared)
        }
    }

    fn ticket_manager() -> Arc<SessionTicketManager> {
        Arc::new(SessionTicketManager::new(
            [7u8; 32],
            Duration::from_secs(60),
        ))
    }

    fn static_keypair() -> StaticKemKeyPair {
        let kem = TestKem;
        let (public, secret) = kem.generate_keypair().expect("keypair");
        StaticKemKeyPair::new(public, secret)
    }

    fn replay_guard() -> Arc<dyn ReplayGuard> {
        Arc::new(InMemoryReplayGuard::default())
    }

    #[test]
    fn payload_roundtrip() {
        let payload = ClientHelloPayload {
            protocol_version: PROTOCOL_VERSION_DRAFT1,
            cipher_suites: vec![CIPHER_SUITE_CHACHA20_POLY1305_SHA384],
            kem_suites: vec![KEM_SUITE_ML_KEM_768],
            grease: 0x0a0a,
            client_random: [7u8; CLIENT_RANDOM_LEN],
            client_nonce: [9u8; CLIENT_NONCE_LEN],
            client_kem_public: vec![1, 2, 3],
            auth_ciphertext: vec![4, 5, 6],
            cookie: Some(vec![9, 9]),
            psk_identity: Some(vec![8, 8]),
            binder: None,
            early_data: Some(vec![1, 2, 3, 4]),
        };
        let encoded = payload.encode_full().expect("encode");
        let decoded: ClientHelloPayload = cbor_from_slice(&encoded).expect("decode");
        assert_eq!(payload, decoded);

        let server_payload = ServerHelloPayload {
            selected_version: PROTOCOL_VERSION_DRAFT1,
            selected_cipher: CIPHER_SUITE_CHACHA20_POLY1305_SHA384,
            selected_kem: KEM_SUITE_ML_KEM_768,
            fs_ciphertext: vec![5, 6, 7],
            server_finished: vec![8, 9],
            session_ticket: Some(vec![1, 1, 1]),
            resumption_accepted: true,
            max_early_data: 32,
            retry_cookie: None,
        };
        let encoded = cbor_to_vec(&server_payload).expect("encode server");
        let decoded: ServerHelloPayload = cbor_from_slice(&encoded).expect("decode");
        assert_eq!(server_payload, decoded);
    }

    #[test]
    fn round_trip_handshake() {
        let kem = TestKem;
        let static_keys = static_keypair();
        let manager = ticket_manager();
        let suite = HybridSuite::BALANCED;

        let client = ClientHandshake::new(
            kem.clone(),
            suite,
            static_keys.public.clone(),
            ClientHelloOptions::default(),
        )
        .expect("client init");

        let client_payload_bytes = client.client_payload_bytes().to_vec();
        let client_payload: ClientHelloPayload =
            cbor_from_slice(&client_payload_bytes).expect("client decode");

        let mut server = ServerHandshake::new(
            kem.clone(),
            suite,
            Arc::clone(&manager),
            static_keys,
            replay_guard(),
        );
        let result = server
            .respond(&client_payload, &client_payload_bytes)
            .expect("server respond");
        let server_payload = result.payload.clone();
        let completion = client.complete(&server_payload).expect("client complete");

        let server_keys = server
            .finalize(
                &client_payload,
                &server_payload,
                &completion.client_finished,
                &completion.client_finished_bytes,
            )
            .expect("server finalize");

        assert_eq!(
            completion.key_schedule.handshake_secret,
            server_keys.handshake_secret
        );
        assert_eq!(
            completion.key_schedule.application_secret,
            server_keys.application_secret
        );
    }

    #[test]
    fn replay_guard_rejects_duplicate_0rtt() {
        let kem = TestKem;
        let static_keys = static_keypair();
        let manager = ticket_manager();
        let guard: Arc<dyn ReplayGuard> = Arc::new(InMemoryReplayGuard::default());
        let suite = HybridSuite::BALANCED;

        // Initial full handshake to obtain resumption material.
        let client1 = ClientHandshake::new(
            kem.clone(),
            suite,
            static_keys.public.clone(),
            ClientHelloOptions::default(),
        )
        .expect("client init");
        let client_payload_bytes1 = client1.client_payload_bytes().to_vec();
        let client_payload1: ClientHelloPayload =
            cbor_from_slice(&client_payload_bytes1).expect("client decode");
        let mut server1 = ServerHandshake::new(
            kem.clone(),
            suite,
            Arc::clone(&manager),
            static_keys.clone(),
            Arc::clone(&guard),
        );
        let server_result1 = server1
            .respond(&client_payload1, &client_payload_bytes1)
            .expect("server respond");
        let server_payload1 = server_result1.payload.clone();
        let completion1 = client1.complete(&server_payload1).expect("client complete");
        let client_finished_payload1 = completion1.client_finished.clone();
        let client_finished_bytes1 = completion1.client_finished_bytes.clone();
        server1
            .finalize(
                &client_payload1,
                &server_payload1,
                &client_finished_payload1,
                &client_finished_bytes1,
            )
            .expect("server finalize");

        let ticket = server_payload1
            .session_ticket
            .clone()
            .expect("session ticket issued");
        let resumption_secret = completion1.key_schedule.resumption_secret();

        // Second handshake attempts 0-RTT.
        let options2 = ClientHelloOptions {
            resumption: Some(ResumptionParams {
                ticket: ticket.clone(),
                secret: resumption_secret,
            }),
            early_data: Some(b"GET /0rtt HTTP/1.1\r\n\r\n".to_vec()),
            ..ClientHelloOptions::default()
        };
        let client2 =
            ClientHandshake::new(kem.clone(), suite, static_keys.public.clone(), options2)
                .expect("client init 2");
        let client_payload_bytes2 = client2.client_payload_bytes().to_vec();
        let client_payload2: ClientHelloPayload =
            cbor_from_slice(&client_payload_bytes2).expect("client decode 2");
        let mut server2 = ServerHandshake::new(
            kem.clone(),
            suite,
            Arc::clone(&manager),
            static_keys.clone(),
            Arc::clone(&guard),
        );
        let server_result2 = server2
            .respond(&client_payload2, &client_payload_bytes2)
            .expect("server respond 2");
        assert!(server_result2.resumption_accepted);
        let server_payload2 = server_result2.payload.clone();
        let completion2 = client2
            .complete(&server_payload2)
            .expect("client complete 2");
        let client_finished_payload2 = completion2.client_finished.clone();
        let client_finished_bytes2 = completion2.client_finished_bytes.clone();
        server2
            .finalize(
                &client_payload2,
                &server_payload2,
                &client_finished_payload2,
                &client_finished_bytes2,
            )
            .expect("server finalize 2");

        // Replay the second ClientHello; guard should reject 0-RTT reuse.
        let mut server3 = ServerHandshake::new(
            kem,
            suite,
            Arc::clone(&manager),
            static_keys,
            Arc::clone(&guard),
        );
        let server_result3 = server3
            .respond(&client_payload2, &client_payload_bytes2)
            .expect("server respond 3");
        assert!(!server_result3.resumption_accepted);
        assert!(server_result3.early_data.is_none());
        let err = server3
            .finalize(
                &client_payload2,
                &server_result3.payload,
                &client_finished_payload2,
                &client_finished_bytes2,
            )
            .expect_err("replay should fail to finalize");
        assert!(matches!(err, HybridHandshakeError::FinishedVerification));
    }

    #[cfg(feature = "mlkem")]
    #[test]
    fn mlkem_round_trip_handshake() {
        let (public, secret) = MlKem768.generate_keypair().expect("mlkem keypair");
        let static_keys = StaticKemKeyPair::new(public, secret);
        let manager = ticket_manager();
        let suite = HybridSuite::BALANCED;

        let client = ClientHandshake::new(
            MlKem768,
            suite,
            static_keys.public.clone(),
            ClientHelloOptions::default(),
        )
        .expect("client init");

        let client_payload_bytes = client.client_payload_bytes().to_vec();
        let client_payload: ClientHelloPayload =
            cbor_from_slice(&client_payload_bytes).expect("client decode");

        let mut server = ServerHandshake::new(
            MlKem768,
            suite,
            Arc::clone(&manager),
            static_keys,
            replay_guard(),
        );
        let result = server
            .respond(&client_payload, &client_payload_bytes)
            .expect("server respond");
        let server_payload = result.payload.clone();
        let completion = client.complete(&server_payload).expect("client complete");

        let server_keys = server
            .finalize(
                &client_payload,
                &server_payload,
                &completion.client_finished,
                &completion.client_finished_bytes,
            )
            .expect("server finalize");

        assert_eq!(
            completion.key_schedule.handshake_secret,
            server_keys.handshake_secret
        );
        assert_eq!(
            completion.key_schedule.application_secret,
            server_keys.application_secret
        );
    }
}
