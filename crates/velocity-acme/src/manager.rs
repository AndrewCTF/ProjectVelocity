//! ACME certificate management built on top of `instant-acme`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use instant_acme::{
    Account, AccountCredentials, Authorization, AuthorizationStatus, Challenge, ChallengeType,
    Identifier, NewAccount, NewOrder, Order, OrderStatus,
};
use parking_lot::RwLock;
use rustls::ServerConfig;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::config::{AcmeChallengeType, AcmeConfig};
use crate::storage::{AcmeCache, CachedCertificate, StorageError};

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("acme client error: {0}")]
    Client(#[from] instant_acme::Error),
    #[error("acme error: {0}")]
    Acme(String),
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("watch error: {0}")]
    Watch(#[from] tokio::sync::watch::error::SendError<Option<CertificateBundle>>),
    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Debug, Clone)]
pub struct CertificateBundle {
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub expires_at: DateTime<Utc>,
}

impl From<CachedCertificate> for CertificateBundle {
    fn from(value: CachedCertificate) -> Self {
        Self {
            certificate_pem: value.certificate_pem,
            private_key_pem: value.private_key_pem,
            expires_at: value.expires_at,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TlsAlpnState {
    pub server_config: Arc<ServerConfig>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct AcmeHandle {
    http_tokens: Arc<RwLock<HashMap<String, String>>>,
    tls_alpn: Arc<RwLock<Option<TlsAlpnState>>>,
    cert_rx: watch::Receiver<Option<CertificateBundle>>,
    shutdown: watch::Sender<bool>,
    join: Arc<RwLock<Option<JoinHandle<()>>>>,
}

impl AcmeHandle {
    pub fn http_key_authorization(&self, token: &str) -> Option<String> {
        self.http_tokens.read().get(token).cloned()
    }

    pub fn tls_alpn_state(&self) -> Option<TlsAlpnState> {
        self.tls_alpn.read().clone()
    }

    pub fn current_certificate(&self) -> Option<CertificateBundle> {
        self.cert_rx.borrow().clone()
    }

    pub async fn wait_for_certificate(&mut self) -> Option<CertificateBundle> {
        if self.cert_rx.changed().await.is_ok() {
            self.cert_rx.borrow().clone()
        } else {
            None
        }
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        if let Some(join) = self.join.write().take() {
            tokio::spawn(async move {
                let _ = join.await;
            });
        }
    }
}

struct ManagerInner {
    config: AcmeConfig,
    cache: AcmeCache,
    http_tokens: Arc<RwLock<HashMap<String, String>>>,
    tls_alpn: Arc<RwLock<Option<TlsAlpnState>>>,
    sender: watch::Sender<Option<CertificateBundle>>,
    shutdown: watch::Receiver<bool>,
    current: Arc<RwLock<Option<CertificateBundle>>>,
}

impl ManagerInner {
    fn renewal_deadline(&self) -> Option<DateTime<Utc>> {
        self.current.read().as_ref().map(|bundle| bundle.expires_at)
    }
}

pub struct AcmeManager;

impl AcmeManager {
    pub async fn spawn(config: AcmeConfig) -> Result<AcmeHandle, AcmeError> {
        if !config.has_domain() {
            return Err(AcmeError::Configuration(
                "automatic certificates require at least one domain".into(),
            ));
        }

        config.ensure_cache_dir()?;
        let cache = AcmeCache::new(config.cache_dir())?;
        let (tx, rx) = watch::channel(None);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let http_tokens = Arc::new(RwLock::new(HashMap::new()));
        let tls_alpn = Arc::new(RwLock::new(None));
        let inner = Arc::new(ManagerInner {
            config: config.clone(),
            cache: cache.clone(),
            http_tokens: http_tokens.clone(),
            tls_alpn: tls_alpn.clone(),
            sender: tx,
            shutdown: shutdown_rx,
            current: Arc::new(RwLock::new(None)),
        });

        if let Some(cached) = cache.load_certificate()? {
            let bundle = CertificateBundle::from(cached);
            *inner.current.write() = Some(bundle.clone());
            inner.sender.send(Some(bundle))?;
        }

        let run_inner = inner.clone();
        let join = tokio::spawn(async move {
            if let Err(err) = run_loop(run_inner).await {
                warn!(target: "velocity::acme", error = %err, "acme manager exited with error");
            }
        });

        Ok(AcmeHandle {
            http_tokens,
            tls_alpn,
            cert_rx: rx,
            shutdown: shutdown_tx,
            join: Arc::new(RwLock::new(Some(join))),
        })
    }
}

async fn run_loop(inner: Arc<ManagerInner>) -> Result<(), AcmeError> {
    let mut shutdown_rx = inner.shutdown.clone();
    loop {
        let duration_until_renew = match inner.renewal_deadline() {
            Some(expiry) => {
                let renewal_window = ChronoDuration::from_std(inner.config.renewal_window())
                    .unwrap_or_else(|_| ChronoDuration::hours(24));
                let renew_at = expiry - renewal_window;
                let now = Utc::now();
                if now >= renew_at {
                    Duration::from_secs(0)
                } else {
                    (renew_at - now)
                        .to_std()
                        .unwrap_or_else(|_| Duration::from_secs(0))
                }
            }
            None => Duration::from_secs(0),
        };

        tokio::select! {
            _ = sleep(duration_until_renew) => {
                issue_certificate(inner.clone()).await?;
            }
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn issue_certificate(inner: Arc<ManagerInner>) -> Result<(), AcmeError> {
    let bundle = obtain_certificate(inner.clone()).await?;

    *inner.current.write() = Some(bundle.clone());
    inner.sender.send(Some(bundle.clone()))?;

    inner.http_tokens.write().clear();
    inner.tls_alpn.write().take();
    Ok(())
}

async fn obtain_certificate(inner: Arc<ManagerInner>) -> Result<CertificateBundle, AcmeError> {
    let account = load_or_create_account(&inner).await?;

    let identifiers: Vec<Identifier> = inner
        .config
        .domains()
        .iter()
        .map(|domain| Identifier::Dns(domain.clone()))
        .collect();

    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await?;

    prepare_authorizations(&inner, &mut order).await?;
    wait_for_order_ready(&mut order).await?;

    let certificate = build_end_entity_certificate(inner.config.domains())?;
    let csr = certificate.serialize_request_der()?;
    order.finalize(&csr).await?;

    let cert_pem = fetch_certificate(&mut order).await?;
    let key_pem = certificate.serialize_private_key_pem();
    let stored = inner.cache.save_certificate(&cert_pem, &key_pem)?;
    Ok(CertificateBundle::from(stored))
}

async fn load_or_create_account(inner: &ManagerInner) -> Result<Account, AcmeError> {
    let credentials_path = inner.cache.account_path();
    if credentials_path.exists() {
        let data = tokio::fs::read(&credentials_path).await?;
        let creds: AccountCredentials = serde_json::from_slice(&data)?;
        Ok(Account::from_credentials(creds).await?)
    } else {
        let contacts: Vec<String> = inner
            .config
            .contact_email
            .as_ref()
            .map(|email| vec![format!("mailto:{email}")])
            .unwrap_or_default();
        let contact_refs: Vec<&str> = contacts.iter().map(|s| s.as_str()).collect();
        let new_account = NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        let (account, creds) =
            Account::create(&new_account, inner.config.directory_url(), None).await?;
        tokio::fs::write(&credentials_path, serde_json::to_vec_pretty(&creds)?).await?;
        Ok(account)
    }
}

async fn prepare_authorizations(
    inner: &Arc<ManagerInner>,
    order: &mut Order,
) -> Result<(), AcmeError> {
    let authorizations = order.authorizations().await?;
    inner.http_tokens.write().clear();

    for authorization in authorizations {
        if matches!(authorization.status, AuthorizationStatus::Valid) {
            continue;
        }
        satisfy_authorization(inner, order, authorization).await?;
    }

    Ok(())
}

async fn satisfy_authorization(
    inner: &Arc<ManagerInner>,
    order: &mut Order,
    authorization: Authorization,
) -> Result<(), AcmeError> {
    for challenge_pref in &inner.config.challenge_types {
        match challenge_pref {
            AcmeChallengeType::Http01 => {
                if let Some(challenge) = find_challenge(&authorization, ChallengeType::Http01) {
                    handle_http_challenge(inner, order, challenge).await?;
                    return Ok(());
                }
            }
            AcmeChallengeType::TlsAlpn01 => {
                if let Some(challenge) = find_challenge(&authorization, ChallengeType::TlsAlpn01) {
                    handle_tls_alpn_challenge(inner, order, &authorization, challenge).await?;
                    return Ok(());
                }
            }
        }
    }

    Err(AcmeError::Acme(format!(
        "no supported challenges for {}",
        identifier_to_string(&authorization.identifier)
    )))
}

fn find_challenge(authorization: &Authorization, ty: ChallengeType) -> Option<&Challenge> {
    authorization
        .challenges
        .iter()
        .find(|challenge| challenge.r#type == ty)
}

async fn handle_http_challenge(
    inner: &Arc<ManagerInner>,
    order: &mut Order,
    challenge: &Challenge,
) -> Result<(), AcmeError> {
    let key_auth = order.key_authorization(challenge);
    inner
        .http_tokens
        .write()
        .insert(challenge.token.clone(), key_auth.as_str().to_string());
    order.set_challenge_ready(&challenge.url).await?;
    Ok(())
}

async fn handle_tls_alpn_challenge(
    inner: &Arc<ManagerInner>,
    order: &mut Order,
    authorization: &Authorization,
    challenge: &Challenge,
) -> Result<(), AcmeError> {
    let domain = match &authorization.identifier {
        Identifier::Dns(value) => value.clone(),
    };

    let key_auth = order.key_authorization(challenge);
    let digest = key_auth.digest();
    let tls_state = build_tls_alpn_state(&domain, digest.as_ref())?;
    *inner.tls_alpn.write() = Some(tls_state);
    order.set_challenge_ready(&challenge.url).await?;
    Ok(())
}

fn build_tls_alpn_state(domain: &str, digest: &[u8]) -> Result<TlsAlpnState, AcmeError> {
    use rcgen::{CertificateParams, CustomExtension, PKCS_ECDSA_P256_SHA256};
    use rustls::{Certificate as RustlsCertificate, PrivateKey};

    let mut params = CertificateParams::new(vec![domain.to_owned()]);
    params.alg = &PKCS_ECDSA_P256_SHA256;
    params
        .custom_extensions
        .push(CustomExtension::new_acme_identifier(digest));
    let certificate = rcgen::Certificate::from_params(params)?;
    let cert_der = certificate.serialize_der()?;
    let key_der = certificate.serialize_private_key_der();

    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![RustlsCertificate(cert_der)], PrivateKey(key_der))
        .map_err(|err| AcmeError::Acme(err.to_string()))?;
    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];

    Ok(TlsAlpnState {
        server_config: Arc::new(config),
        expires_at: Utc::now() + ChronoDuration::minutes(30),
    })
}

async fn wait_for_order_ready(order: &mut Order) -> Result<(), AcmeError> {
    let mut attempts = 0u8;
    let mut delay = Duration::from_millis(250);

    loop {
        sleep(delay).await;
        let state = order.refresh().await?;
        debug!(target: "velocity::acme", status = ?state.status, "polled order status");

        match state.status {
            OrderStatus::Ready => return Ok(()),
            OrderStatus::Invalid => {
                return Err(AcmeError::Acme(
                    "order marked invalid while waiting for readiness".into(),
                ));
            }
            _ => {}
        }

        attempts += 1;
        if attempts > 7 {
            return Err(AcmeError::Acme(
                "timeout waiting for order readiness".into(),
            ));
        }
        delay = (delay * 2).min(Duration::from_secs(8));
    }
}

async fn fetch_certificate(order: &mut Order) -> Result<String, AcmeError> {
    for attempt in 0..10 {
        if let Some(cert) = order.certificate().await? {
            return Ok(cert);
        }

        debug!(target: "velocity::acme", attempt, "certificate not ready yet");
        sleep(Duration::from_secs(1)).await;
    }

    Err(AcmeError::Acme(
        "timeout waiting for certificate issuance".into(),
    ))
}

fn build_end_entity_certificate(domains: &[String]) -> Result<rcgen::Certificate, AcmeError> {
    if domains.is_empty() {
        return Err(AcmeError::Configuration(
            "cannot request certificate without domains".into(),
        ));
    }

    let mut params = rcgen::CertificateParams::new(domains.to_vec());
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    Ok(rcgen::Certificate::from_params(params)?)
}

fn identifier_to_string(identifier: &Identifier) -> String {
    match identifier {
        Identifier::Dns(value) => value.clone(),
    }
}
