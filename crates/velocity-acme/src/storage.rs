use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use thiserror::Error;
use x509_parser::prelude::*;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("x509 parse error: {0}")]
    X509(String),
}

#[derive(Debug, Clone)]
pub struct CachedCertificate {
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub expires_at: DateTime<Utc>,
}

impl CachedCertificate {
    pub fn is_valid(&self, window: Duration) -> bool {
        let now = Utc::now();
        let renew_at = self.expires_at - chrono::Duration::from_std(window).unwrap_or_default();
        now < renew_at
    }
}

#[derive(Clone)]
pub struct AcmeCache {
    root: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl AcmeCache {
    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self, StorageError> {
        let root = root.as_ref();
        if !root.exists() {
            fs::create_dir_all(root)?;
        }
        secure_cache_dir(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            cert_path: root.join("certificate.pem"),
            key_path: root.join("private_key.pem"),
        })
    }

    pub fn save_certificate(
        &self,
        certificate_pem: &str,
        private_key_pem: &str,
    ) -> Result<CachedCertificate, StorageError> {
        write_public_file(&self.cert_path, certificate_pem.as_bytes())?;
        write_private_file(&self.key_path, private_key_pem.as_bytes())?;
        let expires_at = extract_not_after(certificate_pem)?;
        Ok(CachedCertificate {
            certificate_pem: certificate_pem.to_string(),
            private_key_pem: private_key_pem.to_string(),
            expires_at,
        })
    }

    pub fn load_certificate(&self) -> Result<Option<CachedCertificate>, StorageError> {
        if self.cert_path.exists() && self.key_path.exists() {
            let cert = fs::read_to_string(&self.cert_path)?;
            let key = fs::read_to_string(&self.key_path)?;
            let expires_at = extract_not_after(&cert)?;
            Ok(Some(CachedCertificate {
                certificate_pem: cert,
                private_key_pem: key,
                expires_at,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn account_path(&self) -> PathBuf {
        self.root.join("account.json")
    }
}

fn extract_not_after(pem: &str) -> Result<DateTime<Utc>, StorageError> {
    let (_, certificate_pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|_| StorageError::X509("failed to parse PEM".into()))?;
    let cert = X509Certificate::from_der(&certificate_pem.contents)
        .map_err(|err| StorageError::X509(err.to_string()))?
        .1;
    let not_after = cert.validity().not_after.to_datetime();
    DateTime::<Utc>::from_timestamp(not_after.unix_timestamp(), not_after.nanosecond())
        .ok_or_else(|| StorageError::X509("invalid certificate expiry".into()))
}

#[cfg(unix)]
fn secure_cache_dir(path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_cache_dir(_: &Path) -> Result<(), StorageError> {
    Ok(())
}

pub(crate) fn write_private_file(path: &Path, content: &[u8]) -> Result<(), StorageError> {
    write_file_with_mode(path, content, 0o600)
}

fn write_public_file(path: &Path, content: &[u8]) -> Result<(), StorageError> {
    write_file_with_mode(path, content, 0o644)
}

#[cfg(unix)]
fn write_file_with_mode(path: &Path, content: &[u8], mode: u32) -> Result<(), StorageError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;
    file.write_all(content)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file_with_mode(path: &Path, content: &[u8], _: u32) -> Result<(), StorageError> {
    fs::write(path, content)?;
    Ok(())
}
