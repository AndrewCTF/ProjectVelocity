use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// ACME challenge types supported by the manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AcmeChallengeType {
    #[default]
    Http01,
    TlsAlpn01,
}

impl AcmeChallengeType {
    pub fn http() -> &'static [AcmeChallengeType] {
        &[AcmeChallengeType::Http01]
    }
}

/// Configuration object describing account, cache and domain metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub directory_url: String,
    #[serde(default)]
    pub contact_email: Option<String>,
    pub cache_dir: PathBuf,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default = "default_challenge_types")]
    pub challenge_types: Vec<AcmeChallengeType>,
    #[serde(default = "default_renewal_window_secs")]
    pub renewal_window: u64,
}

fn default_challenge_types() -> Vec<AcmeChallengeType> {
    vec![AcmeChallengeType::Http01, AcmeChallengeType::TlsAlpn01]
}

fn default_renewal_window_secs() -> u64 {
    72 * 60 * 60
}

impl AcmeConfig {
    pub fn ensure_cache_dir(&self) -> std::io::Result<()> {
        if !self.cache_dir.exists() {
            std::fs::create_dir_all(&self.cache_dir)?;
        }
        Ok(())
    }

    pub fn certificate_path(&self) -> PathBuf {
        self.cache_dir.join("certificate.pem")
    }

    pub fn private_key_path(&self) -> PathBuf {
        self.cache_dir.join("private_key.pem")
    }

    pub fn account_path(&self) -> PathBuf {
        self.cache_dir.join("account.json")
    }

    pub fn renewal_window(&self) -> Duration {
        Duration::from_secs(self.renewal_window)
    }

    pub fn directory_url(&self) -> &str {
        &self.directory_url
    }

    pub fn domains(&self) -> &[String] {
        &self.domains
    }

    pub fn has_domain(&self) -> bool {
        !self.domains.is_empty()
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}
