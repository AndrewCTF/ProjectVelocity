use super::handshake::{HybridSuite, DEFAULT_MAX_EARLY_DATA};

/// Security/performance tuning profiles inspired by Cloudflare-style tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// Prioritise absolute latency with ML-KEM-512 and AES-128-GCM.
    Turbo,
    /// Default balance between throughput and security using ML-KEM-768 + ChaCha20.
    Balanced,
    /// Maximised security with ML-KEM-1024 and AES-256-GCM.
    Fortress,
}

impl SecurityProfile {
    pub fn suite(&self) -> HybridSuite {
        match self {
            SecurityProfile::Turbo => HybridSuite::TURBO,
            SecurityProfile::Balanced => HybridSuite::BALANCED,
            SecurityProfile::Fortress => HybridSuite::FORTRESS,
        }
    }

    /// Recommended early-data limit for the selected profile.
    pub fn max_early_data(&self) -> u32 {
        match self {
            SecurityProfile::Turbo => DEFAULT_MAX_EARLY_DATA * 4,
            SecurityProfile::Balanced => DEFAULT_MAX_EARLY_DATA,
            SecurityProfile::Fortress => DEFAULT_MAX_EARLY_DATA / 2,
        }
    }
}
