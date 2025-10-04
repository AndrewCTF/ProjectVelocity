use once_cell::sync::Lazy;
use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha3::{Digest, Sha3_512};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

static MIXER: Lazy<Mutex<LavaLampMixer>> = Lazy::new(|| {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    Mutex::new(LavaLampMixer::new(seed))
});

struct LavaLampMixer {
    rng: ChaCha20Rng,
    last_tick: Instant,
}

impl LavaLampMixer {
    fn new(seed: [u8; 32]) -> Self {
        let rng = ChaCha20Rng::from_seed(seed);
        Self {
            rng,
            last_tick: Instant::now(),
        }
    }

    fn reseed_if_needed(&mut self) {
        let elapsed = self.last_tick.elapsed();
        if elapsed > Duration::from_millis(17) {
            // Mix OS entropy, coarse system time, and timer jitter to mimic Cloudflare's lava lamps.
            let mut seed = [0u8; 64];
            OsRng.fill_bytes(&mut seed);
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default();
            let jitter = Instant::now().duration_since(self.last_tick).as_nanos();

            let mut hasher = Sha3_512::new();
            hasher.update(&seed);
            hasher.update(nanos.to_le_bytes());
            hasher.update(jitter.to_le_bytes());
            let digest = hasher.finalize();
            let mut new_seed = [0u8; 32];
            new_seed.copy_from_slice(&digest[0..32]);
            self.rng = ChaCha20Rng::from_seed(new_seed);
            self.last_tick = Instant::now();
        }
    }

    fn fill(&mut self, buf: &mut [u8]) {
        self.reseed_if_needed();
        self.rng.fill_bytes(buf);
    }
}

/// High-entropy generator inspired by Cloudflare's lava lamp wall.
///
/// The mixer continuously folds in OS randomness, system-timing jitter, and a
/// SHA3 diffusion step to provide resilient entropy suitable for PQ-friendly
/// key generation.
pub struct LavaRand;

impl LavaRand {
    /// Fill the provided buffer with mixed entropy.
    pub fn fill_bytes(buf: &mut [u8]) {
        let mut guard = MIXER.lock().expect("lava mixer");
        guard.fill(buf);
    }

    /// Produce a fresh vector of random bytes of the requested length.
    pub fn random_vec(len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        Self::fill_bytes(&mut out);
        out
    }
}
