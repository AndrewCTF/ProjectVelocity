use std::{
    fs,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use lazy_static::lazy_static;
use parking_lot::Mutex;
use pqq_tls::SecurityProfile;

use crate::EasyError;

pub fn encode_base64_key(key: &[u8]) -> String {
    BASE64_STANDARD.encode(key)
}

pub fn decode_base64_key(key: &str) -> Result<Vec<u8>, EasyError> {
    Ok(BASE64_STANDARD.decode(key.trim())?)
}

const DEFAULT_CACHE_DIR: &str = ".velocity/known_servers";

pub fn default_cache_dir() -> PathBuf {
    dirs::home_dir()
        .map(|home| home.join(DEFAULT_CACHE_DIR))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE_DIR))
}

pub fn profile_from_str(label: &str) -> Result<SecurityProfile, EasyError> {
    match label.to_ascii_lowercase().as_str() {
        "turbo" | "fast" => Ok(SecurityProfile::Turbo),
        "balanced" | "default" => Ok(SecurityProfile::Balanced),
        "fortress" | "secure" => Ok(SecurityProfile::Fortress),
        other => Err(EasyError::UnknownProfile(other.to_string())),
    }
}

pub fn load_cached_key(host: &str, custom_dir: Option<&Path>) -> Result<Vec<u8>, EasyError> {
    let dir = custom_dir
        .map(PathBuf::from)
        .or_else(|| Some(default_cache_dir()))
        .unwrap();
    let path = dir.join(format!("{host}.kem"));
    let data = fs::read(&path)?;
    Ok(data)
}

pub fn store_cached_key(
    host: &str,
    key: &[u8],
    custom_dir: Option<&Path>,
) -> Result<PathBuf, EasyError> {
    let dir = custom_dir
        .map(PathBuf::from)
        .unwrap_or_else(default_cache_dir);
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{host}.kem"));
    fs::write(&path, key)?;
    Ok(path)
}

lazy_static! {
    static ref KEY_CACHE_OVERRIDE: Mutex<Option<PathBuf>> = Mutex::new(None);
}

#[allow(dead_code)]
pub fn set_cache_dir_override(path: Option<PathBuf>) {
    let mut guard = KEY_CACHE_OVERRIDE.lock();
    *guard = path;
}

pub fn cache_dir_override() -> Option<PathBuf> {
    KEY_CACHE_OVERRIDE.lock().clone()
}
