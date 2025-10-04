use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use pqq_core::HandshakeResponse;

/// Attempt to extract an ML-KEM public key from the handshake response.
///
/// Servers may publish the key directly as a base64 string or embed it inside a
/// JSON object containing a `kem_public_b64` field. This helper accepts both
/// formats and returns the decoded byte vector if present.
pub fn extract_kem_public(response: &HandshakeResponse) -> Option<Vec<u8>> {
    let payload = response.pq_payload.as_ref()?;
    parse_kem_payload(payload)
}

pub fn parse_kem_payload(payload: &str) -> Option<Vec<u8>> {
    if payload.trim().is_empty() {
        return None;
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) {
        if let Some(b64) = value.get("kem_public_b64").and_then(|v| v.as_str()) {
            if let Ok(bytes) = BASE64_STANDARD.decode(b64.as_bytes()) {
                return Some(bytes);
            }
        }
        // Allow servers to fallback to a simple string field for compatibility.
        if let Some(b64) = value.get("kem_public").and_then(|v| v.as_str()) {
            if let Ok(bytes) = BASE64_STANDARD.decode(b64.as_bytes()) {
                return Some(bytes);
            }
        }
    }

    BASE64_STANDARD.decode(payload.as_bytes()).ok()
}
