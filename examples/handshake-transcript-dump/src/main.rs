use std::sync::Arc;

use anyhow::{anyhow, Result};
use pqq_client::{Client, ClientConfig};
use pqq_core::cbor_from_slice;
use pqq_server::{Server, ServerConfig};
use pqq_tls::{ClientHelloPayload, ServerHelloPayload};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct TranscriptDocument {
    client_hello_b64: String,
    server_hello_b64: String,
    client_finished_b64: String,
    client_finished_sha256: String,
    client_fields: ClientFields,
    server_fields: ServerFields,
}

#[derive(Serialize)]
struct ClientFields {
    client_random_hex: String,
    client_nonce_hex: String,
    kem_public_len: usize,
    kem_public_sha256: String,
    auth_ciphertext_len: usize,
    auth_ciphertext_sha256: String,
    early_data_len: usize,
}

#[derive(Serialize)]
struct ServerFields {
    fs_ciphertext_len: usize,
    fs_ciphertext_sha256: String,
    server_finished_hex: String,
    session_ticket_hex: Option<String>,
    resumption_accepted: bool,
    max_early_data: u32,
    retry_cookie_present: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let server = Arc::new(Server::bind(([127, 0, 0, 1], 0), ServerConfig::default()).await?);
    let addr = server.local_addr()?;
    let kem_public = server.kem_public_key().to_vec();

    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let session = server.accept().await?;
            session
                .handshake_transcript()
                .cloned()
                .ok_or_else(|| anyhow!("session missing handshake transcript"))
        })
    };

    let client_task = tokio::spawn(async move {
        let client = Client::new(
            ClientConfig::new(addr)
                .with_alpns(["pqq/1", "h3"])
                .with_server_kem_public(kem_public),
        );
        client.connect().await
    });

    let (transcript, _session) = tokio::try_join!(server_task, client_task)?;
    let transcript = transcript?;

    let client_payload: ClientHelloPayload = cbor_from_slice(transcript.client_raw())?;
    let server_payload: ServerHelloPayload = cbor_from_slice(transcript.server_raw())?;

    let document = TranscriptDocument {
        client_hello_b64: transcript.client_base64(),
        server_hello_b64: transcript.server_base64(),
        client_finished_b64: transcript.client_finished_base64(),
        client_finished_sha256: sha256_hex(transcript.client_finished_raw()),
        client_fields: ClientFields {
            client_random_hex: hex(&client_payload.client_random),
            client_nonce_hex: hex(&client_payload.client_nonce),
            kem_public_len: client_payload.client_kem_public.len(),
            kem_public_sha256: sha256_hex(&client_payload.client_kem_public),
            auth_ciphertext_len: client_payload.auth_ciphertext.len(),
            auth_ciphertext_sha256: sha256_hex(&client_payload.auth_ciphertext),
            early_data_len: client_payload
                .early_data
                .as_ref()
                .map(|d| d.len())
                .unwrap_or(0),
        },
        server_fields: ServerFields {
            fs_ciphertext_len: server_payload.fs_ciphertext.len(),
            fs_ciphertext_sha256: sha256_hex(&server_payload.fs_ciphertext),
            server_finished_hex: hex(&server_payload.server_finished),
            session_ticket_hex: server_payload
                .session_ticket
                .as_ref()
                .map(|ticket| hex(ticket)),
            resumption_accepted: server_payload.resumption_accepted,
            max_early_data: server_payload.max_early_data,
            retry_cookie_present: server_payload.retry_cookie.is_some(),
        },
    };

    println!("{}", serde_json::to_string_pretty(&document)?);

    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex(&digest)
}
