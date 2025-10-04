use hkdf::Hkdf;
use sha2::Sha256;

#[cfg(feature = "mlkem")]
use pqcrypto_mlkem::mlkem768;
#[cfg(feature = "mlkem")]
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

#[cfg(feature = "mldsa")]
use pqcrypto_mldsa::mldsa65;
#[cfg(feature = "mldsa")]
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

fn to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn print_section(title: &str) {
    println!("\n=== {} ===", title);
}

fn main() {
    #[cfg(feature = "mlkem")]
    {
        print_section("ML-KEM-768 fixture");
        let (client_pk, client_sk) = mlkem768::keypair();
        let (shared_raw, ciphertext_raw) = mlkem768::encapsulate(&client_pk);
        let ciphertext = ciphertext_raw.as_bytes();
        let shared_secret = shared_raw.as_bytes();
        println!("client_pk={}", to_hex(client_pk.as_bytes()));
        println!("client_pk_len={}", client_pk.as_bytes().len());
        println!("client_sk={}", to_hex(client_sk.as_bytes()));
        println!("client_sk_len={}", client_sk.as_bytes().len());
        println!("ciphertext={}", to_hex(ciphertext));
        println!("ciphertext_len={}", ciphertext.len());
        println!("shared_secret={}", to_hex(shared_secret));
        println!("shared_secret_len={}", shared_secret.len());

        // Derive deterministic handshake/app secrets by mixing example classical shares.
        let client_classical = [0x11u8; 32];
        let server_classical = [0x22u8; 32];
        let mut combined = Vec::new();
        combined.extend_from_slice(&client_classical);
        combined.extend_from_slice(&server_classical);
        combined.extend_from_slice(shared_secret);
        let hkdf = Hkdf::<Sha256>::new(None, &combined);

        let mut handshake = [0u8; 32];
        hkdf.expand(b"handshake secret", &mut handshake)
            .expect("handshake secret");
        let mut application = [0u8; 32];
        hkdf.expand(b"application secret", &mut application)
            .expect("application secret");
        println!("example_client_classical={}", to_hex(&client_classical));
        println!("example_server_classical={}", to_hex(&server_classical));
        println!("example_handshake_secret={}", to_hex(&handshake));
        println!("example_application_secret={}", to_hex(&application));
    }

    #[cfg(feature = "mldsa")]
    {
        print_section("ML-DSA-65 fixture");
        let message = b"VELO deterministic fixture";
        let (pk, sk) = mldsa65::keypair();
        let signature = mldsa65::detached_sign(message, &sk);

        println!("message={}", to_hex(message));
        println!("public_key={}", to_hex(pk.as_bytes()));
        println!("public_key_len={}", pk.as_bytes().len());
        println!("secret_key={}", to_hex(sk.as_bytes()));
        println!("secret_key_len={}", sk.as_bytes().len());
        println!("signature={}", to_hex(signature.as_bytes()));
        println!("signature_len={}", signature.as_bytes().len());
    }
}
