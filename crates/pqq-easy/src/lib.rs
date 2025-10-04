//! Ultra-simple Velocity client and server interfaces.
//!
//! `pqq-easy` wraps the lower-level crates with blocking-friendly builders so
//! applications can adopt Velocity with a handful of lines in any language.

mod client;
mod error;
mod server;
mod util;

pub use client::{EasyClient, EasyClientBuilder, EasyClientConfig};
pub use error::EasyError;
pub use server::{
    EasyAsyncHandler, EasyHandler, EasyRequest, EasyRequestHook, EasyResponse, EasyServerBuilder,
    EasyServerHandle, EasyTelemetryHook,
};
pub use util::{decode_base64_key, encode_base64_key, profile_from_str};

pub use pqq_tls::SecurityProfile;
