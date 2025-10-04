use std::io::Cursor;

use serde::{de::DeserializeOwned, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to serialize CBOR payload: {0}")]
    Serialize(#[from] ciborium::ser::Error<std::io::Error>),
    #[error("failed to deserialize CBOR payload: {0}")]
    Deserialize(#[from] ciborium::de::Error<std::io::Error>),
}

pub fn to_vec<T>(value: &T) -> Result<Vec<u8>, Error>
where
    T: Serialize,
{
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)?;
    Ok(buf)
}

pub fn from_slice<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: DeserializeOwned,
{
    let mut cursor = Cursor::new(bytes);
    Ok(ciborium::de::from_reader(&mut cursor)?)
}
