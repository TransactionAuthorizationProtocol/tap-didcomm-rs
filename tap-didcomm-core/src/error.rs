//! Error types for the tap-didcomm-core crate.

use thiserror::Error;

/// Error type for the DIDComm core library
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid format error
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    /// Base64 decode error
    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    /// Invalid signature error
    #[error("Invalid signature")]
    InvalidSignature,
    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
    /// DID resolution error
    #[error("DID resolution error: {0}")]
    DIDResolution(String),
    /// Serialization error
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    /// Signing error
    #[error("Signing error: {0}")]
    Signing(String),
    /// Verification error
    #[error("Verification error: {0}")]
    Verification(String),
    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),
    /// Decryption error
    #[error("Decryption error: {0}")]
    Decryption(String),
    /// Plugin not available error
    #[error("Plugin not available: {0}")]
    PluginNotAvailable(String),
}

/// Result type for the DIDComm core library
pub type Result<T> = std::result::Result<T, Error>; 