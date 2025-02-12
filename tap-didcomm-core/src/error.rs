//! Error types for the `DIDComm` core library.

use thiserror::Error;

/// Error type for the `DIDComm` core library.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid message format
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Base64 decode error
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// System time error
    #[error("System time error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Plugin error
    #[error("Plugin error: {0}")]
    Plugin(String),

    /// HTTP error
    #[error("HTTP error: {0}")]
    Http(String),
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::SerializationError(err.to_string())
    }
}

/// Result type for the `DIDComm` core library.
pub type Result<T> = std::result::Result<T, Error>;
