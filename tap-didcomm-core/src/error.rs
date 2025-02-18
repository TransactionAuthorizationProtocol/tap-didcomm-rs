//! Error types for the `DIDComm` core library.

use thiserror::Error;

/// Error type for the `DIDComm` core library.
#[derive(Debug, Error)]
pub enum Error {
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

    /// Error during key agreement operation
    #[error("Key agreement error: {0}")]
    KeyAgreement(String),

    /// Error processing the JWE header
    #[error("Header error: {0}")]
    Header(String),

    /// Invalid key material
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Authentication failed during decryption
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Base64 decoding error
    #[error("Invalid base64: {0}")]
    Base64(String),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid curve specified for operation
    #[error("Invalid curve: {0}")]
    InvalidCurve(String),

    /// Invalid algorithm specified for operation
    #[error("Invalid algorithm: {0}")]
    InvalidAlgorithm(String),

    /// Error when parsing or validating a DID Document
    #[error("Invalid DID Document: {0}")]
    InvalidDIDDocument(String),

    /// Error when key material is invalid or in wrong format
    #[error("Invalid key material: {0}")]
    InvalidKeyMaterial(String),

    /// Error during key wrapping operation
    #[error("Key wrapping failed: {0}")]
    KeyWrap(String),

    /// Error during content encryption/decryption
    #[error("Content encryption error: {0}")]
    ContentEncryption(String),
}

/// Result type for the `DIDComm` core library.
pub type Result<T> = std::result::Result<T, Error>;
