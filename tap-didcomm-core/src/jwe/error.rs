//! Error types for JWE operations.
//!
//! This module defines the error types that can occur during JWE (JSON Web Encryption)
//! operations, including key agreement, encryption, decryption, and message processing.
//! Each error type provides detailed information about what went wrong to help with
//! debugging and error handling.

use crate::error::Error;
use base64::DecodeError;
use std::error::Error as StdError;
use thiserror::Error;

/// Result type for JWE operations.
pub type Result<T> = std::result::Result<T, JweError>;

/// Errors that can occur during JWE operations.
///
/// This enum represents all possible errors that can occur when working with
/// JWE messages, including cryptographic operations, encoding/decoding,
/// and message validation.
///
/// # Examples
///
/// ```
/// use tap_didcomm_core::jwe::error::JweError;
///
/// let error = JweError::InvalidKey("Key length must be 32 bytes".to_string());
/// assert_eq!(
///     error.to_string(),
///     "Invalid key: Key length must be 32 bytes"
/// );
/// ```
#[derive(Debug, Error)]
pub enum JweError {
    /// Error during key agreement operation
    #[error("Key agreement error: {0}")]
    KeyAgreement(String),

    /// Error processing the JWE header
    #[error("Header error: {0}")]
    Header(String),

    /// Invalid key material
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Error during encryption operation
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Error during decryption operation
    #[error("Decryption error: {0}")]
    Decryption(String),

    /// Authentication failed during decryption
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Base64 encoding/decoding error
    #[error("Base64 error in {0}: {1}")]
    Base64(&'static str, #[source] DecodeError),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid curve specified for operation
    #[error("Invalid curve: {0}")]
    InvalidCurve(String),

    /// Invalid algorithm specified for operation
    #[error("Invalid algorithm: {0}")]
    InvalidAlgorithm(String),

    /// Invalid message format
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

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

    /// Core error
    #[error(transparent)]
    Core(#[from] Error),
}

impl From<DecodeError> for JweError {
    fn from(err: DecodeError) -> Self {
        Self::Base64("decode", err)
    }
}

impl From<Error> for JweError {
    fn from(err: Error) -> Self {
        Self::Core(err)
    }
}

impl From<serde_json::Error> for JweError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

// Add conversion from JweError to Error for cross-crate error handling
impl From<JweError> for Error {
    fn from(err: JweError) -> Self {
        match err {
            JweError::Base64(ctx, e) => {
                Error::InvalidFormat(format!("Base64 error in {}: {}", ctx, e))
            }
            JweError::Json(e) => Error::InvalidFormat(format!("JSON error: {}", e)),
            JweError::Core(e) => e,
            JweError::KeyAgreement(msg) => {
                Error::InvalidFormat(format!("Key agreement error: {}", msg))
            }
            JweError::Header(msg) => Error::InvalidFormat(format!("Header error: {}", msg)),
            JweError::InvalidKey(msg) => Error::InvalidFormat(format!("Invalid key: {}", msg)),
            JweError::Encryption(msg) => Error::EncryptionFailed(msg),
            JweError::Decryption(msg) => Error::DecryptionFailed(msg),
            JweError::AuthenticationFailed => Error::InvalidFormat("Authentication failed".into()),
            JweError::InvalidCurve(msg) => Error::InvalidFormat(format!("Invalid curve: {}", msg)),
            JweError::InvalidAlgorithm(msg) => {
                Error::InvalidFormat(format!("Invalid algorithm: {}", msg))
            }
            JweError::InvalidFormat(msg) => Error::InvalidFormat(msg),
            JweError::InvalidDIDDocument(msg) => {
                Error::InvalidFormat(format!("Invalid DID Document: {}", msg))
            }
            JweError::InvalidKeyMaterial(msg) => {
                Error::InvalidFormat(format!("Invalid key material: {}", msg))
            }
            JweError::KeyWrap(msg) => {
                Error::EncryptionFailed(format!("Key wrapping failed: {}", msg))
            }
            JweError::ContentEncryption(msg) => {
                Error::EncryptionFailed(format!("Content encryption error: {}", msg))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let errors = [
            (
                JweError::KeyAgreement("test".into()),
                "Key agreement error: test",
            ),
            (JweError::Header("test".into()), "Header error: test"),
            (JweError::InvalidKey("test".into()), "Invalid key: test"),
            (
                JweError::Encryption("test".into()),
                "Encryption error: test",
            ),
            (
                JweError::Decryption("test".into()),
                "Decryption error: test",
            ),
            (JweError::AuthenticationFailed, "Authentication failed"),
            (JweError::InvalidCurve("test".into()), "Invalid curve: test"),
            (
                JweError::InvalidAlgorithm("test".into()),
                "Invalid algorithm: test",
            ),
            (
                JweError::InvalidFormat("test".into()),
                "Invalid format: test",
            ),
            (
                JweError::InvalidDIDDocument("test".into()),
                "Invalid DID Document: test",
            ),
            (
                JweError::InvalidKeyMaterial("test".into()),
                "Invalid key material: test",
            ),
            (
                JweError::KeyWrap("test".into()),
                "Key wrapping failed: test",
            ),
            (
                JweError::ContentEncryption("test".into()),
                "Content encryption error: test",
            ),
        ];

        for (error, expected) in errors.iter() {
            assert_eq!(error.to_string(), *expected);
        }
    }

    #[test]
    fn test_error_conversion() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let jwe_err = JweError::from(json_err);
        assert!(matches!(jwe_err, JweError::Json(_)));

        let base64_err = base64::engine::general_purpose::STANDARD
            .decode("invalid")
            .unwrap_err();
        let jwe_err = JweError::from(base64_err);
        assert!(matches!(jwe_err, JweError::Base64(_, _)));
    }
}
