//! Error types for JWE operations.
//!
//! This module defines the error types that can occur during JWE (JSON Web Encryption)
//! operations, including key agreement, encryption, decryption, and message processing.
//! Each error type provides detailed information about what went wrong to help with
//! debugging and error handling.

use std::fmt;
use std::error::Error as StdError;
use base64::DecodeError;

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
#[derive(Debug)]
pub enum JweError {
    /// Error during key agreement operation
    KeyAgreement(String),

    /// Error processing the JWE header
    Header(String),

    /// Invalid key material
    InvalidKey(String),

    /// Error during encryption operation
    Encryption(String),

    /// Error during decryption operation
    Decryption(String),

    /// Authentication failed during decryption
    AuthenticationFailed,

    /// Base64 encoding/decoding error
    Base64(&'static str, DecodeError),

    /// JSON serialization/deserialization error
    Serialization(serde_json::Error),

    /// Invalid curve specified for operation
    InvalidCurve(String),

    /// Invalid algorithm specified for operation
    InvalidAlgorithm(String),

    /// Invalid message format
    InvalidFormat(String),
}

impl fmt::Display for JweError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyAgreement(msg) => write!(f, "Key agreement error: {}", msg),
            Self::Header(msg) => write!(f, "Header error: {}", msg),
            Self::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            Self::Encryption(msg) => write!(f, "Encryption error: {}", msg),
            Self::Decryption(msg) => write!(f, "Decryption error: {}", msg),
            Self::AuthenticationFailed => write!(f, "Authentication failed"),
            Self::Base64(ctx, err) => write!(f, "Base64 error in {}: {}", ctx, err),
            Self::Serialization(err) => write!(f, "Serialization error: {}", err),
            Self::InvalidCurve(msg) => write!(f, "Invalid curve: {}", msg),
            Self::InvalidAlgorithm(msg) => write!(f, "Invalid algorithm: {}", msg),
            Self::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
        }
    }
}

impl StdError for JweError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Base64(_, err) => Some(err),
            Self::Serialization(err) => Some(err),
            _ => None,
        }
    }
}

impl From<DecodeError> for JweError {
    fn from(err: DecodeError) -> Self {
        Self::Base64("decode", err)
    }
}

impl From<serde_json::Error> for JweError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let errors = [
            (JweError::KeyAgreement("test".into()), "Key agreement error: test"),
            (JweError::Header("test".into()), "Header error: test"),
            (JweError::InvalidKey("test".into()), "Invalid key: test"),
            (JweError::Encryption("test".into()), "Encryption error: test"),
            (JweError::Decryption("test".into()), "Decryption error: test"),
            (JweError::AuthenticationFailed, "Authentication failed"),
            (JweError::InvalidCurve("test".into()), "Invalid curve: test"),
            (JweError::InvalidAlgorithm("test".into()), "Invalid algorithm: test"),
            (JweError::InvalidFormat("test".into()), "Invalid format: test"),
        ];

        for (error, expected) in errors.iter() {
            assert_eq!(error.to_string(), *expected);
        }
    }

    #[test]
    fn test_error_conversion() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let jwe_err = JweError::from(json_err);
        assert!(matches!(jwe_err, JweError::Serialization(_)));

        let base64_err = base64::engine::general_purpose::STANDARD.decode("invalid").unwrap_err();
        let jwe_err = JweError::from(base64_err);
        assert!(matches!(jwe_err, JweError::Base64(_, _)));
    }
} 