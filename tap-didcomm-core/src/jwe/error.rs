//! Error types for the JWE module.

use thiserror::Error;

/// Result type for JWE operations.
pub type Result<T> = std::result::Result<T, JweError>;

/// Errors that can occur during JWE operations.
#[derive(Debug, Error)]
pub enum JweError {
    /// Key agreement failed.
    #[error("Key agreement failed: {0}")]
    KeyAgreement(String),

    /// Content encryption failed.
    #[error("Content encryption failed: {0}")]
    ContentEncryption(String),

    /// Key wrapping failed.
    #[error("Key wrapping failed: {0}")]
    KeyWrap(String),

    /// Invalid header.
    #[error("Invalid header: {0}")]
    Header(String),

    /// Base64url decoding failed.
    #[error("Base64url decoding failed: {0}")]
    Base64(&'static str, base64::DecodeError),

    /// Invalid key material.
    #[error("Invalid key material: {0}")]
    InvalidKeyMaterial(String),

    /// Invalid key type.
    #[error("Invalid key type: {0}")]
    InvalidKeyType(String),

    /// Invalid curve.
    #[error("Invalid curve: {0}")]
    InvalidCurve(String),

    /// Unsupported algorithm.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Missing required field.
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid JWE structure.
    #[error("Invalid JWE structure: {0}")]
    InvalidStructure(String),

    /// Authentication failed.
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Message tampering detected.
    #[error("Message tampering detected")]
    TamperingDetected,

    /// DID resolution failed.
    #[error("DID resolution failed: {0}")]
    DidResolution(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = JweError::KeyAgreement("ECDH failed".to_string());
        assert_eq!(err.to_string(), "Key agreement failed: ECDH failed");

        let err = JweError::AuthenticationFailed;
        assert_eq!(err.to_string(), "Authentication failed");
    }

    #[test]
    fn test_error_conversion() {
        let err = JweError::InvalidKeyMaterial("Invalid key length".to_string());
        let _: Box<dyn std::error::Error> = Box::new(err);
    }
} 