//! Common types for JWE operations.
//!
//! This module provides the core types used for JSON Web Encryption (JWE)
//! operations in the `DIDComm` v2 protocol, including key agreement algorithms,
//! content encryption algorithms, and curve types.
//!
//! # Security Considerations
//!
//! - Use appropriate algorithms based on security requirements
//! - Follow key management best practices
//! - Handle errors appropriately without leaking sensitive information
//! - Validate all inputs before processing

use serde::{Deserialize, Serialize};

/// Key agreement algorithms supported for JWE.
///
/// These algorithms are used to establish shared secrets between
/// the sender and recipient(s) of an encrypted message.
///
/// # Security Considerations
///
/// - `ECDH-ES+A256KW` provides anonymous encryption (`AnonCrypt`)
/// - `ECDH-1PU+A256KW` provides authenticated encryption (`AuthCrypt`)
/// - Both use AES key wrapping for the content encryption key
///
/// # Examples
///
/// ```rust
/// use tap_didcomm_core::jwe::types::KeyAgreementAlgorithm;
///
/// let alg = KeyAgreementAlgorithm::EcdhEsA256kw;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum KeyAgreementAlgorithm {
    /// ECDH-ES with AES key wrap (`AnonCrypt`)
    EcdhEsA256kw,
    /// ECDH-1PU with AES key wrap (`AuthCrypt`)
    Ecdh1puA256kw,
}

/// Content encryption algorithms supported for JWE.
///
/// These algorithms are used to encrypt the actual message content
/// using the key derived from the key agreement process.
///
/// # Security Considerations
///
/// - `A256CBC-HS512` provides authenticated encryption with HMAC
/// - `A256GCM` provides authenticated encryption with GCM
/// - `XC20P` (`XChaCha20-Poly1305`) provides authenticated encryption
///   with modern ChaCha20-Poly1305
///
/// # Examples
///
/// ```rust
/// use tap_didcomm_core::jwe::types::ContentEncryptionAlgorithm;
///
/// let alg = ContentEncryptionAlgorithm::A256Gcm;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ContentEncryptionAlgorithm {
    /// AES-256-CBC with HMAC-SHA-512 for authentication
    A256CbcHs512,
    /// AES-256-GCM
    A256Gcm,
    /// XChaCha20-Poly1305
    Xc20P,
}

impl std::fmt::Display for ContentEncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A256CbcHs512 => write!(f, "A256CBC-HS512"),
            Self::A256Gcm => write!(f, "A256GCM"),
            Self::Xc20P => write!(f, "XC20P"),
        }
    }
}

/// Elliptic curves supported for ECDH key agreement.
///
/// Both NIST curves and modern curves (`X25519`) are supported
/// to ensure broad compatibility and high security.
///
/// # Security Considerations
///
/// - `X25519` is recommended for best security and performance
/// - NIST curves are supported for compatibility
/// - All curves provide at least 128 bits of security
///
/// # Examples
///
/// ```rust
/// use tap_didcomm_core::jwe::types::EcdhCurve;
///
/// let curve = EcdhCurve::X25519;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EcdhCurve {
    /// X25519 curve (Curve25519)
    X25519,
    /// NIST P-256 curve
    P256,
    /// NIST P-384 curve
    P384,
    /// NIST P-521 curve
    P521,
}

impl std::fmt::Display for EcdhCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X25519 => write!(f, "X25519"),
            Self::P256 => write!(f, "P-256"),
            Self::P384 => write!(f, "P-384"),
            Self::P521 => write!(f, "P-521"),
        }
    }
}
