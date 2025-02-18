//! Common types for JWE operations.

use serde::{Deserialize, Serialize};

/// Key agreement algorithms supported for JWE.
///
/// These algorithms are used to establish shared secrets between
/// the sender and recipient(s) of an encrypted message.
///
/// # Security Considerations
///
/// - ECDH-ES+A256KW provides anonymous encryption (anoncrypt)
/// - ECDH-1PU+A256KW provides authenticated encryption (authcrypt)
/// - Both use AES key wrapping for the content encryption key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum KeyAgreementAlgorithm {
    /// ECDH-ES with AES key wrap (anoncrypt)
    EcdhEsA256kw,
    /// ECDH-1PU with AES key wrap (authcrypt)
    Ecdh1puA256kw,
}

/// Content encryption algorithms supported for JWE.
///
/// These algorithms are used to encrypt the actual message content
/// using the key derived from the key agreement process.
///
/// # Security Considerations
///
/// - A256CBC-HS512 provides authenticated encryption with HMAC
/// - A256GCM provides authenticated encryption with GCM
/// - XC20P (XChaCha20-Poly1305) provides authenticated encryption
///   with modern ChaCha20-Poly1305
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
/// Both NIST curves and modern curves (X25519) are supported
/// to ensure broad compatibility and high security.
///
/// # Security Considerations
///
/// - X25519 is recommended for best security and performance
/// - NIST curves are supported for compatibility
/// - All curves provide at least 128 bits of security
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
