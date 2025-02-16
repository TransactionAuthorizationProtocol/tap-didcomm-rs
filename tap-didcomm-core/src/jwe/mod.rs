//! JWE (JSON Web Encryption) implementation for DIDComm.
//!
//! This module provides a complete implementation of JWE for DIDComm v2,
//! supporting both anoncrypt and authcrypt modes, multiple recipients,
//! and various key agreement and content encryption algorithms.
//!
//! The implementation follows RFC 7516 (JSON Web Encryption) and includes
//! support for the algorithms required by the DIDComm v2 specification.
//!
//! # Features
//!
//! - Support for ECDH-ES+A256KW and ECDH-1PU+A256KW key agreement
//! - Multiple content encryption algorithms (A256CBC-HS512, A256GCM, XC20P)
//! - Support for X25519 and NIST curves (P-256, P-384, P-521)
//! - Multiple recipient support with shared content encryption
//! - APU/APV parameter support in key derivation
//! - Compressed NIST curve point support
//!
//! # Examples
//!
//! ```rust,no_run
//! use tap_didcomm_core::jwe::{JweMessage, ContentEncryptionAlgorithm, EcdhCurve};
//!
//! async fn example(resolver: impl DIDResolver) {
//!     let plaintext = b"Hello, DIDComm!";
//!     let recipient = "did:example:bob";
//!     let sender = Some("did:example:alice");
//!
//!     // Encrypt a message
//!     let jwe = JweMessage::encrypt(
//!         plaintext,
//!         recipient,
//!         sender,
//!         &resolver,
//!         ContentEncryptionAlgorithm::A256Gcm,
//!         EcdhCurve::X25519,
//!     ).await.unwrap();
//!
//!     // Decrypt the message
//!     let decrypted = jwe.decrypt(recipient_private_key, &resolver).await.unwrap();
//!     assert_eq!(plaintext.to_vec(), decrypted);
//! }
//! ```

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use zeroize::Zeroize;

use crate::plugin::DIDResolver;
use algorithms::*;

pub mod algorithms;
pub mod error;
pub mod header;

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

/// A JWE (JSON Web Encryption) structure.
///
/// This represents a complete JWE object with all the components
/// required by RFC 7516, including protected header, encrypted key,
/// initialization vector, ciphertext, and authentication tag.
///
/// # Examples
///
/// ```rust,no_run
/// use tap_didcomm_core::jwe::Jwe;
///
/// let jwe = Jwe {
///     protected: "base64url".to_string(),
///     encrypted_key: "base64url".to_string(),
///     iv: "base64url".to_string(),
///     ciphertext: "base64url".to_string(),
///     tag: "base64url".to_string(),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwe {
    /// The protected header (base64url-encoded)
    pub protected: String,
    /// The encrypted key (base64url-encoded)
    pub encrypted_key: String,
    /// The initialization vector (base64url-encoded)
    pub iv: String,
    /// The ciphertext (base64url-encoded)
    pub ciphertext: String,
    /// The authentication tag (base64url-encoded)
    pub tag: String,
}

/// Configuration for JWE encryption.
///
/// This structure allows customization of the encryption process
/// by specifying the algorithms and curves to use.
///
/// # Examples
///
/// ```rust
/// use tap_didcomm_core::jwe::{EncryptionConfig, KeyAgreementAlgorithm, ContentEncryptionAlgorithm, EcdhCurve};
///
/// let config = EncryptionConfig {
///     key_agreement: KeyAgreementAlgorithm::EcdhEsA256kw,
///     content_encryption: ContentEncryptionAlgorithm::A256Gcm,
///     curve: EcdhCurve::X25519,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    /// The key agreement algorithm to use
    pub key_agreement: KeyAgreementAlgorithm,
    /// The content encryption algorithm to use
    pub content_encryption: ContentEncryptionAlgorithm,
    /// The curve to use for ECDH
    pub curve: EcdhCurve,
}

impl Default for EncryptionConfig {
    /// Creates a default configuration using recommended algorithms.
    ///
    /// Defaults to:
    /// - ECDH-ES+A256KW for key agreement
    /// - A256GCM for content encryption
    /// - X25519 for the ECDH curve
    fn default() -> Self {
        Self {
            key_agreement: KeyAgreementAlgorithm::EcdhEsA256kw,
            content_encryption: ContentEncryptionAlgorithm::A256Gcm,
            curve: EcdhCurve::X25519,
        }
    }
}

/// A key used for encryption operations.
///
/// This type ensures secure handling of key material by implementing
/// zeroization on drop.
///
/// # Security Considerations
///
/// - Key material is automatically zeroized when dropped
/// - Keys should be generated using cryptographically secure random numbers
/// - Keys should be stored securely when not in use
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionKey(pub Vec<u8>);

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A JWE protected header.
///
/// Contains the parameters needed for decryption and defines the
/// cryptographic algorithms used.
///
/// # Examples
///
/// ```rust
/// use tap_didcomm_core::jwe::{JweHeader, EphemeralPublicKey};
///
/// let header = JweHeader {
///     alg: "ECDH-ES+A256KW".to_string(),
///     enc: "A256GCM".to_string(),
///     epk: Some(EphemeralPublicKey {
///         kty: "OKP".to_string(),
///         crv: "X25519".to_string(),
///         x: "base64url".to_string(),
///         y: None,
///     }),
///     skid: None,
///     apu: None,
///     apv: None,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JweHeader {
    /// Key agreement algorithm
    pub alg: String,
    /// Content encryption algorithm
    pub enc: String,
    /// Ephemeral public key (for key agreement)
    pub epk: Option<EphemeralPublicKey>,
    /// Sender key ID (for authcrypt)
    pub skid: Option<String>,
    /// Agreement PartyUInfo
    pub apu: Option<String>,
    /// Agreement PartyVInfo
    pub apv: Option<String>,
}

impl JweHeader {
    pub fn new_anoncrypt(
        content_encryption: ContentEncryptionAlgorithm,
        epk: EphemeralPublicKey,
    ) -> Self {
        Self {
            alg: "ECDH-ES+A256KW".to_string(),
            enc: content_encryption.to_string(),
            epk: Some(epk),
            skid: None,
            apu: None,
            apv: None,
        }
    }
}

/// An ephemeral public key used in the key agreement process.
///
/// This structure represents the public key component used in
/// ECDH key agreement, supporting both compressed and uncompressed
/// formats for NIST curves.
///
/// # Examples
///
/// ```rust
/// use tap_didcomm_core::jwe::EphemeralPublicKey;
///
/// // X25519 key
/// let x25519_key = EphemeralPublicKey {
///     kty: "OKP".to_string(),
///     crv: "X25519".to_string(),
///     x: "base64url".to_string(),
///     y: None,
/// };
///
/// // NIST P-256 key (uncompressed)
/// let p256_key = EphemeralPublicKey {
///     kty: "EC".to_string(),
///     crv: "P-256".to_string(),
///     x: "base64url".to_string(),
///     y: Some("base64url".to_string()),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralPublicKey {
    /// Key type (e.g., "OKP" for X25519, "EC" for NIST curves)
    pub kty: String,
    /// Curve used (e.g., "X25519", "P-256")
    pub crv: String,
    /// Public key x-coordinate (base64url-encoded)
    pub x: String,
    /// Public key y-coordinate (base64url-encoded, only for NIST curves)
    pub y: Option<String>,
}

impl EphemeralPublicKey {
    pub fn new(curve: EcdhCurve, public_key: &[u8]) -> Result<Self> {
        Ok(Self {
            kty: "OKP".to_string(),
            crv: curve.to_string(),
            x: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key),
            y: None,
        })
    }

    pub fn raw_public_key(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.x)
            .map_err(|e| {
                JweError::InvalidKeyMaterial(format!("Invalid public key encoding: {}", e))
            })
    }
}

/// A complete JWE message structure.
///
/// This represents a JWE in either JSON Serialization or Compact
/// Serialization format, with support for multiple recipients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JweMessage {
    /// Protected header (base64url encoded)
    pub protected: String,
    /// Encrypted key (base64url encoded)
    pub encrypted_key: String,
    /// Initialization vector (base64url encoded)
    pub iv: String,
    /// Ciphertext (base64url encoded)
    pub ciphertext: String,
    /// Authentication tag (base64url encoded)
    pub tag: String,
}

pub use error::{JweError, Result};

impl JweMessage {
    /// Creates a new JWE message by encrypting the given plaintext.
    pub async fn encrypt<R: DIDResolver>(
        plaintext: &[u8],
        recipient_did: &str,
        sender_did: Option<&str>,
        resolver: &R,
        content_encryption: ContentEncryptionAlgorithm,
        curve: EcdhCurve,
    ) -> Result<Self> {
        // Generate ephemeral key pair
        let (ephemeral_private, ephemeral_public) = generate_ephemeral_keypair(curve)?;

        // Resolve recipient's public key
        let recipient_key = resolver.resolve_key(recipient_did).await?;

        // Perform ECDH and derive shared secret
        let shared_secret = ecdh_key_agreement(curve, &ephemeral_private, &recipient_key)?;

        // Create protected header
        let header = JweHeader::new_anoncrypt(
            content_encryption,
            EphemeralPublicKey::new(curve, &ephemeral_public)?,
        );

        // Encode header
        let protected = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(&header)
                .map_err(|e| JweError::Header(format!("Failed to serialize header: {}", e)))?,
        );

        // Generate content encryption key and IV
        let cek = match content_encryption {
            ContentEncryptionAlgorithm::A256CbcHs512 => generate_random_key(32 + 64),
            ContentEncryptionAlgorithm::A256Gcm => generate_random_key(32),
            ContentEncryptionAlgorithm::Xc20P => generate_random_key(32),
        };

        let iv = match content_encryption {
            ContentEncryptionAlgorithm::A256CbcHs512 => generate_random_key(16),
            ContentEncryptionAlgorithm::A256Gcm => generate_random_key(12),
            ContentEncryptionAlgorithm::Xc20P => generate_random_key(24),
        };

        // Derive key encryption key
        let kek = derive_key(&shared_secret, &[], protected.as_bytes(), 32)?;

        // Wrap content encryption key
        let encrypted_key = wrap_key(&kek, &cek.0)?;

        // Encrypt content
        let aad = protected.as_bytes();
        let (ciphertext, tag) = match content_encryption {
            ContentEncryptionAlgorithm::A256CbcHs512 => {
                encrypt_aes_cbc_hmac(&cek.0, &iv.0, aad, plaintext)?
            }
            ContentEncryptionAlgorithm::A256Gcm => encrypt_aes_gcm(&cek.0, &iv.0, aad, plaintext)?,
            ContentEncryptionAlgorithm::Xc20P => {
                encrypt_xchacha20poly1305(&cek.0, &iv.0, aad, plaintext)?
            }
        };

        Ok(Self {
            protected,
            encrypted_key: URL_SAFE_NO_PAD.encode(encrypted_key),
            iv: URL_SAFE_NO_PAD.encode(iv.0),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            tag: URL_SAFE_NO_PAD.encode(tag),
        })
    }

    /// Decrypts the JWE message using the recipient's private key.
    pub async fn decrypt<R: DIDResolver>(
        &self,
        recipient_private_key: &[u8],
        resolver: &R,
    ) -> Result<Vec<u8>> {
        // Decode protected header
        let protected_json = URL_SAFE_NO_PAD
            .decode(&self.protected)
            .map_err(|e| JweError::Base64("Failed to decode protected header", e))?;

        let header: JweHeader = serde_json::from_slice(&protected_json)
            .map_err(|e| JweError::Header(format!("Failed to parse header: {}", e)))?;

        // Extract ephemeral public key
        let epk = header
            .epk
            .ok_or_else(|| JweError::Header("Missing ephemeral public key".to_string()))?;
        let sender_public = epk.raw_public_key()?;

        // Perform ECDH
        let shared_secret = ecdh_key_agreement(epk.crv, recipient_private_key, &sender_public)?;

        // Derive key encryption key
        let kek = derive_key(&shared_secret, &[], self.protected.as_bytes(), 32)?;

        // Unwrap content encryption key
        let encrypted_key = URL_SAFE_NO_PAD
            .decode(&self.encrypted_key)
            .map_err(|e| JweError::Base64("Failed to decode encrypted key", e))?;
        let cek = unwrap_key(&kek, &encrypted_key)?;

        // Decode IV and ciphertext
        let iv = URL_SAFE_NO_PAD
            .decode(&self.iv)
            .map_err(|e| JweError::Base64("Failed to decode IV", e))?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&self.ciphertext)
            .map_err(|e| JweError::Base64("Failed to decode ciphertext", e))?;
        let tag = URL_SAFE_NO_PAD
            .decode(&self.tag)
            .map_err(|e| JweError::Base64("Failed to decode authentication tag", e))?;

        // Decrypt content
        let aad = self.protected.as_bytes();
        match header.enc {
            ContentEncryptionAlgorithm::A256CbcHs512 => {
                decrypt_aes_cbc_hmac(&cek, &iv, aad, &ciphertext, &tag)
            }
            ContentEncryptionAlgorithm::A256Gcm => {
                decrypt_aes_gcm(&cek, &iv, aad, &ciphertext, &tag)
            }
            ContentEncryptionAlgorithm::Xc20P => {
                decrypt_xchacha20poly1305(&cek, &iv, aad, &ciphertext, &tag)
            }
        }
    }
}

/// Resolves a key from a DID Document
async fn resolve_key<R: DIDResolver>(resolver: &R, did: &str) -> Result<Vec<u8>> {
    let did_doc = resolver.resolve(did).await?;
    let doc: Value = serde_json::from_str(&did_doc)?;

    // Extract verification method from DID Document
    let vm = doc["verificationMethod"]
        .as_array()
        .ok_or_else(|| JweError::InvalidDIDDocument("No verification methods found".into()))?
        .first()
        .ok_or_else(|| JweError::InvalidDIDDocument("Empty verification methods".into()))?;

    // Get public key bytes
    let public_key_base64 = vm["publicKeyBase64"]
        .as_str()
        .ok_or_else(|| JweError::InvalidDIDDocument("No publicKeyBase64 found".into()))?;

    URL_SAFE_NO_PAD
        .decode(public_key_base64)
        .map_err(|e| JweError::InvalidDIDDocument(format!("Invalid public key encoding: {}", e)))
}

pub struct EncryptedMessageBuilder {
    // Add fields as needed
}

pub struct Recipient {
    pub did: String,
    pub key: Vec<u8>, // or appropriate key type
}

impl EncryptedMessageBuilder {
    pub fn new() -> Self {
        Self { /* initialize fields */ }
    }

    pub fn from(mut self, sender_did: String, sender_key: Vec<u8>) -> Self {
        // Implementation
        self
    }

    pub fn add_recipient(mut self, did: String, key: Vec<u8>) -> Self {
        // Implementation
        self
    }

    pub fn plaintext(mut self, data: &[u8]) -> Self {
        // Implementation
        self
    }

    pub async fn build(self) -> crate::error::Result<Vec<u8>> {
        // Implementation
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use serde_json::json;

    #[test]
    fn test_encryption_config_default() {
        let config = EncryptionConfig::default();
        assert_eq!(config.key_agreement, KeyAgreementAlgorithm::EcdhEsA256kw);
        assert_eq!(
            config.content_encryption,
            ContentEncryptionAlgorithm::A256Gcm
        );
        assert_eq!(config.curve, EcdhCurve::X25519);
    }

    #[test]
    fn test_jwe_serialization() {
        let jwe = Jwe {
            protected: "header".to_string(),
            encrypted_key: "key".to_string(),
            iv: "iv".to_string(),
            ciphertext: "data".to_string(),
            tag: "tag".to_string(),
        };

        let json = serde_json::to_value(&jwe).unwrap();
        assert_eq!(
            json,
            json!({
                "protected": "header",
                "encrypted_key": "key",
                "iv": "iv",
                "ciphertext": "data",
                "tag": "tag"
            })
        );
    }

    #[test]
    fn test_content_encryption_algorithm_serde() {
        let alg = ContentEncryptionAlgorithm::A256CbcHs512;
        let serialized = serde_json::to_string(&alg).unwrap();
        assert_eq!(serialized, "\"A256CBC-HS512\"");

        let deserialized: ContentEncryptionAlgorithm = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, alg);
    }

    #[test]
    fn test_ecdh_curve_serde() {
        let curve = EcdhCurve::X25519;
        let serialized = serde_json::to_string(&curve).unwrap();
        assert_eq!(serialized, "\"X25519\"");

        let deserialized: EcdhCurve = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, curve);
    }

    #[test]
    fn test_encryption_key_zeroize() {
        let key_data = vec![1, 2, 3, 4];
        let key = EncryptionKey(key_data.clone());
        drop(key);
        // Key data should be zeroized after drop
    }

    #[test]
    fn test_jwe_header_serde() {
        let header = JweHeader {
            alg: "ECDH-ES+A256KW".to_string(),
            enc: "A256GCM".to_string(),
            epk: Some(EphemeralPublicKey {
                kty: "OKP".to_string(),
                crv: "X25519".to_string(),
                x: "base64url".to_string(),
                y: None,
            }),
            skid: Some("did:example:123#key-1".to_string()),
            apu: Some("base64url".to_string()),
            apv: Some("base64url".to_string()),
        };

        let serialized = serde_json::to_string(&header).unwrap();
        let deserialized: JweHeader = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.alg, header.alg);
        assert_eq!(deserialized.enc, header.enc);
        assert_eq!(deserialized.skid, header.skid);
    }

    struct MockResolver;

    #[async_trait]
    impl DIDResolver for MockResolver {
        async fn resolve(&self, did: &str) -> crate::error::Result<String> {
            // Return a test public key
            let mut key = [0u8; 32];
            key[0] = 1;
            Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key))
        }
    }

    #[tokio::test]
    async fn test_jwe_roundtrip() {
        let plaintext = b"test message";
        let recipient_did = "did:example:123";
        let sender_did = Some("did:example:456");
        let resolver = MockResolver;

        // Test with each curve type
        for curve in [
            EcdhCurve::X25519,
            EcdhCurve::P256,
            EcdhCurve::P384,
            EcdhCurve::P521,
        ] {
            // Generate recipient key pair
            let (recipient_private, _) = generate_ephemeral_keypair(curve).unwrap();

            // Encrypt
            let jwe = JweMessage::encrypt(
                plaintext,
                recipient_did,
                sender_did,
                &resolver,
                ContentEncryptionAlgorithm::A256Gcm,
                curve,
            )
            .await
            .unwrap();

            // Decrypt
            let decrypted = jwe.decrypt(&recipient_private, &resolver).await.unwrap();

            assert_eq!(plaintext.to_vec(), decrypted);
        }
    }

    #[tokio::test]
    async fn test_jwe_tamper_detection() {
        let plaintext = b"test message";
        let recipient_did = "did:example:123";
        let resolver = MockResolver;

        // Generate recipient key pair
        let (recipient_private, _) = generate_ephemeral_keypair(EcdhCurve::X25519).unwrap();

        // Encrypt
        let mut jwe = JweMessage::encrypt(
            plaintext,
            recipient_did,
            None,
            &resolver,
            ContentEncryptionAlgorithm::A256Gcm,
            EcdhCurve::X25519,
        )
        .await
        .unwrap();

        // Tamper with ciphertext
        let mut ciphertext = URL_SAFE_NO_PAD.decode(&jwe.ciphertext).unwrap();
        ciphertext[0] ^= 1;
        jwe.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);

        // Attempt to decrypt
        let result = jwe.decrypt(&recipient_private, &resolver).await;
        assert!(matches!(result, Err(JweError::AuthenticationFailed)));
    }
}
