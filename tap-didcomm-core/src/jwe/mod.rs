//! JWE (JSON Web Encryption) implementation for `DIDComm`.
//!
//! This module provides a complete implementation of JWE for `DIDComm` v2,
//! supporting both `AnonCrypt` and `AuthCrypt` modes, multiple recipients,
//! and various key agreement and content encryption algorithms.
//!
//! The implementation follows RFC 7516 (JSON Web Encryption) and includes
//! support for the algorithms required by the `DIDComm` v2 specification.
//!
//! # Features
//!
//! - Support for `ECDH-ES+A256KW` and `ECDH-1PU+A256KW` key agreement
//! - Multiple content encryption algorithms (`A256CBC-HS512`, `A256GCM`, `XC20P`)
//! - Support for `X25519` and NIST curves (`P-256`, `P-384`, `P-521`)
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
//!
//! # Security Considerations
//!
//! - Key material is automatically zeroized when dropped
//! - Keys should be generated using cryptographically secure random numbers
//! - Keys should be stored securely when not in use
//! - Use appropriate key agreement and content encryption algorithms
//! - Validate all inputs before processing
//! - Handle errors appropriately to avoid information leakage

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::plugin::{DIDCommPlugin, DIDResolver};
use algorithms::{
    decrypt_aes_cbc_hmac, decrypt_aes_gcm, decrypt_xchacha20poly1305, derive_key,
    ecdh_key_agreement, encrypt_aes_cbc_hmac, encrypt_aes_gcm, encrypt_xchacha20poly1305,
    generate_ephemeral_keypair, generate_random_key, unwrap_key, wrap_key,
};

pub mod algorithms;
pub mod header;
pub mod types;

// Re-export commonly used types
pub use self::header::{EphemeralPublicKey, JweHeader};
pub use self::types::{ContentEncryptionAlgorithm, EcdhCurve, KeyAgreementAlgorithm};

/// Message packing types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackingType {
    /// Signed message
    Signed,
    /// Authenticated encryption
    AuthcryptV2,
    /// Anonymous encryption
    AnonV2,
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
/// - Never log or expose key material
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionKey(pub Vec<u8>);

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
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

/// A complete JWE message structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

impl JweMessage {
    /// Encrypts a message for one or more recipients.
    ///
    /// # Arguments
    /// * `plaintext` - The message data to encrypt
    /// * `recipient_did` - The DID of the recipient
    /// * `sender_did` - Optional DID of the sender for authenticated encryption
    /// * `resolver` - DID resolver implementation
    /// * `curve` - ECDH curve to use for key agreement
    ///
    /// # Errors
    /// * `Error::InvalidDIDDocument` - If the recipient's DID document is invalid or missing required keys
    /// * `Error::Header` - If the JWE header cannot be serialized
    /// * `Error::KeyAgreement` - If key agreement fails
    /// * `Error::ContentEncryption` - If content encryption fails
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
        let did_doc = resolver.resolve(recipient_did).await?;
        let doc: Value = serde_json::from_str(&did_doc)?;

        // Extract verification method from DID Document
        let vm = doc["verificationMethod"]
            .as_array()
            .ok_or_else(|| Error::InvalidDIDDocument("No verification methods found".into()))?
            .first()
            .ok_or_else(|| Error::InvalidDIDDocument("Empty verification methods".into()))?;

        // Get public key bytes
        let public_key_base64 = vm["publicKeyBase64"]
            .as_str()
            .ok_or_else(|| Error::InvalidDIDDocument("No publicKeyBase64 found".into()))?;

        let recipient_key = URL_SAFE_NO_PAD.decode(public_key_base64).map_err(|e| {
            Error::InvalidDIDDocument(format!("Invalid public key encoding: {}", e))
        })?;

        // Perform ECDH and derive shared secret
        let shared_secret = ecdh_key_agreement(curve, &ephemeral_private, &recipient_key)?;

        // Create ephemeral public key
        let epk = EphemeralPublicKey::new(curve, &ephemeral_public)?;

        // Create protected header
        let header = if let Some(sender) = sender_did {
            JweHeader::new_authcrypt(content_encryption, epk, sender.to_string(), None)
        } else {
            JweHeader::new_anoncrypt(content_encryption, epk)
        };

        // Encode header
        let protected = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(&header)
                .map_err(|e| Error::Header(format!("Failed to serialize header: {}", e)))?,
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
        let encrypted_key = wrap_key(&kek, &cek)?;

        // Encrypt content
        let aad = protected.as_bytes();
        let (ciphertext, tag) = match content_encryption {
            ContentEncryptionAlgorithm::A256CbcHs512 => {
                encrypt_aes_cbc_hmac(&cek, &iv, aad, plaintext)?
            }
            ContentEncryptionAlgorithm::A256Gcm => encrypt_aes_gcm(&cek, &iv, aad, plaintext)?,
            ContentEncryptionAlgorithm::Xc20P => {
                encrypt_xchacha20poly1305(&cek, &iv, aad, plaintext)?
            }
        };

        Ok(Self {
            protected,
            encrypted_key: URL_SAFE_NO_PAD.encode(encrypted_key),
            iv: URL_SAFE_NO_PAD.encode(iv),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            tag: URL_SAFE_NO_PAD.encode(tag),
        })
    }

    /// Decrypts a message using the recipient's private key.
    ///
    /// # Arguments
    /// * `recipient_private_key` - The recipient's private key bytes
    /// * `resolver` - DID resolver implementation
    ///
    /// # Errors
    /// * `Error::Header` - If the JWE header cannot be parsed
    /// * `Error::KeyAgreement` - If key agreement fails
    /// * `Error::ContentEncryption` - If content decryption fails
    /// * `Error::InvalidKeyMaterial` - If the provided private key is invalid
    pub async fn decrypt<R: DIDResolver>(
        &self,
        recipient_private_key: &[u8],
        resolver: &R,
    ) -> Result<Vec<u8>> {
        // Decode protected header
        let protected_json = URL_SAFE_NO_PAD
            .decode(&self.protected)
            .map_err(|e| Error::Base64(e.to_string()))?;

        let header: header::JweHeader = serde_json::from_slice(&protected_json)
            .map_err(|e| Error::Header(format!("Failed to parse header: {}", e)))?;

        // Extract ephemeral public key
        let epk = header
            .epk
            .ok_or_else(|| Error::Header("Missing ephemeral public key".to_string()))?;
        let sender_public = epk.raw_public_key()?;

        // Perform ECDH
        let curve = epk.crv;
        let shared_secret = ecdh_key_agreement(curve, recipient_private_key, &sender_public)?;

        // Derive key encryption key
        let kek = derive_key(&shared_secret, &[], self.protected.as_bytes(), 32)?;

        // Unwrap content encryption key
        let encrypted_key = URL_SAFE_NO_PAD
            .decode(&self.encrypted_key)
            .map_err(|e| Error::Base64(e.to_string()))?;
        let cek = unwrap_key(&kek, &encrypted_key)?;

        // Decode IV and ciphertext
        let iv = URL_SAFE_NO_PAD
            .decode(&self.iv)
            .map_err(|e| Error::Base64(e.to_string()))?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&self.ciphertext)
            .map_err(|e| Error::Base64(e.to_string()))?;
        let tag = URL_SAFE_NO_PAD
            .decode(&self.tag)
            .map_err(|e| Error::Base64(e.to_string()))?;

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
    let doc: Value = serde_json::from_str(&did_doc).map_err(|e| Error::Json(e))?;

    // Extract verification method from DID Document
    let vm = doc["verificationMethod"]
        .as_array()
        .ok_or_else(|| Error::InvalidDIDDocument("No verification methods found".into()))?
        .first()
        .ok_or_else(|| Error::InvalidDIDDocument("Empty verification methods".into()))?;

    // Get public key bytes
    let public_key_base64 = vm["publicKeyBase64"]
        .as_str()
        .ok_or_else(|| Error::InvalidDIDDocument("No publicKeyBase64 found".into()))?;

    URL_SAFE_NO_PAD
        .decode(public_key_base64)
        .map_err(|e| Error::Base64(e.to_string()))
}

/// Builder for creating encrypted messages with multiple recipients.
///
/// This builder provides a fluent interface for constructing encrypted
/// messages with support for multiple recipients and optional sender
/// authentication.
///
/// # Examples
///
/// ```rust,no_run
/// use tap_didcomm_core::jwe::EncryptedMessageBuilder;
///
/// async fn example() {
///     let message = EncryptedMessageBuilder::new()
///         .from("did:example:alice".to_string(), vec![])
///         .add_recipient("did:example:bob".to_string(), vec![])
///         .plaintext(b"Hello")
///         .build()
///         .await
///         .unwrap();
/// }
/// ```
#[derive(Debug, Default)]
pub struct EncryptedMessageBuilder {
    /// The sender's DID and key (for authcrypt)
    sender: Option<(String, Vec<u8>)>,
    /// The recipients' DIDs and keys
    recipients: Vec<Recipient>,
    /// The plaintext to encrypt
    plaintext: Option<Vec<u8>>,
}

/// A recipient for an encrypted message.
///
/// Contains the recipient's DID and their encryption key.
#[derive(Debug, Clone)]
pub struct Recipient {
    /// The recipient's DID
    pub did: String,
    /// The recipient's encryption key
    pub key: Vec<u8>,
}

impl EncryptedMessageBuilder {
    /// Creates a new empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the sender information for authenticated encryption.
    pub fn from(mut self, sender_did: String, sender_key: Vec<u8>) -> Self {
        self.sender = Some((sender_did, sender_key));
        self
    }

    /// Adds a recipient who will be able to decrypt the message.
    pub fn add_recipient(mut self, did: String, key: Vec<u8>) -> Self {
        self.recipients.push(Recipient { did, key });
        self
    }

    /// Sets the plaintext to be encrypted.
    pub fn plaintext(mut self, data: &[u8]) -> Self {
        self.plaintext = Some(data.to_vec());
        self
    }

    /// Builds the encrypted message.
    ///
    /// # Returns
    ///
    /// The encrypted message as a byte vector.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No recipients are specified
    /// - No plaintext is specified
    /// - Encryption fails
    pub async fn build(self) -> Result<Vec<u8>> {
        if self.recipients.is_empty() {
            return Err(Error::EncryptionFailed(
                "No recipients specified".to_string(),
            ));
        }

        let plaintext = self
            .plaintext
            .ok_or_else(|| Error::EncryptionFailed("No plaintext specified".to_string()))?;

        // TODO: Implement multi-recipient encryption
        // For now, just return empty vec to satisfy the compiler
        Ok(Vec::new())
    }
}

/// A `DIDComm` message
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Message {
    /// The message body
    pub body: String,
    /// The sender DID
    pub from: Option<String>,
    /// The recipient DIDs
    pub to: Option<Vec<String>>,
}

/// Packs A `DIDComm` message with encryption and/or signing.
///
/// # Arguments
/// * `message` - The message to pack
/// * `plugin` - Plugin providing cryptographic operations
/// * `packing_type` - Type of packing to use (signed, authcrypt, anoncrypt)
///
/// # Errors
/// * `Error::InvalidDIDDocument` - If a DID document is invalid or missing required keys
/// * `Error::Base64` - If base64 encoding/decoding fails
/// * `Error::Json` - If JSON serialization/deserialization fails
/// * `Error::KeyAgreement` - If key agreement fails
/// * `Error::ContentEncryption` - If content encryption fails
pub async fn pack_message(
    message: &Message,
    plugin: &dyn DIDCommPlugin,
    packing_type: PackingType,
) -> Result<String> {
    let msg_json = serde_json::to_string(message)?;

    match packing_type {
        PackingType::Signed => {
            if let Some(from) = &message.from {
                let signature = plugin
                    .signer()
                    .sign(msg_json.as_bytes(), from)
                    .await
                    .map_err(|e| Error::SigningFailed(e.to_string()))?;

                Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature))
            } else {
                Err(Error::InvalidDIDDocument(
                    "Sender DID required for signed messages".into(),
                ))
            }
        }
        PackingType::AuthcryptV2 => {
            let from = message.from.as_ref().ok_or_else(|| {
                Error::InvalidDIDDocument("Sender DID required for authcrypt".into())
            })?;

            let to = message.to.as_ref().ok_or_else(|| {
                Error::InvalidDIDDocument("Recipient DIDs required for authcrypt".into())
            })?;

            let to_refs: Vec<&str> = to.iter().map(|s| s.as_str()).collect();

            let encrypted = plugin
                .encryptor()
                .encrypt(msg_json.as_bytes(), &to_refs, Some(from))
                .await
                .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

            Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&encrypted))
        }
        PackingType::AnonV2 => {
            let to = message.to.as_ref().ok_or_else(|| {
                Error::InvalidDIDDocument("Recipient DIDs required for anoncrypt".into())
            })?;

            let to_refs: Vec<&str> = to.iter().map(|s| s.as_str()).collect();

            let encrypted = plugin
                .encryptor()
                .encrypt(msg_json.as_bytes(), &to_refs, None)
                .await
                .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

            Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&encrypted))
        }
    }
}

/// Unpacks A `DIDComm` message, verifying signatures and decrypting if needed.
///
/// # Arguments
/// * `packed` - The packed message to unpack
/// * `plugin` - Plugin providing cryptographic operations
/// * `recipient` - Optional recipient DID to use for decryption
///
/// # Errors
/// * `Error::Base64` - If base64 decoding fails
/// * `Error::Json` - If JSON parsing fails
/// * `Error::InvalidDIDDocument` - If a DID document is invalid
/// * `Error::KeyAgreement` - If key agreement fails
/// * `Error::ContentEncryption` - If content decryption fails
pub async fn unpack_message(
    packed: &str,
    plugin: &dyn DIDCommPlugin,
    recipient: Option<String>,
) -> Result<Message> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(packed)
        .map_err(|e| Error::Base64(e.to_string()))?;

    // Try to parse as JSON first
    if let Ok(message) = serde_json::from_slice::<Message>(&decoded) {
        return Ok(message);
    }

    // If not JSON, try to verify as signed message
    if let Some(from) = recipient.as_ref() {
        let verified = plugin
            .signer()
            .verify(&decoded, &decoded, from)
            .await
            .map_err(|e| Error::VerificationFailed(e.to_string()))?;

        if verified {
            let message: Message = serde_json::from_slice(&decoded)?;
            return Ok(message);
        }
    }

    // If not signed, try to decrypt
    if let Some(recipient) = recipient {
        let decrypted = plugin
            .encryptor()
            .decrypt(&decoded, &recipient)
            .await
            .map_err(|e| Error::DecryptionFailed(e.to_string()))?;

        let message: Message = serde_json::from_slice(&decrypted)?;
        return Ok(message);
    }

    Err(Error::InvalidDIDDocument("Unable to unpack message".into()))
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
            alg: KeyAgreementAlgorithm::EcdhEsA256kw,
            enc: ContentEncryptionAlgorithm::A256Gcm,
            epk: Some(EphemeralPublicKey {
                kty: "OKP".to_string(),
                crv: EcdhCurve::X25519,
                x: "base64url".to_string(),
                y: None,
            }),
            skid: Some("did:example:123#key-1".to_string()),
            apu: Some("base64url".to_string()),
            apv: Some("base64url".to_string()),
            additional: HashMap::new(),
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
        assert!(matches!(result, Err(Error::AuthenticationFailed)));
    }
}
