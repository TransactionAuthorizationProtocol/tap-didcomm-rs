//! Plugin system for `DIDComm` operations.
//!
//! This module defines traits that plugins must implement to provide DID resolution
//! and cryptographic operations. Implementations of these traits can be provided to
//! customize the behavior of `DIDComm` operations.
//!
//! The main traits are:
//! - [`DIDResolver`] - For resolving DIDs to DID documents
//! - [`Signer`] - For signing messages
//! - [`Encryptor`] - For encrypting/decrypting messages
//!
//! These can be combined into a single implementation of the
//! [`DIDCommPlugin`] trait to provide a complete `DIDComm` implementation.
//!
//! # Guidelines for plugin implementations
//!
//! - Follow `DIDComm` v2 specifications
//! - Handle errors gracefully
//! - Document security considerations
//! - Validate inputs
//! - Use secure cryptographic primitives
//!
//! # Plugin Architecture
//!
//! The plugin system consists of three main traits:
//! - [`DIDResolver`]: For resolving DIDs to DID Documents
//! - [`Signer`]: For message signing and signature verification
//! - [`Encryptor`]: For message encryption and decryption
//!
//! These traits can be implemented individually or combined through the
//! [`DIDCommPlugin`] trait to provide a complete DIDComm implementation.
//!
//! # Examples
//!
//! Implementing a custom plugin:
//!
//! ```rust,no_run
//! use tap_didcomm_core::plugin::{DIDCommPlugin, DIDResolver, Signer, Encryptor};
//! use tap_didcomm_core::{Result, DIDDocument};
//!
//! struct CustomPlugin {
//!     // Plugin state...
//! }
//!
//! #[async_trait::async_trait]
//! impl DIDResolver for CustomPlugin {
//!     async fn resolve(&self, did: &str) -> Result<DIDDocument> {
//!         // Implement DID resolution...
//!         todo!()
//!     }
//! }
//!
//! #[async_trait::async_trait]
//! impl Signer for CustomPlugin {
//!     async fn sign(&self, data: &[u8], key_id: &str) -> Result<Vec<u8>> {
//!         // Implement signing...
//!         todo!()
//!     }
//!
//!     async fn verify(&self, data: &[u8], signature: &[u8], key_id: &str) -> Result<bool> {
//!         // Implement verification...
//!         todo!()
//!     }
//! }
//!
//! #[async_trait::async_trait]
//! impl Encryptor for CustomPlugin {
//!     async fn encrypt(&self, data: &[u8], recipients: &[&str], sender: Option<&str>) -> Result<Vec<u8>> {
//!         // Implement encryption...
//!         todo!()
//!     }
//!
//!     async fn decrypt(&self, data: &[u8], recipient: &str) -> Result<Vec<u8>> {
//!         // Implement decryption...
//!         todo!()
//!     }
//! }
//!
//! impl DIDCommPlugin for CustomPlugin {
//!     fn resolver(&self) -> &dyn DIDResolver { self }
//!     fn signer(&self) -> &dyn Signer { self }
//!     fn encryptor(&self) -> &dyn Encryptor { self }
//! }
//! ```
//!
//! Using a plugin:
//!
//! ```rust,no_run
//! use tap_didcomm_core::{Message, PackingType};
//! use tap_didcomm_core::plugin::DIDCommPlugin;
//!
//! async fn send_message(plugin: &impl DIDCommPlugin, message: Message) -> tap_didcomm_core::Result<()> {
//!     // Resolve recipient DID
//!     let did_doc = plugin.resolver().resolve(&message.to[0]).await?;
//!
//!     // Sign the message
//!     let signature = plugin.signer().sign(&message.to_bytes()?, &message.from).await?;
//!
//!     // Encrypt for recipient
//!     let encrypted = plugin.encryptor()
//!         .encrypt(&message.to_bytes()?, &[&message.to[0]], Some(&message.from))
//!         .await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Security Considerations
//!
//! When implementing plugins:
//! - Use secure cryptographic algorithms
//! - Properly handle key material
//! - Validate all inputs
//! - Handle errors securely
//! - Follow DIDComm v2 specifications
//! - Test implementations thoroughly
//! - Consider side-channel attacks

use crate::error::Result;
use async_trait::async_trait;

/// Resolves DIDs to DID Documents.
#[async_trait]
pub trait DIDResolver: Send + Sync {
    /// Resolves a DID to a DID Document
    async fn resolve(&self, did: &str) -> crate::error::Result<String>;
}

/// Signs and verifies messages.
#[async_trait]
pub trait Signer: Send + Sync {
    /// Signs data using a specified key.
    ///
    /// # Arguments
    /// * `message` - The data to sign
    /// * `from` - The key ID to use for signing
    ///
    /// # Returns
    /// The signature or an error
    ///
    /// # Errors
    /// - If the key is not found
    /// - If signing fails
    /// - If the data is invalid
    async fn sign(&self, message: &[u8], from: &str) -> Result<Vec<u8>>;

    /// Verifies a signature.
    ///
    /// # Arguments
    /// * `message` - The original data that was signed
    /// * `signature` - The signature to verify
    /// * `from` - The key ID to use for verification
    ///
    /// # Returns
    /// Whether the signature is valid or an error
    ///
    /// # Errors
    /// - If the key is not found
    /// - If verification fails
    /// - If the data or signature is invalid
    async fn verify(&self, message: &[u8], signature: &[u8], from: &str) -> Result<bool>;
}

/// Encrypts and decrypts messages.
#[async_trait]
pub trait Encryptor: Send + Sync {
    /// Encrypts data for one or more recipients.
    ///
    /// # Arguments
    /// * `message` - The data to encrypt
    /// * `to` - The recipient DIDs
    /// * `from` - Optional sender DID for authenticated encryption
    ///
    /// # Returns
    /// The encrypted data or an error
    ///
    /// # Errors
    /// - If recipient keys cannot be resolved
    /// - If encryption fails
    /// - If the data is invalid
    async fn encrypt(&self, message: &[u8], to: &[&str], from: Option<&str>) -> Result<Vec<u8>>;

    /// Decrypts data.
    ///
    /// # Arguments
    /// * `message` - The encrypted data
    /// * `recipient` - The recipient DID
    ///
    /// # Returns
    /// The decrypted data or an error
    ///
    /// # Errors
    /// - If the recipient key cannot be found
    /// - If decryption fails
    /// - If the data is invalid
    async fn decrypt(&self, message: &[u8], recipient: &str) -> Result<Vec<u8>>;
}

/// A `DIDComm` plugin that provides DID resolution and cryptographic operations.
pub trait DIDCommPlugin: DIDResolver + Signer + Encryptor {
    /// Gets the DID resolver implementation.
    fn resolver(&self) -> &dyn DIDResolver;

    /// Gets the signer implementation.
    fn signer(&self) -> &dyn Signer;

    /// Gets the encryptor implementation.
    fn encryptor(&self) -> &dyn Encryptor;
}

/// A collection of DIDComm plugin implementations.
///
/// This trait provides access to DID resolution and signing operations
/// needed for DIDComm message handling.
#[async_trait::async_trait]
pub trait DIDCommPlugins {
    /// Resolves a DID to its associated key material.
    ///
    /// # Arguments
    /// * `did` - The DID to resolve
    ///
    /// # Returns
    /// The key bytes associated with the DID
    ///
    /// # Errors
    /// Returns an error if:
    /// - DID resolution fails
    /// - Key extraction fails
    async fn resolve_did(&self, did: &str) -> crate::error::Result<Vec<u8>>;

    /// Gets a signer implementation for a specific DID.
    ///
    /// # Arguments
    /// * `did` - The DID to get a signer for
    ///
    /// # Returns
    /// A boxed signer implementation
    ///
    /// # Errors
    /// Returns an error if:
    /// - DID is invalid
    /// - No signer is available for the DID
    async fn get_signer(&self, did: &str) -> crate::error::Result<Box<dyn Signer>>;
}

/// Test implementations and mock plugins for testing DIDComm functionality.
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::Error;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    /// A mock plugin implementation for testing that provides simple base64 operations
    /// as stand-ins for actual cryptographic operations.
    ///
    /// This mock implementation:
    /// - Uses base64 encoding/decoding for encryption/decryption
    /// - Returns a simple JSON structure for DID resolution
    /// - Uses base64 encoding for signatures
    pub struct MockTestPlugin;

    #[async_trait]
    impl DIDResolver for MockTestPlugin {
        async fn resolve(&self, _did: &str) -> crate::error::Result<String> {
            Ok(r#"{"id":"did:example:123"}"#.to_string())
        }
    }

    #[async_trait]
    impl Signer for MockTestPlugin {
        async fn sign(&self, message: &[u8], _from: &str) -> Result<Vec<u8>> {
            Ok(STANDARD.encode(message).into_bytes())
        }

        async fn verify(&self, message: &[u8], signature: &[u8], _from: &str) -> Result<bool> {
            Ok(message == signature)
        }
    }

    #[async_trait]
    impl Encryptor for MockTestPlugin {
        async fn encrypt(
            &self,
            message: &[u8],
            _to: &[&str],
            _from: Option<&str>,
        ) -> Result<Vec<u8>> {
            Ok(STANDARD.encode(message).into_bytes())
        }

        async fn decrypt(&self, message: &[u8], _recipient: &str) -> Result<Vec<u8>> {
            STANDARD
                .decode(message)
                .map_err(|e| Error::Base64(e.to_string()))
        }
    }

    impl DIDCommPlugin for MockTestPlugin {
        fn resolver(&self) -> &dyn DIDResolver {
            self
        }

        fn signer(&self) -> &dyn Signer {
            self
        }

        fn encryptor(&self) -> &dyn Encryptor {
            self
        }
    }

    #[tokio::test]
    async fn test_plugin_mock() {
        let plugin = MockTestPlugin;
        let message = b"test message";

        // Test encryption/decryption
        let encrypted = plugin
            .encryptor()
            .encrypt(message, &["did:example:123"], None)
            .await
            .unwrap();
        let decrypted = plugin
            .encryptor()
            .decrypt(&encrypted, "did:example:123")
            .await
            .unwrap();
        assert_eq!(message, decrypted.as_slice());

        // Test signing/verification
        let signature = plugin
            .signer()
            .sign(message, "did:example:123")
            .await
            .unwrap();
        let valid = plugin
            .signer()
            .verify(message, &signature, "did:example:123")
            .await
            .unwrap();
        assert!(valid);

        // Test DID resolution
        let doc = plugin.resolver().resolve("did:example:123").await.unwrap();
        assert!(doc.contains("did:example:123"));
    }
}
