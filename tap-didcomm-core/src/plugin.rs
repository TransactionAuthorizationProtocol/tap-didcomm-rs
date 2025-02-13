//! Plugin system for DIDComm operations.
//!
//! This module provides the core plugin traits that define the interface for
//! DID resolution, message signing, and encryption operations. Implementations
//! of these traits can be provided to customize the behavior of DIDComm operations.
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

use crate::{DIDDocument, Result};
use async_trait::async_trait;

/// Resolves DIDs to DID Documents.
#[async_trait]
pub trait DIDResolver: Send + Sync {
    /// Resolves a DID to its DID Document.
    ///
    /// # Arguments
    /// * `did` - The DID to resolve (e.g., "did:example:123")
    ///
    /// # Returns
    /// The resolved DID Document or an error
    ///
    /// # Errors
    /// - If the DID is invalid
    /// - If resolution fails
    /// - If the DID Document is invalid
    async fn resolve(&self, did: &str) -> Result<DIDDocument>;
}

/// Signs and verifies messages.
#[async_trait]
pub trait Signer: Send + Sync {
    /// Signs data using a specified key.
    ///
    /// # Arguments
    /// * `data` - The data to sign
    /// * `key_id` - The key ID to use for signing
    ///
    /// # Returns
    /// The signature or an error
    ///
    /// # Errors
    /// - If the key is not found
    /// - If signing fails
    /// - If the data is invalid
    async fn sign(&self, data: &[u8], key_id: &str) -> Result<Vec<u8>>;

    /// Verifies a signature.
    ///
    /// # Arguments
    /// * `data` - The original data that was signed
    /// * `signature` - The signature to verify
    /// * `key_id` - The key ID to use for verification
    ///
    /// # Returns
    /// Whether the signature is valid or an error
    ///
    /// # Errors
    /// - If the key is not found
    /// - If verification fails
    /// - If the data or signature is invalid
    async fn verify(&self, data: &[u8], signature: &[u8], key_id: &str) -> Result<bool>;
}

/// Encrypts and decrypts messages.
#[async_trait]
pub trait Encryptor: Send + Sync {
    /// Encrypts data for one or more recipients.
    ///
    /// # Arguments
    /// * `data` - The data to encrypt
    /// * `recipients` - The recipient DIDs
    /// * `sender` - Optional sender DID for authenticated encryption
    ///
    /// # Returns
    /// The encrypted data or an error
    ///
    /// # Errors
    /// - If recipient keys cannot be resolved
    /// - If encryption fails
    /// - If the data is invalid
    async fn encrypt(
        &self,
        data: &[u8],
        recipients: &[&str],
        sender: Option<&str>,
    ) -> Result<Vec<u8>>;

    /// Decrypts data.
    ///
    /// # Arguments
    /// * `data` - The encrypted data
    /// * `recipient` - The recipient DID
    ///
    /// # Returns
    /// The decrypted data or an error
    ///
    /// # Errors
    /// - If the recipient key cannot be found
    /// - If decryption fails
    /// - If the data is invalid
    async fn decrypt(&self, data: &[u8], recipient: &str) -> Result<Vec<u8>>;
}

/// Combined interface for DIDComm operations.
///
/// This trait combines DID resolution, signing, and encryption capabilities
/// into a single interface. Implementations should provide access to concrete
/// implementations of each capability.
pub trait DIDCommPlugin: Send + Sync {
    /// Gets the DID resolver implementation.
    fn resolver(&self) -> &dyn DIDResolver;

    /// Gets the signer implementation.
    fn signer(&self) -> &dyn Signer;

    /// Gets the encryptor implementation.
    fn encryptor(&self) -> &dyn Encryptor;
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use mockall::predicate::*;

    mock! {
        TestPlugin {}

        #[async_trait]
        impl DIDResolver for TestPlugin {
            async fn resolve(&self, did: &str) -> Result<String>;
        }

        #[async_trait]
        impl Signer for TestPlugin {
            async fn sign(&self, message: &[u8], key_id: &str) -> Result<Vec<u8>>;
            async fn verify(&self, message: &[u8], signature: &[u8], key_id: &str) -> Result<bool>;
        }

        #[async_trait]
        impl Encryptor for TestPlugin {
            async fn encrypt(&self, message: &[u8], to: Vec<String>, from: Option<String>) -> Result<Vec<u8>>;
            async fn decrypt(&self, message: &[u8], recipient: String) -> Result<Vec<u8>>;
        }
    }

    impl DIDCommPlugin for MockTestPlugin {}

    #[tokio::test]
    async fn test_plugin_mock() {
        let mut plugin = MockTestPlugin::new();
        let test_message = b"test message";
        let test_signature = b"test signature";
        let test_key = "did:example:123";

        plugin
            .expect_sign()
            .with(eq(test_message.as_ref()), eq(test_key))
            .returning(|_, _| Ok(b"test signature".to_vec()));

        plugin
            .expect_verify()
            .with(
                eq(test_message.as_ref()),
                eq(test_signature.as_ref()),
                eq(test_key),
            )
            .returning(|_, _, _| Ok(true));

        let signature = plugin.sign(test_message, test_key).await.unwrap();
        assert_eq!(signature, test_signature);

        let valid = plugin
            .verify(test_message, test_signature, test_key)
            .await
            .unwrap();
        assert!(valid);
    }
}
