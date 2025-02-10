//! Plugin traits for customizing DIDComm functionality.
//!
//! This module provides a flexible plugin system that allows customization of key
//! DIDComm operations such as DID resolution, message signing, and encryption.
//! Implementors can provide their own implementations of these traits to integrate
//! with different key management systems, DID methods, and cryptographic backends.
//!
//! # Examples
//!
//! ```rust,no_run
//! use tap_didcomm_core::plugin::{DIDResolver, Signer, Encryptor, DIDCommPlugin};
//! use async_trait::async_trait;
//!
//! struct MyPlugin {
//!     resolver: MyResolver,
//!     signer: MySigner,
//!     encryptor: MyEncryptor,
//! }
//!
//! impl DIDCommPlugin for MyPlugin {
//!     fn as_resolver(&self) -> &dyn DIDResolver { &self.resolver }
//!     fn as_signer(&self) -> &dyn Signer { &self.signer }
//!     fn as_encryptor(&self) -> &dyn Encryptor { &self.encryptor }
//! }
//! ```

use async_trait::async_trait;
use ssi::did_resolve::DIDResolver as SSIResolver;
use crate::error::{Error, Result};

/// A trait for resolving DIDs to their DID Documents.
///
/// This trait is the foundation for DID resolution in the DIDComm system.
/// Implementations should be able to resolve DIDs to their corresponding
/// DID Documents, which contain the cryptographic material needed for
/// secure communication.
///
/// # Security Considerations
///
/// Implementations should:
/// - Validate DID syntax before resolution
/// - Handle resolution timeouts appropriately
/// - Cache resolutions when appropriate
/// - Implement proper error handling for network issues
///
/// # Examples
///
/// ```rust,no_run
/// use tap_didcomm_core::plugin::DIDResolver;
/// use async_trait::async_trait;
///
/// struct MyResolver;
///
/// #[async_trait]
/// impl DIDResolver for MyResolver {
///     async fn resolve(&self, did: &str) -> tap_didcomm_core::error::Result<String> {
///         // Validate DID syntax
///         if !did.starts_with("did:") {
///             return Err("Invalid DID syntax".into());
///         }
///
///         // Resolve the DID and return the DID Document
///         Ok(r#"{"id": "did:example:123", ...}"#.to_string())
///     }
/// }
/// ```
#[async_trait]
pub trait DIDResolver: Send + Sync {
    /// Resolves a DID to its DID Document.
    ///
    /// # Arguments
    ///
    /// * `did` - The DID to resolve (e.g., "did:example:123")
    ///
    /// # Returns
    ///
    /// A Result containing the resolved DID Document as a JSON string, or an error
    /// if resolution fails.
    ///
    /// # Errors
    ///
    /// Common error cases include:
    /// - Invalid DID syntax
    /// - Network errors during resolution
    /// - Resolution timeout
    /// - DID not found
    async fn resolve(&self, did: &str) -> Result<String>;
}

/// A trait for signing and verifying messages.
///
/// This trait handles the cryptographic operations needed for message
/// signing and signature verification. Implementations should support
/// the cryptographic algorithms required by DIDComm v2.
///
/// # Security Considerations
///
/// Implementations should:
/// - Use cryptographically secure random number generation
/// - Implement proper key management and protection
/// - Support the required signature algorithms (EdDSA, ECDSA)
/// - Validate all inputs before processing
///
/// # Examples
///
/// ```rust,no_run
/// use tap_didcomm_core::plugin::Signer;
/// use async_trait::async_trait;
///
/// struct MySigner;
///
/// #[async_trait]
/// impl Signer for MySigner {
///     async fn sign(&self, data: &[u8], key_id: &str) -> tap_didcomm_core::error::Result<Vec<u8>> {
///         // Perform signing operation
///         Ok(vec![])
///     }
///
///     async fn verify(&self, data: &[u8], signature: &[u8], key_id: &str) -> tap_didcomm_core::error::Result<bool> {
///         // Verify signature
///         Ok(true)
///     }
/// }
/// ```
#[async_trait]
pub trait Signer: Send + Sync {
    /// Signs a message with the specified key.
    ///
    /// # Arguments
    ///
    /// * `data` - The message bytes to sign
    /// * `key_id` - The key ID to use for signing (typically a DID URL)
    ///
    /// # Returns
    ///
    /// A Result containing the signature bytes, or an error if signing fails.
    ///
    /// # Errors
    ///
    /// Common error cases include:
    /// - Key not found
    /// - Invalid key format
    /// - Signing operation failure
    async fn sign(&self, data: &[u8], key_id: &str) -> Result<Vec<u8>>;

    /// Verifies a message signature.
    ///
    /// # Arguments
    ///
    /// * `data` - The original message bytes
    /// * `signature` - The signature to verify
    /// * `key_id` - The key ID that was used to create the signature
    ///
    /// # Returns
    ///
    /// A Result containing true if the signature is valid, false if invalid,
    /// or an error if verification fails.
    ///
    /// # Errors
    ///
    /// Common error cases include:
    /// - Key not found
    /// - Invalid signature format
    /// - Verification operation failure
    async fn verify(&self, data: &[u8], signature: &[u8], key_id: &str) -> Result<bool>;
}

/// A trait for encrypting and decrypting messages.
///
/// This trait handles the cryptographic operations needed for message
/// encryption and decryption. Implementations should support the
/// encryption algorithms required by DIDComm v2, including support
/// for both anoncrypt and authcrypt modes.
///
/// # Security Considerations
///
/// Implementations should:
/// - Use secure key derivation functions
/// - Implement proper key management
/// - Support required algorithms (ECDH-ES+A256KW, ECDH-1PU+A256KW)
/// - Validate all inputs before processing
///
/// # Examples
///
/// ```rust,no_run
/// use tap_didcomm_core::plugin::Encryptor;
/// use async_trait::async_trait;
///
/// struct MyEncryptor;
///
/// #[async_trait]
/// impl Encryptor for MyEncryptor {
///     async fn encrypt(&self, data: &[u8], recipients: Vec<String>, from: Option<String>) -> tap_didcomm_core::error::Result<Vec<u8>> {
///         // Perform encryption
///         Ok(vec![])
///     }
///
///     async fn decrypt(&self, data: &[u8], recipient: String) -> tap_didcomm_core::error::Result<Vec<u8>> {
///         // Perform decryption
///         Ok(vec![])
///     }
/// }
/// ```
#[async_trait]
pub trait Encryptor: Send + Sync {
    /// Encrypts a message for the specified recipients.
    ///
    /// # Arguments
    ///
    /// * `data` - The message bytes to encrypt
    /// * `recipients` - The DIDs to encrypt for
    /// * `from` - The DID encrypting the message (optional, for authcrypt)
    ///
    /// # Returns
    ///
    /// A Result containing the encrypted message bytes, or an error if encryption fails.
    ///
    /// # Errors
    ///
    /// Common error cases include:
    /// - Recipient key not found
    /// - Invalid key format
    /// - Encryption operation failure
    async fn encrypt(&self, data: &[u8], recipients: Vec<String>, from: Option<String>) -> Result<Vec<u8>>;

    /// Decrypts a message.
    ///
    /// # Arguments
    ///
    /// * `data` - The encrypted message bytes
    /// * `recipient` - The DID the message was encrypted for
    ///
    /// # Returns
    ///
    /// A Result containing the decrypted message bytes, or an error if decryption fails.
    ///
    /// # Errors
    ///
    /// Common error cases include:
    /// - Recipient key not found
    /// - Invalid ciphertext format
    /// - Decryption operation failure
    async fn decrypt(&self, data: &[u8], recipient: String) -> Result<Vec<u8>>;
}

/// A wrapper for the SSI crate's DID resolver that implements our DIDResolver trait.
///
/// This wrapper allows using any SSI-compatible DID resolver with our DIDComm
/// implementation. It handles the conversion between the SSI resolver's interface
/// and our own.
///
/// # Examples
///
/// ```rust,no_run
/// use tap_didcomm_core::plugin::SSIDIDResolverWrapper;
/// use ssi::did_resolve::HTTPDIDResolver;
///
/// let http_resolver = HTTPDIDResolver::new(
///     "https://resolver.example.com",
///     vec!["did:web", "did:key"]
/// );
/// let wrapper = SSIDIDResolverWrapper::new(http_resolver);
/// ```
pub struct SSIDIDResolverWrapper<T: SSIResolver>(pub T);

#[async_trait]
impl<T> DIDResolver for SSIDIDResolverWrapper<T>
where
    T: SSIResolver + Send + Sync,
{
    async fn resolve(&self, did: &str) -> Result<String> {
        let (metadata, doc, _) = self.0.resolve(did, &Default::default()).await;
        
        if metadata.error.is_some() {
            let error = metadata.error.unwrap();
            return Err(Error::DIDResolution(error));
        }

        if let Some(doc) = doc {
            serde_json::to_string(&doc).map_err(Error::Serialization)
        } else {
            Err(Error::DIDResolution("DID document not found".to_string()))
        }
    }
}

impl<T> SSIDIDResolverWrapper<T>
where
    T: SSIResolver + Send + Sync,
{
    /// Creates a new SSI DID resolver wrapper.
    ///
    /// # Arguments
    ///
    /// * `resolver` - The SSI resolver to wrap
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use tap_didcomm_core::plugin::SSIDIDResolverWrapper;
    /// use ssi::did_resolve::HTTPDIDResolver;
    ///
    /// let http_resolver = HTTPDIDResolver::new(
    ///     "https://resolver.example.com",
    ///     vec!["did:web", "did:key"]
    /// );
    /// let wrapper = SSIDIDResolverWrapper::new(http_resolver);
    /// ```
    pub fn new(resolver: T) -> Self {
        Self(resolver)
    }
}

/// A trait for implementing a complete DIDComm plugin.
///
/// This trait combines DID resolution, signing, and encryption capabilities
/// into a single interface. Implementations should provide all the
/// functionality needed for secure DIDComm message exchange.
pub trait DIDCommPlugin: Send + Sync {
    /// Returns a reference to the DID resolver implementation.
    fn as_resolver(&self) -> &dyn DIDResolver;

    /// Returns a reference to the signer implementation.
    fn as_signer(&self) -> &dyn Signer;

    /// Returns a reference to the encryptor implementation.
    fn as_encryptor(&self) -> &dyn Encryptor;
}

/// Tests for the plugin module.
#[cfg(test)]
pub mod tests {
    use super::*;
    use ssi::did_resolve::{DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata};

    struct MockResolver;

    #[async_trait::async_trait]
    impl SSIResolver for MockResolver {
        async fn resolve(
            &self,
            _did: &str,
            _input_metadata: &ResolutionInputMetadata,
        ) -> (ResolutionMetadata, Option<ssi::did::Document>, Option<DocumentMetadata>) {
            let mut metadata = ResolutionMetadata::default();
            metadata.error = Some("test error".to_string());
            (metadata, None, None)
        }
    }

    #[tokio::test]
    async fn test_ssi_resolver_wrapper() {
        let resolver = SSIDIDResolverWrapper::new(MockResolver);
        let result = resolver.resolve("did:example:123").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "DID resolution error: test error");
    }
}

/// Creates a new DIDCommPlugin with the given resolver
pub fn new<T>(resolver: T) -> SSIDIDResolverWrapper<T>
where
    T: SSIResolver + Send + Sync,
{
    SSIDIDResolverWrapper(resolver)
} 