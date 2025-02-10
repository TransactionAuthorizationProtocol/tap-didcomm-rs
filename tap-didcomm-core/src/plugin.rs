//! Plugin traits for customizing DIDComm functionality.

use async_trait::async_trait;
use ssi::did_resolve::DIDResolver as SSIResolver;
use crate::error::{Error, Result};

/// A trait for resolving DIDs.
#[async_trait]
pub trait DIDResolver: Send + Sync {
    /// Resolves a DID to its DID Document.
    ///
    /// # Arguments
    ///
    /// * `did` - The DID to resolve
    ///
    /// # Returns
    ///
    /// The resolved DID Document as a JSON value.
    async fn resolve(&self, did: &str) -> Result<String>;
}

/// A trait for signing and verifying messages.
#[async_trait]
pub trait Signer: Send + Sync {
    /// Signs a message with the specified key.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `key_id` - The key ID to sign with
    ///
    /// # Returns
    ///
    /// The signed message.
    async fn sign(&self, data: &[u8], key_id: &str) -> Result<Vec<u8>>;

    /// Verifies a message signature.
    ///
    /// # Arguments
    ///
    /// * `message` - The signed message
    /// * `signature` - The signature to verify
    /// * `key_id` - The key ID that signed the message
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the signature is valid, `Ok(false)` if the signature is invalid, or an error if verification fails.
    async fn verify(&self, data: &[u8], signature: &[u8], key_id: &str) -> Result<bool>;
}

/// A trait for encrypting and decrypting messages.
#[async_trait]
pub trait Encryptor: Send + Sync {
    /// Encrypts a message for the specified recipients.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to encrypt
    /// * `recipients` - The DIDs to encrypt for
    /// * `from` - The DID encrypting the message (optional)
    ///
    /// # Returns
    ///
    /// The encrypted message.
    async fn encrypt(&self, data: &[u8], recipients: Vec<String>, from: Option<String>) -> Result<Vec<u8>>;

    /// Decrypts a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The encrypted message
    /// * `recipient` - The DID the message was encrypted for
    ///
    /// # Returns
    ///
    /// The decrypted message.
    async fn decrypt(&self, data: &[u8], recipient: String) -> Result<Vec<u8>>;
}

/// A wrapper for the SSI crate's DID resolver that implements our DIDResolver trait.
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
    pub fn new(resolver: T) -> Self {
        Self(resolver)
    }
}

/// A trait for implementing a complete DIDComm plugin.
///
/// This trait combines DID resolution, signing, and encryption capabilities.
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
    use mockall::mock;
    use ssi::did_resolve::DIDResolver as SSIResolver;
    use ssi::did::Document;
    use ssi::did_resolve::ResolutionMetadata;

    mock! {
        Plugin {}

        #[async_trait]
        impl DIDResolver for Plugin {
            async fn resolve(&self, did: &str) -> Result<String>;
        }

        #[async_trait]
        impl Signer for Plugin {
            async fn sign(&self, message: &[u8], key_id: &str) -> Result<Vec<u8>>;
            async fn verify(&self, message: &[u8], signature: &[u8], key_id: &str) -> Result<bool>;
        }

        #[async_trait]
        impl Encryptor for Plugin {
            async fn encrypt(&self, message: &[u8], recipients: Vec<String>, from: Option<String>) -> Result<Vec<u8>>;
            async fn decrypt(&self, message: &[u8], recipient: String) -> Result<Vec<u8>>;
        }
    }

    impl Clone for MockPlugin {
        fn clone(&self) -> Self {
            MockPlugin::new()
        }
    }

    impl DIDCommPlugin for MockPlugin {
        fn as_resolver(&self) -> &dyn DIDResolver {
            self
        }

        fn as_signer(&self) -> &dyn Signer {
            self
        }

        fn as_encryptor(&self) -> &dyn Encryptor {
            self
        }
    }

    #[tokio::test]
    async fn test_ssi_resolver_wrapper() {
        struct MockResolver;

        #[async_trait::async_trait]
        impl SSIResolver for MockResolver {
            async fn resolve(
                &self,
                _did: &str,
                _input_metadata: &Default::default(),
            ) -> (ResolutionMetadata, Option<Document>, Option<Default::default()>) {
                let mut metadata = ResolutionMetadata::default();
                metadata.error = Some("test error".to_string());
                (metadata, None, None)
            }
        }

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