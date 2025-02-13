//! Plugin system for `DIDComm` message handling.
//!
//! This module provides the plugin interface for handling `DIDComm` messages,
//! including signing, verification, encryption, and decryption operations.

use async_trait::async_trait;

use crate::error::Result;

/// A resolver for DID documents.
#[async_trait]
pub trait DIDResolver: Send + Sync {
    /// Resolves a DID to its DID document.
    async fn resolve(&self, did: &str) -> Result<String>;
}

/// A signer for DIDComm messages.
#[async_trait]
pub trait Signer: Send + Sync {
    /// Signs a message using the specified key.
    async fn sign(&self, message: &[u8], key_id: &str) -> Result<Vec<u8>>;

    /// Verifies a message signature.
    async fn verify(&self, message: &[u8], signature: &[u8], key_id: &str) -> Result<bool>;
}

/// An encryptor for DIDComm messages.
#[async_trait]
pub trait Encryptor: Send + Sync {
    /// Encrypts a message for the specified recipients.
    async fn encrypt(
        &self,
        message: &[u8],
        to: Vec<String>,
        from: Option<String>,
    ) -> Result<Vec<u8>>;

    /// Decrypts a message using the recipient's key.
    async fn decrypt(&self, message: &[u8], recipient: String) -> Result<Vec<u8>>;
}

/// A plugin for DIDComm operations.
#[async_trait]
pub trait DIDCommPlugin: DIDResolver + Signer + Encryptor + Send + Sync {
    /// Gets the resolver implementation.
    fn as_resolver(&self) -> &dyn DIDResolver
    where
        Self: Sized,
    {
        self
    }

    /// Gets the signer implementation.
    fn as_signer(&self) -> &dyn Signer
    where
        Self: Sized,
    {
        self
    }

    /// Gets the encryptor implementation.
    fn as_encryptor(&self) -> &dyn Encryptor
    where
        Self: Sized,
    {
        self
    }
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
