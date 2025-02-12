//! Mock implementations for testing `DIDComm` functionality.
//!
//! This module provides mock implementations of the core `DIDComm` traits for testing purposes.
//! It includes:
//! - A mock DID resolver that returns a simple DID document
//! - A mock signer that uses base64 encoding as a stand-in for signatures
//! - A mock encryptor that uses base64 encoding as a stand-in for encryption
//!
//! These mocks are useful for testing the `DIDComm` node functionality without requiring
//! actual cryptographic operations or network calls.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::json;
use tap_didcomm_core::{DIDCommPlugin, DIDResolver, Encryptor, Error as CoreError, Result, Signer};

/// A mock plugin for testing `DIDComm` functionality.
#[derive(Clone, Default)]
pub struct MockPlugin;

impl MockPlugin {
    /// Creates a new instance of the mock plugin.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl DIDResolver for MockPlugin {
    async fn resolve(&self, did: &str) -> Result<String> {
        Ok(json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{}#key-1", did),
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }]
        })
        .to_string())
    }
}

#[async_trait]
impl Signer for MockPlugin {
    async fn sign(&self, message: &[u8], _from: &str) -> Result<Vec<u8>> {
        // For testing, just base64 encode the message as a mock signature
        Ok(STANDARD.encode(message).into_bytes())
    }

    async fn verify(&self, message: &[u8], signature: &[u8], _from: &str) -> Result<bool> {
        // For testing, verify that the signature is the base64 encoded message
        let decoded = STANDARD.decode(signature).map_err(CoreError::Base64)?;
        Ok(message == decoded)
    }
}

#[async_trait]
impl Encryptor for MockPlugin {
    async fn encrypt(
        &self,
        message: &[u8],
        _to: Vec<String>,
        _from: Option<String>,
    ) -> Result<Vec<u8>> {
        // For testing, just base64 encode the message as mock encryption
        Ok(STANDARD.encode(message).into_bytes())
    }

    async fn decrypt(&self, message: &[u8], _recipient: String) -> Result<Vec<u8>> {
        // For testing, base64 decode the message as mock decryption
        STANDARD.decode(message).map_err(CoreError::Base64)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_mock_plugin() {
        let plugin = Arc::new(MockPlugin::new());

        // Test DID resolution
        let did_doc = plugin.resolve("did:example:test").await.unwrap();
        assert!(did_doc.contains("did:example:test"));

        // Test signing and verification
        let message = b"test message";
        let signature = plugin.sign(message, "did:example:test").await.unwrap();
        let verified = plugin
            .verify(message, &signature, "did:example:test")
            .await
            .unwrap();
        assert!(verified);

        // Test encryption and decryption
        let encrypted = plugin
            .encrypt(
                message,
                vec!["did:example:recipient".to_string()],
                Some("did:example:sender".to_string()),
            )
            .await
            .unwrap();

        let decrypted = plugin
            .decrypt(&encrypted, "did:example:recipient".to_string())
            .await
            .unwrap();
        assert_eq!(decrypted, message);
    }
}
