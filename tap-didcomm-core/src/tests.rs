use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::json;

use crate::{
    error::Result,
    plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer},
};

/// A mock plugin for testing `DIDComm` functionality.
#[derive(Clone)]
pub struct MockTestPlugin;

#[async_trait]
impl DIDResolver for MockTestPlugin {
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
impl Signer for MockTestPlugin {
    async fn sign(&self, message: &[u8], _from: &str) -> Result<Vec<u8>> {
        // For testing, just base64 encode the message as a mock signature
        Ok(STANDARD.encode(message).into_bytes())
    }

    async fn verify(&self, message: &[u8], signature: &[u8], _from: &str) -> Result<bool> {
        // For testing, verify that the signature is the base64 encoded message
        let decoded = STANDARD
            .decode(signature)
            .map_err(|e| crate::Error::Base64(e.to_string()))?;
        Ok(message == decoded)
    }
}

#[async_trait]
impl Encryptor for MockTestPlugin {
    async fn encrypt(&self, message: &[u8], _to: &[&str], _from: Option<&str>) -> Result<Vec<u8>> {
        // For testing, just base64 encode the message as mock encryption
        Ok(STANDARD.encode(message).into_bytes())
    }

    async fn decrypt(&self, message: &[u8], _recipient: &str) -> Result<Vec<u8>> {
        // For testing, base64 decode the message as mock decryption
        Ok(STANDARD
            .decode(message)
            .map_err(|e| crate::Error::Base64(e.to_string()))?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_mock_plugin() {
        let plugin = Arc::new(MockTestPlugin);

        // Test DID resolution
        let did_doc = plugin.resolver().resolve("did:example:test").await.unwrap();
        assert!(did_doc.contains("did:example:test"));

        // Test signing and verification
        let message = b"test message";
        let signature = plugin
            .signer()
            .sign(message, "did:example:test")
            .await
            .unwrap();
        let verified = plugin
            .signer()
            .verify(message, &signature, "did:example:test")
            .await
            .unwrap();
        assert!(verified);

        // Test encryption and decryption
        let encrypted = plugin
            .encryptor()
            .encrypt(
                message,
                &["did:example:recipient"],
                Some("did:example:sender"),
            )
            .await
            .unwrap();

        let decrypted = plugin
            .encryptor()
            .decrypt(&encrypted, "did:example:recipient")
            .await
            .unwrap();
        assert_eq!(decrypted, message);
    }
}
