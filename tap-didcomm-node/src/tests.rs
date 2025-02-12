use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::json;
use tap_didcomm_core::{
    error::Result,
    plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer},
};

/// A mock plugin for testing DIDComm functionality.
#[derive(Clone)]
pub struct MockPlugin;

impl MockPlugin {
    /// Creates a new instance of the mock plugin.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl DIDResolver for MockPlugin {
    async fn resolve(&self, _did: &str) -> Result<String> {
        Ok("{}".to_string())
    }
}

#[async_trait]
impl Signer for MockPlugin {
    async fn sign(&self, message: &[u8], _from: &str) -> Result<Vec<u8>> {
        Ok(message.to_vec())
    }

    async fn verify(&self, message: &[u8], signature: &[u8], _from: &str) -> Result<bool> {
        Ok(true)
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
        Ok(message.to_vec())
    }

    async fn decrypt(&self, message: &[u8], _recipient: String) -> Result<Vec<u8>> {
        Ok(message.to_vec())
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

    #[tokio::test]
    async fn test_mock_plugin() {
        let plugin = MockPlugin::new();

        // Test DID resolution
        let did_doc = plugin.resolve("did:example:test").await.unwrap();
        assert!(did_doc.contains("{}"));

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
