use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use tap_didcomm_core::{
    error::Result,
    plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer},
};

/// Mock plugin for testing.
pub struct MockPlugin;

impl MockPlugin {
    /// Creates a new mock plugin.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl DIDResolver for MockPlugin {
    async fn resolve(&self, _did: &str) -> Result<String> {
        Ok(r#"{
            "id": "did:example:123",
            "verificationMethod": [{
                "id": "did:example:123#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:example:123",
                "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }]
        }"#
        .to_string())
    }
}

#[async_trait]
impl Signer for MockPlugin {
    async fn sign(&self, message: &[u8], _from: &str) -> Result<Vec<u8>> {
        Ok(STANDARD.encode(message).into_bytes())
    }

    async fn verify(&self, message: &[u8], signature: &[u8], _from: &str) -> Result<bool> {
        Ok(message == signature)
    }
}

#[async_trait]
impl Encryptor for MockPlugin {
    async fn encrypt(&self, message: &[u8], _to: &[&str], _from: Option<&str>) -> Result<Vec<u8>> {
        Ok(STANDARD.encode(message).into_bytes())
    }

    async fn decrypt(&self, message: &[u8], _recipient: &str) -> Result<Vec<u8>> {
        Ok(STANDARD.decode(message)?)
    }
}

impl DIDCommPlugin for MockPlugin {
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

    #[tokio::test]
    async fn test_mock_plugin() {
        let plugin = MockPlugin::new();
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
