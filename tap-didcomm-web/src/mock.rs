use tap_didcomm_core::{
    plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer},
    error::Result,
};
use async_trait::async_trait;
use serde_json::json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// A mock plugin for testing DIDComm functionality.
#[derive(Clone)]
pub struct MockPlugin;

impl MockPlugin {
    /// Creates a new instance of the mock plugin.
    pub fn new() -> Self {
        Self
    }
}

#[cfg_attr(not(feature = "wasm"), async_trait)]
#[cfg_attr(feature = "wasm", async_trait(?Send))]
impl DIDResolver for MockPlugin {
    async fn resolve(&self, _did: &str) -> Result<String> {
        Ok(json!({
            "id": "did:example:test",
            "verificationMethod": [{
                "id": "did:example:test#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:example:test",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "test"
                }
            }]
        }).to_string())
    }
}

#[async_trait]
impl Signer for MockPlugin {
    async fn sign(
        &self,
        message: &[u8],
        _from: &str,
    ) -> Result<Vec<u8>> {
        // For testing, we'll just base64 encode the message as our "signature"
        Ok(STANDARD.encode(message).into_bytes())
    }

    async fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        _from: &str,
    ) -> Result<bool> {
        // Verify by comparing the base64 encoded message with the signature
        let sig_str = String::from_utf8_lossy(signature);
        Ok(STANDARD.encode(message) == sig_str)
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
        // For testing, we'll just base64 encode the message
        Ok(STANDARD.encode(message).into_bytes())
    }

    async fn decrypt(
        &self,
        message: &[u8],
        _recipient: String,
    ) -> Result<Vec<u8>> {
        // For testing, we'll just base64 decode the message
        STANDARD.decode(message)
            .map_err(|e| tap_didcomm_core::error::Error::Decryption(e.to_string()))
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
        assert!(did_doc.contains("did:example:test"));
        
        // Test signing
        let message = b"test message";
        let signature = plugin.sign(message, "did:example:test").await.unwrap();
        let verified = plugin.verify(message, &signature, "did:example:test").await.unwrap();
        assert!(verified);
        
        // Test encryption
        let encrypted = plugin.encrypt(message, vec!["did:example:recipient".to_string()], None).await.unwrap();
        let decrypted = plugin.decrypt(&encrypted, "did:example:recipient".to_string()).await.unwrap();
        assert_eq!(message, decrypted.as_slice());
    }
} 