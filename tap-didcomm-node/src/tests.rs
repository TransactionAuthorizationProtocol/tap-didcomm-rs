use tap_didcomm_core::{
    plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer},
    error::Result,
};
use async_trait::async_trait;
use serde_json::json;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

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
        // For testing, we'll just base64 encode the message as our "encryption"
        Ok(STANDARD.encode(message).into_bytes())
    }

    async fn decrypt(
        &self,
        message: &[u8],
        _recipient: String,
    ) -> Result<Vec<u8>> {
        // Decrypt by base64 decoding
        let message_str = String::from_utf8_lossy(message);
        Ok(STANDARD.decode(message_str.as_bytes())
            .map_err(|e| tap_didcomm_core::error::Error::Decryption(e.to_string()))?)
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

    #[actix_rt::test]
    async fn test_mock_plugin() {
        let plugin = MockPlugin::new();
        
        // Test DID resolution
        let did_doc = plugin.resolve("did:example:test").await.unwrap();
        assert!(did_doc.contains("did:example:test"));
        
        // Test signing and verification
        let message = b"test message";
        let signature = plugin.sign(message, "did:example:test").await.unwrap();
        let verified = plugin.verify(message, &signature, "did:example:test").await.unwrap();
        assert!(verified);
        
        // Test encryption and decryption
        let encrypted = plugin.encrypt(
            message,
            vec!["did:example:recipient".to_string()],
            Some("did:example:sender".to_string())
        ).await.unwrap();
        
        let decrypted = plugin.decrypt(&encrypted, "did:example:recipient".to_string()).await.unwrap();
        assert_eq!(decrypted, message);
    }
} 