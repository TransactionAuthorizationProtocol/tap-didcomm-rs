use tap_didcomm_core::{
    plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer},
    Message as CoreMessage,
    types::PackingType,
};
use async_trait::async_trait;
use serde_json::json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use actix::Actor;

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
    async fn resolve(&self, _did: &str) -> tap_didcomm_core::error::Result<String> {
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
    ) -> tap_didcomm_core::error::Result<Vec<u8>> {
        // For testing, we'll just base64 encode the message as our "signature"
        Ok(STANDARD.encode(message).into_bytes())
    }

    async fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        _from: &str,
    ) -> tap_didcomm_core::error::Result<bool> {
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
    ) -> tap_didcomm_core::error::Result<Vec<u8>> {
        // For testing, we'll just base64 encode the message as our "encryption"
        Ok(STANDARD.encode(message).into_bytes())
    }

    async fn decrypt(
        &self,
        message: &[u8],
        _recipient: String,
    ) -> tap_didcomm_core::error::Result<Vec<u8>> {
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
    use actix_web::{test, web, App};
    use crate::server::{ServerConfig, CorsConfig, DIDCommServer};
    use tap_didcomm_node::{NodeConfig, actor::LoggingActor};

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

    #[actix_rt::test]
    async fn test_handlers() {
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            cors: CorsConfig {
                allowed_origins: vec!["*".to_string()],
                allow_credentials: true,
            },
        };

        let node_config = NodeConfig::default();
        let plugin = MockPlugin::new();

        let server = DIDCommServer::new(config, node_config, plugin);
        let node = server.get_node();
        let node_data = web::Data::new(node);

        // Create and register a logging actor
        let logging_actor = LoggingActor::new("test-logger").start();
        if let Ok(mut node) = node_data.lock() {
            node.register_handler("*", logging_actor.recipient());
        }
        
        let app = test::init_service(
            App::new()
                .app_data(node_data.clone())
                .service(crate::handlers::receive_message)
                .service(crate::handlers::send_message)
                .service(crate::handlers::status),
        )
        .await;

        // Test status endpoint
        let req = test::TestRequest::post().uri("/status").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // Test sending a message
        let message = CoreMessage::new("test", json!({"hello": "world"}))
            .unwrap()
            .from("did:example:alice")
            .to(vec!["did:example:bob"]);

        let req = test::TestRequest::post()
            .uri("/didcomm/send")
            .set_json(json!({
                "message": message,
                "packing": PackingType::Signed,
                "endpoint": "http://example.com/didcomm"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // Test receiving a message
        let packed_message = {
            let node = node_data.lock().expect("Failed to lock node");
            tap_didcomm_core::pack::pack_message(
                &message,
                node.plugin(),
                PackingType::Signed
            ).await.unwrap()
        };

        let req = test::TestRequest::post()
            .uri("/didcomm")
            .set_json(json!({
                "data": STANDARD.encode(&packed_message),
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
} 