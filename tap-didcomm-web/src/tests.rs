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

#[cfg_attr(not(feature = "wasm"), async_trait)]
#[cfg_attr(feature = "wasm", async_trait(?Send))]
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
        // For testing, we'll just base64 encode the message
        Ok(STANDARD.encode(message).into_bytes())
    }

    async fn decrypt(
        &self,
        message: &[u8],
        _recipient: String,
    ) -> tap_didcomm_core::error::Result<Vec<u8>> {
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
    use crate::server::{DIDCommServer, ServerConfig};
    use tap_didcomm_node::NodeConfig;
    use actix_web::{test, web, App};

    #[actix_rt::test]
    async fn test_handlers() {
        let server = DIDCommServer::new(
            ServerConfig::default(),
            NodeConfig::default(),
            MockPlugin::new(),
        );

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(server.get_node()))
                .service(web::resource("/receive").to(crate::handlers::receive_message))
                .service(web::resource("/send").to(crate::handlers::send_message))
                .service(web::resource("/status").to(crate::handlers::status))
        ).await;

        // Test receive endpoint
        let req = test::TestRequest::post()
            .uri("/receive")
            .set_json(json!({
                "data": STANDARD.encode("test message")
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // Test send endpoint
        let req = test::TestRequest::post()
            .uri("/send")
            .set_json(json!({
                "message": {
                    "id": "test-1",
                    "type": "test",
                    "body": { "test": "data" }
                },
                "packing": "signed",
                "endpoint": "http://example.com"
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // Test status endpoint
        let req = test::TestRequest::get()
            .uri("/status")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
} 