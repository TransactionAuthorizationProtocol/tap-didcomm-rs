use std::env;
use tap_didcomm_core::plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer, SSIDIDResolverWrapper};
use tap_didcomm_web::server::{CorsConfig, ServerConfig, DIDCommServer};
use ssi_dids::did_resolve::HTTPDIDResolver;
use ssi_jwk::{JWK, Algorithm};
use ssi_jws::{encode_sign_custom_header, decode_verify, Header};
use serde_json::Value;
use tap_didcomm_node::actor::LoggingActor;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::sync::Arc;
use actix::Actor;

#[derive(Clone)]
struct UniversalPlugin {
    resolver: Arc<Box<dyn DIDResolver + Send + Sync>>,
    signing_key: JWK,
}

impl UniversalPlugin {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let http_resolver = HTTPDIDResolver::new(
            "https://dev.uniresolver.io/1.0/identifiers/"
        );

        // Create signing key with key operations
        let mut signing_key = JWK::generate_ed25519()?;
        signing_key.key_operations = Some(vec![
            "sign".to_string(),
            "verify".to_string(),
        ]);
        
        // Wrap the HTTP resolver with SSIDIDResolverWrapper
        let resolver = SSIDIDResolverWrapper::new(http_resolver);
        
        Ok(Self {
            resolver: Arc::new(Box::new(resolver)),
            signing_key,
        })
    }
}

#[async_trait::async_trait]
impl DIDResolver for UniversalPlugin {
    async fn resolve(&self, did: &str) -> tap_didcomm_core::error::Result<String> {
        self.resolver.resolve(did).await
    }
}

#[async_trait::async_trait]
impl Signer for UniversalPlugin {
    async fn sign(
        &self,
        message: &[u8],
        from: &str,
    ) -> tap_didcomm_core::error::Result<Vec<u8>> {
        let header = Header {
            algorithm: Algorithm::EdDSA,
            key_id: Some(from.to_string()),
            ..Default::default()
        };

        let message_str = std::str::from_utf8(message)
            .map_err(|e| tap_didcomm_core::error::Error::InvalidFormat(e.to_string()))?;
        
        let jws = encode_sign_custom_header(
            message_str,
            &self.signing_key,
            &header,
        ).map_err(|e| tap_didcomm_core::error::Error::Signing(e.to_string()))?;

        Ok(jws.into_bytes())
    }

    async fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        from: &str,
    ) -> tap_didcomm_core::error::Result<bool> {
        // Verify JWS using the public key from DID document
        let doc = self.resolve(from).await?;
        let doc: Value = serde_json::from_str(&doc)
            .map_err(|e| tap_didcomm_core::error::Error::InvalidFormat(e.to_string()))?;
        
        let key = doc["verificationMethod"]
            .as_array()
            .and_then(|methods| {
                methods.iter().find(|m| m["type"] == "JsonWebKey2020")
            })
            .and_then(|m| Some(m["publicKeyJwk"].clone()))
            .ok_or_else(|| tap_didcomm_core::error::Error::InvalidFormat("No verification key found".into()))?;

        let key: JWK = serde_json::from_value(key)
            .map_err(|e| tap_didcomm_core::error::Error::InvalidFormat(e.to_string()))?;
        
        let sig_str = std::str::from_utf8(signature)
            .map_err(|e| tap_didcomm_core::error::Error::InvalidFormat(e.to_string()))?;

        let (_, verified_message) = decode_verify(sig_str, &key)
            .map_err(|e| tap_didcomm_core::error::Error::Verification(e.to_string()))?;

        Ok(verified_message == message)
    }
}

#[async_trait::async_trait]
impl Encryptor for UniversalPlugin {
    async fn encrypt(
        &self,
        message: &[u8],
        _to: Vec<String>,
        from: Option<String>,
    ) -> tap_didcomm_core::error::Result<Vec<u8>> {
        // For now, we'll just sign the message since we don't have proper encryption
        if let Some(from) = from {
            self.sign(message, &from).await
        } else {
            Ok(message.to_vec())
        }
    }

    async fn decrypt(
        &self,
        message: &[u8],
        _recipient: String,
    ) -> tap_didcomm_core::error::Result<Vec<u8>> {
        // For now, we'll just verify the signature since we don't have proper decryption
        let message_str = std::str::from_utf8(message)
            .map_err(|e| tap_didcomm_core::error::Error::InvalidFormat(e.to_string()))?;

        let (_, verified_message) = decode_verify(message_str, &self.signing_key)
            .map_err(|e| tap_didcomm_core::error::Error::Decryption(e.to_string()))?;

        Ok(verified_message.to_vec())
    }
}

impl DIDCommPlugin for UniversalPlugin {
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

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // Get port from environment or use default
    let port = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let config = ServerConfig {
        host: "0.0.0.0".to_string(),
        port,
        cors: CorsConfig {
            allowed_origins: vec!["*".to_string()],
            allow_credentials: true,
        },
    };

    // Create the universal plugin
    let plugin = UniversalPlugin::new()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let node_config = tap_didcomm_node::NodeConfig::default();
    let server = DIDCommServer::new(config, node_config, plugin);

    // Create and register the logging actor
    let logging_actor = LoggingActor::new("main-logger").start();
    server.register_handler("*", logging_actor.recipient());

    // Run the server
    server.run().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web};
    use tap_didcomm_core::{Message as CoreMessage, types::PackingType};
    use serde_json::json;
    use env_logger;
    use tap_didcomm_web::mock::MockPlugin;

    fn setup() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[actix_rt::test]
    async fn test_server_endpoints() {
        setup();

        // Create a test server
        let plugin = MockPlugin::new();
        let node_config = tap_didcomm_node::NodeConfig::default();
        let server_config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8081,
            cors: CorsConfig {
                allowed_origins: vec!["*".to_string()],
                allow_credentials: true,
            },
        };

        let server = DIDCommServer::new(server_config, node_config, plugin);
        let node = server.get_node();
        let node_data = web::Data::new(node);

        // Create and register a logging actor
        let logging_actor = LoggingActor::new("test-logger").start();
        if let Ok(mut node) = node_data.lock() {
            node.register_handler("*", logging_actor.recipient());
        }

        let app = test::init_service(
            actix_web::App::new()
                .app_data(node_data.clone())
                .service(tap_didcomm_web::handlers::receive_message)
                .service(tap_didcomm_web::handlers::send_message)
                .service(tap_didcomm_web::handlers::status)
        ).await;

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
                "data": STANDARD.encode(&packed_message)
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_end_to_end_message_flow() {
        setup();

        // Create a test server
        let plugin = MockPlugin::new();
        let node_config = tap_didcomm_node::NodeConfig::default();
        let server_config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8082,
            cors: CorsConfig {
                allowed_origins: vec!["*".to_string()],
                allow_credentials: true,
            },
        };

        let server = DIDCommServer::new(server_config, node_config, plugin);
        let node = server.get_node();
        let node_data = web::Data::new(node);

        // Create and register a logging actor
        let logging_actor = LoggingActor::new("test-logger").start();
        if let Ok(mut node) = node_data.lock() {
            node.register_handler("*", logging_actor.recipient());
        }

        let app = test::init_service(
            actix_web::App::new()
                .app_data(node_data.clone())
                .service(tap_didcomm_web::handlers::receive_message)
                .service(tap_didcomm_web::handlers::send_message)
                .service(tap_didcomm_web::handlers::status)
        ).await;

        // Create and encrypt a test message
        let message = CoreMessage::new("test", json!({"hello": "world"}))
            .unwrap()
            .from("did:example:alice")
            .to(vec!["did:example:bob"]);

        // First pack the message
        let node = node_data.lock().expect("Failed to lock node");
        let packed_message = tap_didcomm_core::pack::pack_message(
            &message,
            node.plugin(),
            PackingType::Signed
        ).await.unwrap();
        drop(node);

        // Base64 encode the packed message
        let encoded_message = STANDARD.encode(&packed_message);

        // Send the encrypted message
        let req = test::TestRequest::post()
            .uri("/didcomm")
            .set_json(json!({
                "data": encoded_message
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
} 