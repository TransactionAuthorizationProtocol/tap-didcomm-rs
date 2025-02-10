//! HTTP server implementation.

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use tap_didcomm_core::plugin::DIDCommPlugin;
use tap_didcomm_node::{DIDCommNode, NodeConfig};

use crate::{
    error::Result,
    handlers::{receive_message, send_message, status},
};

/// Configuration for CORS.
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// The allowed origins.
    pub allowed_origins: Vec<String>,
    /// Whether to allow credentials.
    pub allow_credentials: bool,
}

/// Configuration for the DIDComm server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The host to bind to.
    pub host: String,
    /// The port to bind to.
    pub port: u16,
    /// CORS configuration.
    pub cors: CorsConfig,
}

/// A DIDComm server that exposes HTTP endpoints.
pub struct DIDCommServer {
    /// The server configuration.
    config: ServerConfig,
    /// The DIDComm node.
    node: DIDCommNode,
}

impl DIDCommServer {
    /// Creates a new DIDComm server.
    ///
    /// # Arguments
    ///
    /// * `config` - The server configuration
    /// * `node_config` - The node configuration
    /// * `plugin` - The plugin to use for DIDComm operations
    pub fn new(
        config: ServerConfig,
        node_config: NodeConfig,
        plugin: impl DIDCommPlugin + 'static,
    ) -> Self {
        Self {
            config,
            node: DIDCommNode::new(node_config, plugin),
        }
    }

    /// Runs the server.
    ///
    /// # Returns
    ///
    /// A future that resolves when the server stops.
    pub async fn run(self) -> Result<()> {
        let node = web::Data::new(self.node);
        let config = self.config;

        HttpServer::new(move || {
            let allowed_origins = config.cors.allowed_origins.clone();
            let mut cors = Cors::default()
                .allowed_origin_fn(move |origin, _| {
                    let origin = origin.to_str().unwrap_or("");
                    allowed_origins
                        .iter()
                        .any(|allowed| allowed == "*" || allowed == origin)
                })
                .allowed_methods(vec!["GET", "POST"]);

            if config.cors.allow_credentials {
                cors = cors.supports_credentials();
            }

            App::new()
                .wrap(Logger::default())
                .wrap(cors)
                .app_data(node.clone())
                .service(receive_message)
                .service(send_message)
                .service(status)
        })
        .bind((config.host, config.port))
        .map_err(|e| crate::error::Error::Internal(format!("Failed to bind server: {}", e)))?
        .run()
        .await
        .map_err(|e| crate::error::Error::Internal(format!("Server error: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;
    use serde_json::json;
    use tap_didcomm_core::Message as CoreMessage;

    // Mock plugin (same as in node tests)
    struct MockPlugin;

    #[async_trait::async_trait]
    impl tap_didcomm_core::plugin::DIDResolver for MockPlugin {
        async fn resolve(&self, _did: &str) -> tap_didcomm_core::error::Result<String> {
            Ok("{}".to_string())
        }
    }

    #[async_trait::async_trait]
    impl tap_didcomm_core::plugin::Signer for MockPlugin {
        async fn sign(
            &self,
            message: &[u8],
            _from: &str,
        ) -> tap_didcomm_core::error::Result<Vec<u8>> {
            Ok(message.to_vec())
        }

        async fn verify(&self, _message: &[u8], _signature: &[u8], _from: &str) -> tap_didcomm_core::error::Result<bool> {
            Ok(true)
        }
    }

    #[async_trait::async_trait]
    impl tap_didcomm_core::plugin::Encryptor for MockPlugin {
        async fn encrypt(
            &self,
            message: &[u8],
            _to: Vec<String>,
            _from: Option<String>,
        ) -> tap_didcomm_core::error::Result<Vec<u8>> {
            Ok(message.to_vec())
        }

        async fn decrypt(
            &self,
            message: &[u8],
            _recipient: String,
        ) -> tap_didcomm_core::error::Result<Vec<u8>> {
            Ok(message.to_vec())
        }
    }

    impl tap_didcomm_core::plugin::DIDCommPlugin for MockPlugin {
        fn as_resolver(&self) -> &dyn tap_didcomm_core::plugin::DIDResolver {
            self
        }

        fn as_signer(&self) -> &dyn tap_didcomm_core::plugin::Signer {
            self
        }

        fn as_encryptor(&self) -> &dyn tap_didcomm_core::plugin::Encryptor {
            self
        }
    }

    #[actix_rt::test]
    async fn test_server() {
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            cors: CorsConfig {
                allowed_origins: vec!["*".to_string()],
                allow_credentials: true,
            },
        };

        let node_config = NodeConfig::default();
        let plugin = MockPlugin;

        let server = DIDCommServer::new(config, node_config, plugin);
        let node = web::Data::new(server.node);

        let app = test::init_service(
            App::new()
                .app_data(node.clone())
                .service(receive_message)
                .service(send_message)
                .service(status),
        )
        .await;

        // Test status endpoint
        let req = test::TestRequest::get().uri("/status").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
} 