//! DIDComm HTTP server implementation.

use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpServer};
use tap_didcomm_core::plugin::DIDCommPlugin;
use tap_didcomm_node::{DIDCommNode, NodeConfig};
use tracing::info;

use crate::{
    error::{Error, Result},
    handlers::{get_status, receive_message, send_message},
};

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

/// CORS configuration.
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins.
    pub allowed_origins: Vec<String>,
    /// Whether to allow credentials.
    pub allow_credentials: bool,
}

/// A DIDComm HTTP server.
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

    /// Starts the server.
    ///
    /// # Returns
    ///
    /// A future that resolves when the server has started.
    pub async fn run(self) -> Result<()> {
        info!(
            "Starting DIDComm server on {}:{}",
            self.config.host, self.config.port
        );

        // Create the node data
        let node_data = web::Data::new(self.node);

        // Create CORS middleware
        let cors = Cors::default()
            .allowed_origin_fn(move |origin, _| {
                let origin = origin.to_str().unwrap_or("");
                self.config
                    .cors
                    .allowed_origins
                    .iter()
                    .any(|allowed| allowed == "*" || allowed == origin)
            })
            .allow_methods(vec!["GET", "POST"])
            .allow_headers(vec!["Content-Type"])
            .supports_credentials(self.config.cors.allow_credentials);

        // Start the server
        HttpServer::new(move || {
            App::new()
                .app_data(node_data.clone())
                .wrap(middleware::Logger::default())
                .wrap(cors.clone())
                .service(receive_message)
                .service(send_message)
                .service(get_status)
        })
        .bind((self.config.host, self.config.port))
        .map_err(|e| Error::Internal(format!("Failed to bind server: {}", e)))?
        .run()
        .await
        .map_err(|e| Error::Internal(format!("Server error: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;
    use serde_json::json;
    use tap_didcomm_core::types::PackingType;

    // Mock plugin (same as in handlers tests)
    struct MockPlugin;

    #[async_trait::async_trait]
    impl tap_didcomm_core::plugin::DIDResolver for MockPlugin {
        async fn resolve(&self, _did: &str) -> tap_didcomm_core::error::Result<serde_json::Value> {
            Ok(json!({}))
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

        async fn verify(&self, _message: &[u8], _from: &str) -> tap_didcomm_core::error::Result<()> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl tap_didcomm_core::plugin::Encryptor for MockPlugin {
        async fn encrypt(
            &self,
            message: &[u8],
            _to: &[String],
            _from: Option<&str>,
        ) -> tap_didcomm_core::error::Result<tap_didcomm_core::types::PackedMessage> {
            Ok(tap_didcomm_core::types::PackedMessage {
                data: String::from_utf8(message.to_vec()).unwrap(),
                packing: self.packing_type(),
            })
        }

        async fn decrypt(
            &self,
            message: &tap_didcomm_core::types::PackedMessage,
            _to: &str,
        ) -> tap_didcomm_core::error::Result<Vec<u8>> {
            Ok(message.data.as_bytes().to_vec())
        }

        fn packing_type(&self) -> PackingType {
            PackingType::Plain
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
    async fn test_server_config() {
        let server = DIDCommServer::new(
            ServerConfig {
                host: "127.0.0.1".into(),
                port: 8080,
                cors: CorsConfig {
                    allowed_origins: vec!["*".into()],
                    allow_credentials: true,
                },
            },
            NodeConfig {
                did: "did:example:node".into(),
                default_packing: PackingType::Plain,
                base_url: Some("http://localhost:8080".into()),
            },
            MockPlugin,
        );

        assert_eq!(server.config.host, "127.0.0.1");
        assert_eq!(server.config.port, 8080);
        assert_eq!(server.config.cors.allowed_origins, vec!["*"]);
        assert!(server.config.cors.allow_credentials);
    }
} 