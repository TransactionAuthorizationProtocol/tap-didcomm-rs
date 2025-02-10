//! HTTP server implementation.

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use tap_didcomm_core::plugin::DIDCommPlugin;
use tap_didcomm_node::{DIDCommNode, NodeConfig};
use actix::Recipient;
use tap_didcomm_node::actor::Message;
use std::sync::{Arc, Mutex};

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
    node: Arc<Mutex<DIDCommNode>>,
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
            node: Arc::new(Mutex::new(DIDCommNode::new(node_config, plugin))),
        }
    }

    /// Gets a reference to the underlying node.
    pub fn get_node(&self) -> Arc<Mutex<DIDCommNode>> {
        self.node.clone()
    }

    /// Register a message handler with the node.
    pub fn register_handler(&self, message_type: &str, handler: Recipient<Message>) {
        if let Ok(mut node) = self.node.lock() {
            node.register_handler(message_type, handler);
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
    use crate::tests::MockPlugin;
    use actix::Actor;
    use tap_didcomm_node::actor::LoggingActor;

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
                .app_data(node_data)
                .service(receive_message)
                .service(send_message)
                .service(status),
        )
        .await;

        // Test status endpoint
        let req = test::TestRequest::post().uri("/status").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
} 