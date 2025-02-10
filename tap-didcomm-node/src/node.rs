//! Core DIDComm node implementation.
//!
//! This module provides the main DIDComm node implementation that handles:
//! - Message receiving and unpacking
//! - Message routing to appropriate handlers
//! - Message dispatch to other nodes
//! - Plugin management for DID resolution and cryptographic operations
//!
//! # Architecture
//!
//! The node is built around these main components:
//! - `DIDCommNode`: The main node struct that coordinates all operations
//! - `NodeConfig`: Configuration options for the node
//! - `HandlerRegistry`: Registry of message handlers (from the actor module)
//!
//! # Examples
//!
//! ```rust,no_run
//! use tap_didcomm_node::{DIDCommNode, NodeConfig};
//! use tap_didcomm_core::Message;
//!
//! async fn example() {
//!     let config = NodeConfig::default();
//!     let mut node = DIDCommNode::new(config, your_plugin);
//!
//!     // Register message handlers
//!     node.register_handler("test", your_handler.recipient());
//!
//!     // Start processing messages
//!     node.start().await;
//! }
//! ```

use actix::prelude::*;
use std::collections::HashMap;
use tap_didcomm_core::{
    plugin::DIDCommPlugin,
    types::PackingType,
    error::Error as CoreError,
};
use tracing::{debug, error, info};

use crate::{
    actor::Message,
    error::{Error, Result},
};

/// Configuration options for a DIDComm node.
///
/// This struct contains all the configuration parameters that control
/// how the node operates, including networking, message handling,
/// and security settings.
///
/// # Examples
///
/// ```rust
/// use tap_didcomm_node::NodeConfig;
///
/// let config = NodeConfig {
///     port: 8080,
///     host: "localhost".to_string(),
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// The port to listen on for incoming messages
    pub port: u16,

    /// The host address to bind to
    pub host: String,

    /// Whether to use HTTPS for incoming connections
    pub use_https: bool,

    /// The maximum size of incoming messages in bytes
    pub max_message_size: usize,

    /// Configuration for message dispatch
    pub dispatch: DispatchConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            port: 8080,
            host: "localhost".to_string(),
            use_https: false,
            max_message_size: 1024 * 1024, // 1MB
            dispatch: DispatchConfig::default(),
        }
    }
}

/// A DIDComm node that can send and receive messages.
///
/// The DIDCommNode is the main entry point for DIDComm operations. It handles:
/// - Receiving and unpacking messages
/// - Routing messages to appropriate handlers
/// - Dispatching messages to other nodes
/// - Managing DID resolution and cryptographic operations via plugins
///
/// # Examples
///
/// ```rust,no_run
/// use tap_didcomm_node::{DIDCommNode, NodeConfig};
///
/// async fn example() {
///     let config = NodeConfig::default();
///     let mut node = DIDCommNode::new(config, your_plugin);
///
///     // Register a message handler
///     node.register_handler("test", your_handler.recipient());
///
///     // Process an incoming message
///     node.receive(&packed_message).await?;
/// }
/// ```
pub struct DIDCommNode {
    /// The node's configuration
    config: NodeConfig,

    /// The plugin providing DID resolution and crypto operations
    plugin: Box<dyn DIDCommPlugin>,

    /// Registry of message handlers
    handlers: HashMap<String, Vec<Recipient<Message>>>,
}

impl DIDCommNode {
    /// Create a new DIDComm node.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the node
    /// * `plugin` - Plugin providing DID resolution and crypto operations
    ///
    /// # Returns
    ///
    /// A new DIDCommNode instance
    pub fn new(config: NodeConfig, plugin: impl DIDCommPlugin + 'static) -> Self {
        Self {
            config,
            plugin: Box::new(plugin),
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for a specific message type.
    ///
    /// # Arguments
    ///
    /// * `msg_type` - The type of message to handle
    /// * `handler` - The actor recipient that will handle messages of this type
    pub fn register_handler(
        &mut self,
        msg_type: impl Into<String>,
        handler: Recipient<Message>,
    ) {
        let msg_type = msg_type.into();
        self.handlers
            .entry(msg_type.clone())
            .or_default()
            .push(handler);
        info!("Registered handler for message type: {}", msg_type);
    }

    /// Start the node and begin processing messages.
    ///
    /// This method starts the HTTP server and begins listening for incoming
    /// messages. It will run until the node is shut down.
    ///
    /// # Returns
    ///
    /// A future that completes when the node is shut down
    pub async fn start(&self) -> Result<()> {
        // Implementation details...
        unimplemented!()
    }

    /// Process an incoming packed message.
    ///
    /// This method unpacks a received message and routes it to the appropriate
    /// handler based on its type.
    ///
    /// # Arguments
    ///
    /// * `packed_msg` - The packed message to process
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure of message processing
    pub async fn receive(&self, packed_msg: &[u8]) -> Result<()> {
        // Implementation details...
        unimplemented!()
    }

    /// Send a message to another DIDComm node.
    ///
    /// This method packs and dispatches a message to its intended recipient.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to send
    /// * `packing` - The packing type to use
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure of message sending
    pub async fn send(&self, message: &Message, packing: PackingType) -> Result<()> {
        // Implementation details...
        unimplemented!()
    }

    /// Returns a reference to the node's configuration.
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Returns a reference to the node's plugin.
    pub fn plugin(&self) -> &dyn DIDCommPlugin {
        &*self.plugin
    }
}

impl From<CoreError> for Error {
    fn from(err: CoreError) -> Self {
        Error::Core(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::Actor;
    use serde_json::json;

    // Mock message handler actor
    struct MockHandler {
        received: bool,
    }

    impl Actor for MockHandler {
        type Context = Context<Self>;
    }

    impl Handler<Message> for MockHandler {
        type Result = ();

        fn handle(&mut self, _msg: Message, _ctx: &mut Self::Context) {
            self.received = true;
        }
    }

    impl MockHandler {
        fn new() -> Self {
            Self { received: false }
        }
    }

    // Mock plugin
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
    async fn test_receive_message() {
        // Create a mock handler
        let handler = MockHandler::new().start();

        // Create a node
        let mut node = DIDCommNode::new(
            NodeConfig {
                did: "did:example:node".into(),
                default_packing: PackingType::Signed,
                base_url: None,
            },
            MockPlugin,
        );

        // Register the handler
        node.register_handler("test", handler.recipient());

        // Create and pack a test message
        let message = tap_didcomm_core::Message::new("test", json!({"hello": "world"}))
            .unwrap()
            .from("did:example:alice")
            .to(vec!["did:example:node"]);

        let packed = tap_didcomm_core::pack::pack_message(&message, &MockPlugin, PackingType::Signed)
            .await
            .unwrap();

        // Receive the message
        node.receive(&packed).await.unwrap();
    }

    #[tokio::test]
    async fn test_message_handling() {
        let _message = tap_didcomm_core::Message::new("test", json!({"hello": "world"}))
            .unwrap()
            .to(vec!["did:example:bob".to_string()])
            .from("did:example:alice");
        // ... rest of the test ...
    }
} 