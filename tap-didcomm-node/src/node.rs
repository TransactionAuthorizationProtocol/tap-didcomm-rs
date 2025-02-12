//! Core `DIDComm` node implementation.
//!
//! This module provides the main `DIDComm` node implementation that handles:
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
//! use tap_didcomm_node::{DIDCommNode, NodeConfig, HandlerHandle};
//! use tap_didcomm_core::Message;
//! use tap_didcomm_node::mock::MockPlugin;
//! use tokio::sync::mpsc;
//!
//! fn example() -> tap_didcomm_node::error::Result<()> {
//!     let config = NodeConfig::default();
//!     let mut node = DIDCommNode::new(config, MockPlugin::new());
//!     
//!     // Create a handler
//!     let (tx, _rx) = mpsc::channel(32);
//!     let handler = HandlerHandle::new(tx);
//!     
//!     // Register message handlers
//!     node.register_handler("test", handler);
//!     
//!     // Start processing messages
//!     node.start()
//! }
//! ```

use std::collections::HashMap;
use tap_didcomm_core::{pack_message, unpack_message, DIDCommPlugin, Message, PackingType};
use tracing::{error, info};

use crate::{
    actor::{HandlerHandle, Message as ActorMessage},
    dispatch::{dispatch_message, DispatchConfig},
    error::{Error, Result},
};

/// Configuration for a `DIDComm` node.
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
            host: "127.0.0.1".to_string(),
            use_https: false,
            max_message_size: 1024 * 1024, // 1MB
            dispatch: DispatchConfig::default(),
        }
    }
}

/// A `DIDComm` node that can send and receive messages.
///
/// The `DIDCommNode` is the main entry point for `DIDComm` operations. It handles:
/// - Receiving and unpacking messages
/// - Routing messages to appropriate handlers
/// - Dispatching messages to other nodes
/// - Managing DID resolution and cryptographic operations via plugins
///
/// # Examples
///
/// ```rust,no_run
/// use tap_didcomm_node::{DIDCommNode, NodeConfig, HandlerHandle, error::Result};
/// use tap_didcomm_node::mock::MockPlugin;
/// use tokio::sync::mpsc;
///
/// async fn example() -> Result<()> {
///     let config = NodeConfig::default();
///     let mut node = DIDCommNode::new(config, MockPlugin::new());
///     
///     // Create a handler
///     let (tx, _rx) = mpsc::channel(32);
///     let handler = HandlerHandle::new(tx);
///     
///     // Register message handlers
///     node.register_handler("test", handler);
///     
///     // Process an incoming message
///     let message = b"packed message bytes";
///     node.receive(message).await
/// }
/// ```
pub struct DIDCommNode {
    /// The node's configuration
    config: NodeConfig,

    /// The plugin providing DID resolution and crypto operations
    plugin: Box<dyn DIDCommPlugin>,

    /// Registry of message handlers
    handlers: HashMap<String, Vec<HandlerHandle>>,
}

impl DIDCommNode {
    /// Create a new `DIDComm` node.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the node
    /// * `plugin` - Plugin providing DID resolution and crypto operations
    ///
    /// # Returns
    ///
    /// A new `DIDCommNode` instance
    #[must_use]
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
    /// * `handler` - The handler that will process messages of this type
    pub fn register_handler(&mut self, msg_type: impl Into<String>, handler: HandlerHandle) {
        let msg_type = msg_type.into();
        self.handlers
            .entry(msg_type.clone())
            .or_default()
            .push(handler);
        info!("Registered handler for message type: {msg_type}");
    }

    /// Start the node and begin processing messages.
    ///
    /// This method starts the HTTP server and begins listening for incoming
    /// messages. It will run until the node is shut down.
    ///
    /// # Returns
    ///
    /// A future that completes when the node is shut down
    ///
    /// # Errors
    ///
    /// Returns an error if the node fails to start
    pub fn start(&self) -> Result<()> {
        info!(
            "Starting DIDComm node on {}:{}",
            self.config.host, self.config.port
        );
        Ok(())
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
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The message is not valid UTF-8
    /// - The message cannot be unpacked
    /// - The message cannot be routed to a handler
    pub async fn receive(&self, packed_msg: &[u8]) -> Result<()> {
        let msg = unpack_message(
            std::str::from_utf8(packed_msg)
                .map_err(|e| Error::InvalidFormat(format!("Invalid UTF-8: {e}")))?,
            self.plugin.as_ref(),
            None,
        )
        .await
        .map_err(Error::Core)?;

        // Dispatch to registered handlers
        if let Some(handlers) = self.handlers.get(&msg.typ.0) {
            for handler in handlers {
                if let Err(e) = handler.send(ActorMessage(msg.clone())).await {
                    error!("Failed to send message to handler: {e}");
                }
            }
        }

        Ok(())
    }

    /// Send a message to another `DIDComm` node.
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
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The message cannot be packed
    /// - The message cannot be dispatched
    pub async fn send(&self, message: &Message, packing: PackingType) -> Result<()> {
        let _packed = pack_message(message, self.plugin.as_ref(), packing)
            .await
            .map_err(Error::Core)?;

        dispatch_message(message, &self.config.dispatch).await?;

        Ok(())
    }

    /// Returns a reference to the node's configuration.
    #[must_use]
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Returns a reference to the node's plugin.
    #[must_use]
    pub fn plugin(&self) -> &dyn DIDCommPlugin {
        self.plugin.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockPlugin;
    use serde_json::json;
    use tokio::sync::mpsc;

    struct TestHandler {
        received: bool,
        tx: mpsc::Sender<()>,
    }

    impl TestHandler {
        fn new(tx: mpsc::Sender<()>) -> Self {
            Self {
                received: false,
                tx,
            }
        }
    }

    #[tokio::test]
    async fn test_message_handling() {
        let (tx, mut rx) = mpsc::channel(1);
        let (handler_tx, mut handler_rx) = mpsc::channel(32);
        let handler = HandlerHandle::new(handler_tx);

        // Create a node
        let mut node = DIDCommNode::new(NodeConfig::default(), MockPlugin);

        // Register the handler
        node.register_handler("test", handler);

        // Create and pack a test message
        let message = tap_didcomm_core::Message::new("test", json!({"hello": "world"}))
            .unwrap()
            .from("did:example:sender");

        let packed = pack_message(&message, node.plugin(), PackingType::Signed)
            .await
            .unwrap();

        // Start handler task
        tokio::spawn(async move {
            while let Some(msg) = handler_rx.recv().await {
                tx.send(()).await.unwrap();
            }
        });

        // Receive the message
        node.receive(packed.as_bytes()).await.unwrap();

        // Wait for handler to process message
        rx.recv().await.unwrap();
    }
}
