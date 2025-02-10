//! DIDComm node implementation.

use actix::prelude::*;
use std::collections::HashMap;
use tap_didcomm_core::{
    plugin::DIDCommPlugin,
    types::PackingType,
};
use tracing::{debug, error, info};

use crate::{
    actor::Message,
    error::{Error, Result},
};

/// Configuration for a DIDComm node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// The DID of this node.
    pub did: String,
    /// The default packing type to use for outgoing messages.
    pub default_packing: PackingType,
    /// The base URL for this node (used for receiving messages).
    pub base_url: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            did: "did:example:default".to_string(),
            default_packing: PackingType::Signed,
            base_url: None,
        }
    }
}

/// A DIDComm node that can receive and process messages.
pub struct DIDCommNode {
    /// The node's configuration.
    config: NodeConfig,
    /// The plugin to use for DIDComm operations.
    plugin: Box<dyn DIDCommPlugin>,
    /// Registered message handlers.
    handlers: HashMap<String, Vec<Recipient<Message>>>,
}

impl DIDCommNode {
    /// Creates a new DIDComm node.
    ///
    /// # Arguments
    ///
    /// * `config` - The node configuration
    /// * `plugin` - The plugin to use for DIDComm operations
    pub fn new(config: NodeConfig, plugin: impl DIDCommPlugin + 'static) -> Self {
        Self {
            config,
            plugin: Box::new(plugin),
            handlers: HashMap::new(),
        }
    }

    /// Registers a message handler for a specific message type.
    ///
    /// # Arguments
    ///
    /// * `message_type` - The message type to handle
    /// * `handler` - The actor that will handle messages of this type
    pub fn register_handler(
        &mut self,
        message_type: impl Into<String>,
        handler: Recipient<Message>,
    ) {
        let message_type = message_type.into();
        self.handlers
            .entry(message_type.clone())
            .or_default()
            .push(handler);
        info!("Registered handler for message type: {}", message_type);
    }

    /// Receives and processes a DIDComm message.
    ///
    /// # Arguments
    ///
    /// * `packed_message` - The packed message to process
    ///
    /// # Returns
    ///
    /// A future that resolves when the message has been processed.
    pub async fn receive(&self, packed_message: &str) -> Result<()> {
        debug!("Received message: {}", packed_message);

        // Unpack the message
        let message = tap_didcomm_core::pack::unpack_message(
            packed_message,
            &*self.plugin,
            Some(self.config.did.clone()),
        )
        .await
        .map_err(Error::Core)?;

        // Find handlers for this message type
        if let Some(handlers) = self.handlers.get(&message.typ.0) {
            for handler in handlers {
                // Send the message to each handler
                if let Err(e) = handler.send(Message(message.clone())).await {
                    error!("Failed to send message to handler: {}", e);
                }
            }
        } else {
            debug!("No handlers registered for message type: {}", message.typ.0);
        }

        Ok(())
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
        let sys = actix_rt::System::new();

        sys.block_on(async {
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
            let message = CoreMessage::new("test", json!({"hello": "world"}))
                .unwrap()
                .to(vec!["did:example:node"]);

            let packed = tap_didcomm_core::pack::pack_message(&message, &MockPlugin, PackingType::Signed)
                .await
                .unwrap();

            // Receive the message
            node.receive(&packed).await.unwrap();
        });
    }
} 