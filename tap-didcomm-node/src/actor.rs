//! Actor system integration for DIDComm message handling.
//!
//! This module provides the integration between the DIDComm node and the Actix actor system.
//! It allows messages to be handled asynchronously by actors, enabling flexible and
//! scalable message processing pipelines.
//!
//! # Architecture
//!
//! The actor system is built around two main components:
//! - `MessageHandler`: A trait that defines how actors handle DIDComm messages
//! - `HandlerRegistry`: A registry that maps message types to their handlers
//!
//! # Examples
//!
//! ```rust,no_run
//! use actix::prelude::*;
//! use tap_didcomm_node::actor::MessageHandler;
//! use tap_didcomm_core::Message;
//!
//! struct MyHandler;
//!
//! impl Actor for MyHandler {
//!     type Context = Context<Self>;
//! }
//!
//! impl MessageHandler for MyHandler {
//!     fn handle(&self, msg: Message) -> Result<(), Error> {
//!         // Process the message
//!         Ok(())
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use actix::prelude::*;
use tap_didcomm_core::Message as CoreMessage;

use crate::error::{Error, Result};

/// A wrapper type for DIDComm messages that can be handled by actors.
#[derive(Debug, Clone)]
pub struct Message(pub CoreMessage);

impl Message {
    /// Creates a new message.
    pub fn new(typ: impl Into<String>, body: impl Into<serde_json::Value>) -> Result<Self, serde_json::Error> {
        Ok(Self(CoreMessage::new(typ, body)?))
    }

    /// Sets the sender of the message.
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.0 = self.0.from(from);
        self
    }

    /// Sets the recipients of the message.
    pub fn to(mut self, to: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.0 = self.0.to(to);
        self
    }
}

impl From<CoreMessage> for Message {
    fn from(msg: CoreMessage) -> Self {
        Self(msg)
    }
}

impl actix::Message for Message {
    type Result = ();
}

/// A trait for actors that can handle DIDComm messages.
///
/// Implement this trait to create custom message handlers that can be
/// registered with the DIDComm node. Handlers receive unpacked messages
/// and can process them according to application-specific logic.
///
/// # Examples
///
/// ```rust,no_run
/// use tap_didcomm_node::actor::MessageHandler;
/// use tap_didcomm_core::Message;
///
/// struct MyHandler;
///
/// impl MessageHandler for MyHandler {
///     fn handle(&self, msg: Message) -> Result<(), Error> {
///         println!("Received message: {:?}", msg);
///         Ok(())
///     }
/// }
/// ```
pub trait MessageHandler: Actor {
    /// Handle a DIDComm message.
    ///
    /// This method is called when a message is received that matches
    /// the handler's registered type. The implementation should process
    /// the message and return Ok(()) on success, or an appropriate error
    /// if processing fails.
    ///
    /// # Arguments
    ///
    /// * `msg` - The unpacked DIDComm message to process
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure of message processing
    fn handle(&self, msg: Message) -> Result<()>;
}

/// A registry for message handlers.
///
/// The registry maps message types to their corresponding handlers, allowing
/// the node to dispatch messages to the appropriate actor based on the
/// message type.
///
/// # Examples
///
/// ```rust,no_run
/// use tap_didcomm_node::actor::HandlerRegistry;
///
/// let mut registry = HandlerRegistry::new();
/// registry.register("test", handler.recipient());
/// ```
#[derive(Default)]
pub struct HandlerRegistry {
    /// The mapping of message types to their handlers
    handlers: HashMap<String, Arc<Recipient<Message>>>,
}

impl HandlerRegistry {
    /// Create a new empty handler registry.
    ///
    /// # Returns
    ///
    /// A new HandlerRegistry instance
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for a specific message type.
    ///
    /// # Arguments
    ///
    /// * `msg_type` - The type of message to handle
    /// * `handler` - The actor recipient that will handle messages of this type
    pub fn register(&mut self, msg_type: &str, handler: Recipient<Message>) {
        self.handlers.insert(msg_type.to_string(), Arc::new(handler));
    }

    /// Get the handler for a specific message type.
    ///
    /// # Arguments
    ///
    /// * `msg_type` - The type of message to get the handler for
    ///
    /// # Returns
    ///
    /// An Option containing the handler if one is registered for the message type
    pub fn get_handler(&self, msg_type: &str) -> Option<Arc<Recipient<Message>>> {
        self.handlers.get(msg_type).cloned()
    }
}

/// A simple logging actor that logs all received messages.
pub struct LoggingActor {
    /// The name of this actor (for logging).
    name: String,
}

impl LoggingActor {
    /// Creates a new logging actor.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of this actor
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
        }
    }
}

impl Actor for LoggingActor {
    type Context = Context<Self>;
}

impl Handler<Message> for LoggingActor {
    type Result = ();

    fn handle(&mut self, msg: Message, _ctx: &mut Self::Context) {
        tracing::info!(
            actor = self.name,
            message_type = msg.0.typ.0,
            message_id = msg.0.id.0,
            "Received message"
        );
    }
}

impl MessageHandler for LoggingActor {
    fn handle(&self, msg: Message) -> Result<()> {
        self.handle(msg, &mut Context::new());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[actix_rt::test]
    async fn test_logging_actor() {
        // Create a logging actor
        let actor = LoggingActor::new("test").start();

        // Create a test message
        let message = Message::new("test", json!({"hello": "world"}))
            .unwrap()
            .from("did:example:alice")
            .to(vec!["did:example:bob"]);

        // Send the message to the actor
        actor.send(message).await.unwrap();
    }
} 