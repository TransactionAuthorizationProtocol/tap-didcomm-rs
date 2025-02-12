//! Lightweight actor system for `DIDComm` message handling.
//!
//! This module provides a simple actor-based message handling system using Tokio channels.
//! It is designed to work in both native and WASM environments by using a single-threaded
//! runtime model.

use std::sync::Arc;
use tap_didcomm_core::Message as CoreMessage;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error};

use crate::{
    error::{Error, Result},
    node::DIDCommNode,
};

/// A `DIDComm` message wrapper
#[derive(Debug, Clone)]
pub struct Message(pub CoreMessage);

impl Message {
    /// Creates a new message with the given type and body
    ///
    /// # Arguments
    ///
    /// * `typ` - The message type
    /// * `body` - The message body
    ///
    /// # Returns
    ///
    /// A new message instance
    ///
    /// # Errors
    ///
    /// Returns an error if the message creation fails
    pub fn new(typ: impl Into<String>, body: impl Into<serde_json::Value>) -> Result<Self> {
        let msg = CoreMessage::new(typ.into(), body.into())?;
        Ok(Message(msg))
    }

    /// Sets the sender of the message
    ///
    /// # Arguments
    ///
    /// * `from` - The sender's DID
    #[must_use]
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.0.from = Some(from.into());
        self
    }

    /// Sets the recipients of the message
    ///
    /// # Arguments
    ///
    /// * `to` - The recipients' DIDs
    #[must_use]
    pub fn to(mut self, to: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.0.to = Some(to.into_iter().map(Into::into).collect());
        self
    }
}

/// Messages that can be sent to the message handler actor
#[derive(Debug)]
pub enum HandlerMessage {
    /// Handle an incoming `DIDComm` message
    HandleMessage(Message, oneshot::Sender<Result<()>>),
    /// Process a message and return a response
    Process {
        /// The message to process
        message: CoreMessage,
        /// Channel for sending the response back
        response: mpsc::Sender<Result<CoreMessage>>,
    },
}

/// A handle to a message handler actor
#[derive(Clone)]
pub struct HandlerHandle {
    sender: mpsc::Sender<HandlerMessage>,
}

impl HandlerHandle {
    /// Creates a new handler handle
    ///
    /// # Arguments
    ///
    /// * `sender` - The channel sender for the handler
    #[must_use]
    pub fn new(sender: mpsc::Sender<HandlerMessage>) -> Self {
        Self { sender }
    }

    /// Sends a message to the handler
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to send
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The message cannot be sent
    /// - The handler has been dropped
    pub async fn send(&self, msg: Message) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(HandlerMessage::HandleMessage(msg, tx))
            .await
            .map_err(|_| Error::Actor("Failed to send message to handler".into()))?;
        rx.await
            .map_err(|_| Error::Actor("Handler was dropped".into()))?
    }

    /// Process a message and return a response
    ///
    /// # Arguments
    ///
    /// * `message` - The message to process
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The message cannot be processed
    /// - The handler has been dropped
    pub async fn process(&self, message: CoreMessage) -> Result<CoreMessage> {
        let (tx, mut rx) = mpsc::channel(1);
        self.sender
            .send(HandlerMessage::Process {
                message: message.clone(),
                response: tx,
            })
            .await
            .map_err(|_| Error::Actor("Failed to send message to actor".into()))?;

        rx.recv()
            .await
            .ok_or_else(|| Error::Actor("Failed to receive response from actor".into()))?
    }
}

/// Registry for message handlers
#[derive(Default)]
pub struct HandlerRegistry {
    handlers: Vec<HandlerHandle>,
}

impl HandlerRegistry {
    /// Creates a new empty registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Registers a new message handler
    pub fn register(&mut self, handler: HandlerHandle) {
        self.handlers.push(handler);
    }

    /// Gets all registered handlers
    #[must_use]
    pub fn get_handlers(&self) -> &[HandlerHandle] {
        &self.handlers
    }
}

/// Spawns a new message handler actor
#[must_use]
pub fn spawn_message_handler() -> HandlerHandle {
    let (tx, mut rx) = mpsc::channel(32);
    let handle = HandlerHandle::new(tx);

    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                HandlerMessage::HandleMessage(message, reply_tx) => {
                    debug!("Handling message: {message:?}");
                    // Add your message handling logic here
                    let result = Ok(());
                    if reply_tx.send(result).is_err() {
                        error!("Failed to send reply");
                    }
                }
                HandlerMessage::Process { message, response } => {
                    debug!("Processing message: {message:?}");
                    // Add your message processing logic here
                    let result = Ok(message);
                    if response.send(result).await.is_err() {
                        error!("Failed to send response");
                    }
                }
            }
        }
    });

    handle
}

/// A message handler that processes messages using a `DIDComm` node
pub struct Handler {
    node: Arc<DIDCommNode>,
}

impl Handler {
    /// Creates a new handler with the given node
    ///
    /// # Arguments
    ///
    /// * `node` - The `DIDComm` node to use for processing
    #[must_use]
    pub fn new(node: Arc<DIDCommNode>) -> Self {
        Self { node }
    }

    /// Runs the handler, processing messages from the given channel
    ///
    /// # Arguments
    ///
    /// * `rx` - The channel receiver for incoming messages
    ///
    /// # Errors
    ///
    /// Returns an error if message processing fails
    pub async fn run(self, mut rx: mpsc::Receiver<HandlerMessage>) -> Result<()> {
        while let Some(msg) = rx.recv().await {
            match msg {
                HandlerMessage::HandleMessage(message, reply_tx) => {
                    debug!("Handling message: {message:?}");
                    let result = Ok(());
                    if reply_tx.send(result).is_err() {
                        error!("Failed to send reply");
                    }
                }
                HandlerMessage::Process { message, response } => {
                    debug!("Processing message: {message:?}");
                    // Add your message processing logic here
                    let result = Ok(message);
                    if response.send(result).await.is_err() {
                        error!("Failed to send response");
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::NodeConfig;
    use serde_json::json;
    use tokio::runtime::Builder;

    #[test]
    fn test_message_handler() {
        let rt = Builder::new_current_thread().enable_all().build().unwrap();

        rt.block_on(async {
            let handler = spawn_message_handler();
            let msg = Message::new("test", json!({"test": "data"})).unwrap();

            let result = handler.send(msg).await;
            assert!(result.is_ok());
        });
    }

    #[tokio::test]
    async fn test_handler() {
        let config = NodeConfig::default();
        let node = Arc::new(DIDCommNode::new(config, crate::mock::MockPlugin));
        let (tx, rx) = mpsc::channel(32);
        let handle = HandlerHandle::new(tx);
        let handler = Handler::new(node);

        tokio::spawn(handler.run(rx));

        let result = handle
            .process(CoreMessage::new("test", json!({"test": "value"})).unwrap())
            .await;

        assert!(result.is_ok());
    }
}
