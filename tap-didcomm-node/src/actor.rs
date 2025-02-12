//! Lightweight actor system for DIDComm message handling.
//! 
//! This module provides a simple actor-based message handling system using Tokio channels.
//! It is designed to work in both native and WASM environments by using a single-threaded
//! runtime model.

use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tap_didcomm_core::Message as CoreMessage;
use tracing::{debug, error};
use serde_json::Value;

use crate::{
    error::{Error, Result},
    node::Node,
};

/// A DIDComm message wrapper
#[derive(Debug)]
pub struct Message(pub CoreMessage);

impl Message {
    /// Creates a new message with the given type and body
    pub fn new(typ: impl Into<String>, body: impl Into<serde_json::Value>) -> Result<Self> {
        let msg = CoreMessage::new(typ.into(), body.into())?;
        Ok(Message(msg))
    }

    /// Sets the sender of the message
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.0.from = Some(from.into());
        self
    }

    /// Sets the recipients of the message
    pub fn to(mut self, to: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.0.to = Some(to.into_iter().map(|s| s.into()).collect());
        self
    }
}

/// Messages that can be sent to the message handler actor
#[derive(Debug)]
pub enum HandlerMessage {
    /// Handle an incoming DIDComm message
    HandleMessage(Message, oneshot::Sender<Result<()>>),
    Process {
        message: CoreMessage,
        response: mpsc::Sender<Result<CoreMessage>>,
    },
}

/// A handle to a message handler actor
#[derive(Clone)]
pub struct HandlerHandle {
    sender: mpsc::Sender<HandlerMessage>,
}

impl HandlerHandle {
    /// Handles a DIDComm message
    pub async fn handle_message(&self, msg: Message) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(HandlerMessage::HandleMessage(msg, tx)).await
            .map_err(|_| tap_didcomm_core::error::Error::Actor("Failed to send message to handler".into()))?;
        rx.await
            .map_err(|_| tap_didcomm_core::error::Error::Actor("Handler was dropped".into()))?
    }

    pub async fn process(
        &self,
        typ: String,
        body: Value,
    ) -> Result<CoreMessage> {
        let mut msg = CoreMessage::new(typ);
        msg.body = body.to_string();
        
        let (tx, mut rx) = mpsc::channel(1);
        self.sender.send(HandlerMessage::Process {
            message: msg.clone(),
            response: tx,
        }).await.map_err(|_| Error::Actor("Failed to send message to actor".into()))?;

        rx.recv().await
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
    pub fn get_handlers(&self) -> &[HandlerHandle] {
        &self.handlers
    }
}

/// Spawns a new message handler actor
pub fn spawn_message_handler() -> HandlerHandle {
    let (tx, mut rx) = mpsc::channel(32);
    let handle = HandlerHandle { sender: tx };

    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                HandlerMessage::HandleMessage(message, reply_tx) => {
                    debug!("Handling message: {:?}", message);
                    // Add your message handling logic here
                    let result = Ok(());
                    if reply_tx.send(result).is_err() {
                        error!("Failed to send reply");
                    }
                }
            }
        }
    });

    handle
}

pub struct Handler {
    node: Arc<Node>,
}

impl Handler {
    pub fn new(node: Arc<Node>) -> Self {
        Self { node }
    }

    pub async fn run(self, mut rx: mpsc::Receiver<HandlerMessage>) -> Result<()> {
        while let Some(msg) = rx.recv().await {
            match msg {
                HandlerMessage::Process { message, response } => {
                    let result = self.node.process_message(message).await;
                    let _ = response.send(result).await;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Builder;
    use serde_json::json;

    #[test]
    fn test_message_handler() {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let handler = spawn_message_handler();
            let msg = Message::new("test", serde_json::json!({"test": "data"})).unwrap();
            
            let result = handler.handle_message(msg).await;
            assert!(result.is_ok());
        });
    }

    #[tokio::test]
    async fn test_handler() {
        let node = Arc::new(Node::new());
        let (tx, _rx) = mpsc::channel(32);
        let handle = HandlerHandle { sender: tx };

        let result = handle.process(
            "test".into(),
            json!({"test": "value"})
        ).await;

        assert!(result.is_ok());
    }
} 