//! Actor system integration for DIDComm message handling.

use actix::prelude::*;
use tap_didcomm_core::Message as CoreMessage;

/// A wrapper type for DIDComm messages that can be handled by actors.
#[derive(Debug, Clone)]
pub struct Message(pub CoreMessage);

impl From<CoreMessage> for Message {
    fn from(msg: CoreMessage) -> Self {
        Self(msg)
    }
}

impl actix::Message for Message {
    type Result = ();
}

/// A trait for actors that can handle DIDComm messages.
pub trait MessageHandler: Actor {
    /// Handles a DIDComm message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to handle
    /// * `ctx` - The actor context
    fn handle_message(&mut self, message: Message, ctx: &mut Self::Context);
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
    fn handle_message(&mut self, message: Message, ctx: &mut Self::Context) {
        self.handle(message, ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[actix_rt::test]
    async fn test_logging_actor() {
        let sys = actix_rt::System::new();

        sys.block_on(async {
            // Create a logging actor
            let actor = LoggingActor::new("test").start();

            // Create a test message
            let message = Message::new("test", json!({"hello": "world"}))
                .unwrap()
                .from("did:example:alice")
                .to(vec!["did:example:bob"]);

            // Send the message to the actor
            actor.send(message).await.unwrap();
        });
    }
} 