//! `DIDComm` message type and related functionality.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A `DIDComm` message.
///
/// This structure represents a basic message that can be packed and unpacked
/// using different methods (signed, authcrypt, anoncrypt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// The unique identifier for this message
    pub id: String,

    /// The message body/content
    pub body: String,

    /// The DID of the sender (optional for anonymous messages)
    pub from: Option<String>,

    /// The DIDs of the recipients
    pub to: Option<Vec<String>>,
}

impl Message {
    /// Creates a new message with the given body.
    #[must_use]
    pub fn new(body: String) -> Message {
        Message {
            id: Uuid::new_v4().to_string(),
            body,
            from: None,
            to: None,
        }
    }

    /// Sets the sender of the message.
    #[must_use]
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Sets the recipients of the message.
    #[must_use]
    pub fn to(mut self, to: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.to = Some(to.into_iter().map(Into::into).collect());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let message = Message::new("test".to_string())
            .from("did:example:alice")
            .to(vec!["did:example:bob"]);

        assert_eq!(message.body, "test");
        assert_eq!(message.from, Some("did:example:alice".to_string()));
        assert_eq!(message.to, Some(vec!["did:example:bob".to_string()]));
    }
}
