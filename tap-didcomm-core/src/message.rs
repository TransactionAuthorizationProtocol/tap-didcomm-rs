//! DIDComm message type and related functionality.

use serde::{Deserialize, Serialize};

/// A DIDComm message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// The message body.
    pub body: String,
    /// The DID of the sender.
    pub from: Option<String>,
    /// The DIDs of the recipients.
    pub to: Option<Vec<String>>,
}

impl Message {
    /// Creates a new message with the given content.
    ///
    /// # Arguments
    ///
    /// * `body` - The message content as a string
    pub fn new(body: String) -> Message {
        Message {
            body,
            from: None,
            to: None,
        }
    }

    /// Sets the sender of the message.
    ///
    /// # Arguments
    ///
    /// * `from` - The DID of the sender
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Sets the recipients of the message.
    ///
    /// # Arguments
    ///
    /// * `to` - The DIDs of the recipients
    pub fn to(mut self, to: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.to = Some(to.into_iter().map(Into::into).collect());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_new() {
        let message = Message::new("test".to_string());
        assert_eq!(message.body, "test");
        assert_eq!(message.from, None);
        assert_eq!(message.to, None);
    }

    #[test]
    fn test_message_builder() {
        let message = Message::new("test".to_string())
            .from("did:example:sender")
            .to(vec!["did:example:recipient1", "did:example:recipient2"]);

        assert_eq!(message.from, Some("did:example:sender".to_string()));
        assert_eq!(
            message.to,
            Some(vec![
                "did:example:recipient1".to_string(),
                "did:example:recipient2".to_string()
            ])
        );
    }
} 