//! Core DIDComm v2 type definitions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// A DIDComm message type identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageType(pub String);

/// Represents a DIDComm message ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub String);

impl MessageId {
    /// Create a new message ID
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Create a new random message ID
    pub fn random() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Get the message ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Represents a DIDComm message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// The message ID
    pub id: MessageId,
    /// The message type
    pub typ: MessageType,
    /// The sender's DID
    pub from: Option<String>,
    /// The recipient's DIDs
    pub to: Option<Vec<String>>,
    /// The time the message was created
    pub created_time: u64,
    /// The time the message expires
    pub expires_time: Option<u64>,
    /// The message body
    pub body: serde_json::Value,
    /// Message attachments
    pub attachments: Option<Vec<Attachment>>,
}

impl Message {
    /// Create a new message
    pub fn new(typ: impl Into<String>, body: impl Into<serde_json::Value>) -> Result<Self, serde_json::Error> {
        Ok(Self {
            id: MessageId::random(),
            typ: MessageType(typ.into()),
            from: None,
            to: None,
            created_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            expires_time: None,
            body: body.into(),
            attachments: None,
        })
    }

    /// Set the sender of the message
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Set the recipients of the message
    pub fn to(mut self, to: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.to = Some(to.into_iter().map(Into::into).collect());
        self
    }
}

/// Represents a message attachment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// The attachment ID
    pub id: String,
    /// The attachment description
    pub description: Option<String>,
    /// The attachment filename
    pub filename: Option<String>,
    /// The attachment media type
    pub media_type: Option<String>,
    /// The attachment format
    pub format: Option<String>,
    /// The attachment data
    pub data: AttachmentData,
}

/// Represents attachment data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttachmentData {
    /// JWS data
    Jws(serde_json::Value),
    /// Hash data
    Hash(serde_json::Value),
    /// Links data
    Links(Vec<String>),
    /// Base64 data
    Base64(String),
    /// JSON data
    Json(serde_json::Value),
}

/// The type of message packing to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackingType {
    /// No encryption, just signed
    Signed,
    /// Authenticated encryption with sender identity
    AuthcryptV2,
    /// Anonymous encryption without sender identity
    AnonV2,
}

impl Default for PackingType {
    fn default() -> Self {
        PackingType::Signed
    }
}

/// A DIDComm message header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    /// The message ID.
    pub id: MessageId,
    /// The message type.
    #[serde(rename = "type")]
    pub typ: MessageType,
    /// The sender's DID.
    pub from: Option<String>,
    /// The recipient's DID.
    pub to: Option<Vec<String>>,
    /// The time the message was created.
    pub created_time: Option<u64>,
    /// The time the message expires.
    pub expires_time: Option<u64>,
    /// Additional headers.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// The body of a DIDComm message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    /// The message content.
    #[serde(flatten)]
    pub content: serde_json::Value,
    /// Message attachments.
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

/// A packed DIDComm message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackedMessage {
    /// The packed message data.
    pub data: String,
    /// The type of packing used.
    #[serde(skip)]
    pub packing: PackingType,
}

impl MessageType {
    /// Create a new message type
    pub fn new(typ: String) -> Self {
        Self(typ)
    }

    /// Get the message type as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_message_serialization() {
        let message = Message {
            id: MessageId::new("test".to_string()),
            typ: MessageType::new("test".to_string()),
            from: Some("did:example:alice".to_string()),
            to: Some(vec!["did:example:bob".to_string()]),
            created_time: 0,
            expires_time: None,
            body: json!("world"),
            attachments: None,
        };

        let json = serde_json::to_string(&message).unwrap();
        let deserialized: Message = serde_json::from_str(&json).unwrap();

        assert_eq!(message.id.as_str(), deserialized.id.as_str());
        assert_eq!(message.typ.as_str(), deserialized.typ.as_str());
        assert_eq!(message.from, deserialized.from);
        assert_eq!(message.to, deserialized.to);
    }

    #[test]
    fn test_packed_message_serialization() {
        let packed = PackedMessage {
            data: "test".to_string(),
            packing: PackingType::Signed,
        };

        let json = serde_json::to_string(&packed).unwrap();
        let deserialized: PackedMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(packed.data, deserialized.data);
        assert_eq!(packed.packing, deserialized.packing);
    }
} 