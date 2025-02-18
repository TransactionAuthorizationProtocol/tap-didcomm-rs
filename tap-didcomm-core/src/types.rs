//! Core `DIDComm` v2 type definitions.
//!
//! This module contains the fundamental types used throughout the `DIDComm` v2 implementation,
//! including messages, attachments, and packing types.
//! All types follow the `DIDComm` v2 specification and support both native and WASM environments.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// A `DIDComm` message type identifier.
///
/// This type represents the protocol and message type in a `DIDComm` message.
/// For example: <https://didcomm.org/basicmessage/2.0/message>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageType(pub String);

/// A unique identifier for a `DIDComm` message.
///
/// Each message in `DIDComm` must have a unique identifier. This is typically
/// a UUID v4, but can be any string that is unique within the context of the
/// sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageId(pub String);

impl MessageId {
    /// Creates a new message ID from a string.
    #[must_use]
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Creates a new random message ID using UUID v4.
    #[must_use]
    pub fn random() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Gets the string representation of the message ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::random()
    }
}

impl Default for MessageType {
    fn default() -> Self {
        Self("https://didcomm.org/message/1.0".to_string())
    }
}

/// A complete `DIDComm` message.
///
/// This structure represents a `DIDComm` message with all its components as defined
/// in the `DIDComm` v2 specification. It includes the message ID, type, sender,
/// recipients, timestamps, and body content.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Message {
    /// The unique identifier for this message
    pub id: MessageId,

    /// The message type that defines the protocol and message purpose
    pub typ: MessageType,

    /// The DID of the sender (optional for anonymous messages)
    pub from: Option<String>,

    /// The DIDs of the recipients
    pub to: Option<Vec<String>>,

    /// Unix timestamp when the message was created
    pub created_time: u64,

    /// Unix timestamp when the message expires (optional)
    pub expires_time: Option<u64>,

    /// The actual content/payload of the message
    pub body: serde_json::Value,

    /// Optional attachments to the message
    pub attachments: Option<Vec<Attachment>>,
}

impl Message {
    /// Creates a new `DIDComm` message.
    ///
    /// # Errors
    /// Returns an error if the system time cannot be obtained.
    pub fn new(
        typ: impl Into<String>,
        body: impl Into<serde_json::Value>,
    ) -> crate::error::Result<Self> {
        let created_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        Ok(Self {
            id: MessageId::random(),
            typ: MessageType(typ.into()),
            from: None,
            to: None,
            created_time,
            expires_time: None,
            body: body.into(),
            attachments: None,
        })
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

    /// Sets the expiration time of the message.
    #[must_use]
    pub fn expires_at(mut self, expires_time: u64) -> Self {
        self.expires_time = Some(expires_time);
        self
    }

    /// Adds an attachment to the message.
    #[must_use]
    pub fn with_attachment(mut self, attachment: Attachment) -> Self {
        match &mut self.attachments {
            Some(attachments) => attachments.push(attachment),
            None => self.attachments = Some(vec![attachment]),
        }
        self
    }
}

/// An attachment to a `DIDComm` message.
///
/// Attachments can contain additional data that is associated with the message,
/// such as files, images, or other binary content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// Unique identifier for the attachment
    pub id: String,

    /// Optional human-readable description
    pub description: Option<String>,

    /// Optional filename for the attachment
    pub filename: Option<String>,

    /// Optional MIME type of the attachment
    pub media_type: Option<String>,

    /// Optional format identifier
    pub format: Option<String>,

    /// The actual attachment data
    pub data: AttachmentData,
}

/// The data formats that can be used for attachments
///
/// This enum represents the different ways data can be attached
/// in a `DIDComm` message, such as JWS, base64-encoded data, or JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttachmentData {
    /// JWS (JSON Web Signature) data
    Jws(serde_json::Value),

    /// Hash of the data for integrity verification
    Hash(serde_json::Value),

    /// Links to external resources
    Links(Vec<String>),

    /// Base64-encoded binary data
    Base64(String),

    /// Direct JSON data
    Json(serde_json::Value),
}

/// `DIDComm` v2 supports three types of message packing:
/// - Signed: No encryption, just signed
/// - `AuthcryptV2`: Authenticated encryption with sender identity
/// - `AnonV2`: Anonymous encryption without sender identity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PackingType {
    /// No encryption, just signed
    #[default]
    Signed,

    /// Authenticated encryption with sender identity
    AuthcryptV2,

    /// Anonymous encryption without sender identity
    AnonV2,
}

/// A `DIDComm` message header.
///
/// Contains metadata about the message such as its ID, type,
/// sender, recipients, and timestamps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    /// The message ID
    pub id: MessageId,

    /// The message type
    #[serde(rename = "type")]
    pub typ: MessageType,

    /// The sender's DID
    pub from: Option<String>,

    /// The recipient's DID
    pub to: Option<Vec<String>>,

    /// When the message was created
    pub created_time: Option<u64>,

    /// When the message expires
    pub expires_time: Option<u64>,

    /// Additional custom headers
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// The body of a `DIDComm` message.
///
/// Contains the actual content of the message along with any attachments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    /// The message content
    #[serde(flatten)]
    pub content: serde_json::Value,

    /// Message attachments
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

/// A packed `DIDComm` message.
///
/// Represents a message that has been packed (signed and/or encrypted)
/// according to the specified packing type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackedMessage {
    /// The packed message data
    pub data: String,

    /// The type of packing used
    #[serde(skip)]
    pub packing: PackingType,
}

impl MessageType {
    /// Creates a new message type.
    #[must_use]
    pub fn new(typ: String) -> Self {
        Self(typ)
    }

    /// Gets the string representation of the message type.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_message_creation() -> crate::error::Result<()> {
        let message = Message::new(
            "https://example.com/protocols/1.0/test",
            json!({
                "test": "Hello, World!"
            }),
        )?
        .from("did:example:alice")
        .to(vec!["did:example:bob"]);

        assert_eq!(message.typ.0, "https://example.com/protocols/1.0/test");
        assert_eq!(message.from, Some("did:example:alice".to_string()));
        assert_eq!(message.to, Some(vec!["did:example:bob".to_string()]));
        assert_eq!(message.body["test"], "Hello, World!");

        Ok(())
    }

    #[test]
    fn test_packed_message_serialization() {
        let packed = PackedMessage {
            data: "test data".to_string(),
            packing: PackingType::Signed,
        };

        let serialized = serde_json::to_string(&packed).unwrap();
        let deserialized: PackedMessage = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.data, "test data");
    }
}
