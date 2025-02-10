//! Core DIDComm v2 type definitions.
//!
//! This module contains the fundamental types used throughout the DIDComm v2 implementation,
//! including message structures, identifiers, and enums for different packing types.
//! All types follow the DIDComm v2 specification and support both native and WASM environments.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// A DIDComm message type identifier.
///
/// This type represents the protocol and message type in a DIDComm message.
/// For example: "https://didcomm.org/basicmessage/2.0/message"
///
/// # Examples
///
/// ```rust
/// use tap_didcomm_core::types::MessageType;
///
/// let typ = MessageType("https://didcomm.org/basicmessage/2.0/message".to_string());
/// assert_eq!(typ.as_str(), "https://didcomm.org/basicmessage/2.0/message");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageType(pub String);

/// A unique identifier for a DIDComm message.
///
/// Each message in DIDComm must have a unique identifier. This is typically
/// a UUID, but can be any string that uniquely identifies the message.
///
/// # Examples
///
/// ```rust
/// use tap_didcomm_core::types::MessageId;
///
/// let id = MessageId::random();
/// assert!(uuid::Uuid::parse_str(id.as_str()).is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub String);

impl MessageId {
    /// Creates a new message ID from a string.
    ///
    /// # Arguments
    ///
    /// * `id` - The string to use as the message ID
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Generates a random message ID using UUID v4.
    pub fn random() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Returns the message ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A complete DIDComm message.
///
/// This structure represents a DIDComm message with all its components as defined
/// in the DIDComm v2 specification. It includes the message ID, type, sender,
/// recipients, timestamps, body, and optional attachments.
///
/// # Examples
///
/// ```rust
/// use tap_didcomm_core::types::Message;
/// use serde_json::json;
///
/// let message = Message::new("test", json!({"hello": "world"}))
///     .unwrap()
///     .from("did:example:alice")
///     .to(vec!["did:example:bob"]);
///
/// assert_eq!(message.from, Some("did:example:alice".to_string()));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Creates a new DIDComm message.
    ///
    /// # Arguments
    ///
    /// * `typ` - The message type identifier
    /// * `body` - The message content/payload
    ///
    /// # Returns
    ///
    /// A Result containing the new Message if successful, or a serialization error if the body is invalid.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use tap_didcomm_core::Message;
    /// use serde_json::json;
    ///
    /// let message = Message::new(
    ///     "https://didcomm.org/basicmessage/2.0/message",
    ///     json!({"content": "Hello, World!"})
    /// ).unwrap();
    /// ```
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

    /// Sets the sender of the message.
    ///
    /// # Arguments
    ///
    /// * `from` - The DID of the sender
    ///
    /// # Returns
    ///
    /// The modified message with the sender set.
    pub fn from(mut self, from: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Sets the recipients of the message.
    ///
    /// # Arguments
    ///
    /// * `to` - An iterator of recipient DIDs
    ///
    /// # Returns
    ///
    /// The modified message with the recipients set.
    pub fn to(mut self, to: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.to = Some(to.into_iter().map(Into::into).collect());
        self
    }
}

/// An attachment to a DIDComm message.
///
/// Attachments can contain additional data in various formats, including
/// base64-encoded binary data, JSON data, or links to external resources.
///
/// # Examples
///
/// ```rust
/// use tap_didcomm_core::types::{Attachment, AttachmentData};
///
/// let attachment = Attachment {
///     id: "test-1".to_string(),
///     description: Some("Test attachment".to_string()),
///     filename: Some("test.txt".to_string()),
///     media_type: Some("text/plain".to_string()),
///     format: None,
///     data: AttachmentData::Base64("SGVsbG8gd29ybGQ=".to_string()),
/// };
/// ```
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

/// The data content of an attachment.
///
/// This enum represents the different ways attachment data can be included
/// in a DIDComm message, such as JWS, base64-encoded data, or JSON.
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

/// The type of packing to use for a message.
///
/// DIDComm v2 supports three types of message packing:
/// - Signed: The message is signed but not encrypted
/// - Authcrypt: The message is encrypted with sender authentication
/// - Anoncrypt: The message is encrypted anonymously
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
///
/// Contains metadata about the message and its processing requirements.
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

/// The body of a DIDComm message.
///
/// Contains the actual message content and any attachments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    /// The message content
    #[serde(flatten)]
    pub content: serde_json::Value,
    
    /// Message attachments
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

/// A packed DIDComm message.
///
/// Represents a message that has been processed according to its packing
/// type (signed, authcrypt, or anoncrypt).
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
    ///
    /// # Arguments
    ///
    /// * `typ` - The message type string
    pub fn new(typ: String) -> Self {
        Self(typ)
    }

    /// Gets the message type as a string slice.
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