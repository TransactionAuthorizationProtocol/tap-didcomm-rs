//! Prelude module for commonly used types and traits.
//!
//! This module provides a convenient way to import commonly used types
//! and traits from the `tap-didcomm-core` crate. Import everything from
//! this module with `use tap_didcomm_core::prelude::*`.
//!
//! # Example
//!
//! ```rust
//! use tap_didcomm_core::prelude::*;
//!
//! async fn example(plugin: &impl DIDCommPlugin) -> Result<()> {
//!     let message = Message::new("Hello DIDComm!".to_string())
//!         .from("did:example:alice")
//!         .to(vec!["did:example:bob"]);
//!
//!     let packed = pack_message(&message, plugin, PackingType::AuthcryptV2).await?;
//!     Ok(())
//! }
//! ```

// Re-export error types
pub use crate::error::{Error, Result};

// Re-export core traits
pub use crate::plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer};

// Re-export message types
pub use crate::types::{
    Attachment, AttachmentData, Header, Message, MessageId, MessageType, PackedMessage, PackingType,
};

// Re-export JWE types
pub use crate::jwe::{
    ContentEncryptionAlgorithm, EcdhCurve, EncryptionKey, JweHeader, JweMessage,
    KeyAgreementAlgorithm,
};

// Re-export core functions
pub use crate::pack::{pack_message, unpack_message};
