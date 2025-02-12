//! Core `DIDComm` v2 implementation.
//!
//! This crate provides the core functionality for `DIDComm` v2 message handling,
//! including message packing and unpacking, plugin system, and error handling.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod pack;
pub mod plugin;
pub mod types;

#[cfg(test)]
pub(crate) mod tests;

pub use error::{Error, Result};
pub use pack::{pack_message, unpack_message};
pub use plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer};
pub use types::{
    Attachment, AttachmentData, Header, Message, MessageId, MessageType, PackedMessage, PackingType,
};
