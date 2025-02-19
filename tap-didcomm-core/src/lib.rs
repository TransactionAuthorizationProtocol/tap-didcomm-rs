//! Core `DIDComm` v2 implementation.
//!
//! This crate provides the core functionality for `DIDComm` v2 message handling,
//! including message packing and unpacking, plugin system, and error handling.
//!
//! # Features
//!
//! - Message packing and unpacking with different security levels:
//!   - `Signed`: Messages are signed but not encrypted
//!   - `AuthCrypt`: Authenticated encryption with sender identity
//!   - `AnonCrypt`: Anonymous encryption without sender identity
//! - Extensible plugin system for:
//!   - DID resolution
//!   - Message signing and verification
//!   - Message encryption and decryption
//! - Comprehensive error handling
//! - WASM compatibility
//!
//! # Architecture
//!
//! The crate is organized into these main modules:
//! - `pack`: Message packing and unpacking operations
//! - `plugin`: Plugin system for DID resolution and cryptographic operations
//! - `types`: Core type definitions
//! - `error`: Error types and handling
//! - `jwe`: JSON Web Encryption implementation
//! - `prelude`: Commonly used types and traits
//!
//! # Examples
//!
//! ```rust,no_run
//! use tap_didcomm_core::prelude::*;
//!
//! async fn example(plugin: &impl DIDCommPlugin) -> Result<()> {
//!     // Create a message
//!     let message = Message::new("Hello DIDComm!".to_string())
//!         .from("did:example:alice")
//!         .to(vec!["did:example:bob"]);
//!
//!     // Pack the message (encrypt and/or sign)
//!     let packed = pack_message(&message, plugin, PackingType::AuthcryptV2).await?;
//!
//!     // Unpack the message (decrypt and/or verify)
//!     let unpacked = unpack_message(&packed, plugin, None).await?;
//!     Ok(())
//! }
//! ```
//!
//! # WASM Support
//!
//! When compiled with the `wasm` feature, this crate provides WebAssembly bindings
//! for use in JavaScript/TypeScript environments. The WASM bindings support all core
//! functionality including message packing, unpacking, and plugin operations.
//!
//! # Security Considerations
//!
//! - Always use appropriate packing types based on security requirements:
//!   - Use `AuthcryptV2` when sender authentication is required
//!   - Use `AnonV2` when sender privacy is required
//!   - Use `Signed` only when encryption is not needed
//! - Validate DIDs and keys before use
//! - Handle errors appropriately to avoid information leakage
//! - Use secure random number generation (provided by the crate)
//! - Keep private keys secure and use appropriate key management
//!
//! # Errors
//!
//! This crate uses a custom `Error` type that covers:
//! - DID resolution failures
//! - Cryptographic operation failures
//! - Message format errors
//! - Plugin errors
//! - Base64 encoding/decoding errors
//! - JSON serialization/deserialization errors

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod crypto;
pub mod error;
pub mod jwe;
pub mod pack;
pub mod plugin;
pub mod prelude;
pub mod types;
/// Utility functions for DID validation and other common operations
pub mod utils;

#[cfg(test)]
pub(crate) mod tests;

// Re-export commonly used types at the crate root
pub use error::{Error, Result};
pub use pack::{pack_message, unpack_message, Message};
pub use plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer};
pub use types::{
    Attachment, AttachmentData, Header, MessageId, MessageType, PackedMessage, PackingType,
};
