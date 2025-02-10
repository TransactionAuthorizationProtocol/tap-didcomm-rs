//! Core DIDComm v2 message handling with async signing, encryption, and verification.
//!
//! This crate provides the core functionality for DIDComm v2 message processing, including:
//! - Message packing and unpacking
//! - Async signing and verification
//! - Encryption and decryption
//! - Pluggable DID resolvers, signers, and encryptors
//!
//! It is designed to work both natively and in WebAssembly environments.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod message;
pub mod pack;
pub mod plugin;
pub mod types;

#[cfg(test)]
pub(crate) mod tests;

// Re-export main types for convenience
pub use error::Error;
pub use types::Message;
pub use pack::{pack_message, unpack_message};
pub use plugin::{DIDResolver, Encryptor, Signer};
pub use types::*; 