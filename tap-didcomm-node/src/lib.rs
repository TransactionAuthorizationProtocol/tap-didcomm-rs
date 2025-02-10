//! Abstract DIDComm node implementation with Actix Actor support.
//!
//! This crate provides a DIDComm node implementation that can:
//! - Receive and process DIDComm messages
//! - Subscribe to messages using Actix actors
//! - Dispatch messages to other nodes
//!
//! It supports both native and WebAssembly environments.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod actor;
pub mod dispatch;
pub mod error;
pub mod node;

#[cfg(test)]
mod tests;

// Re-export main types for convenience
pub use actor::{DIDCommActor, MessageHandler};
pub use dispatch::{dispatch_message, DispatchOptions};
pub use error::{Error, Result};
pub use node::{DIDCommNode, NodeConfig}; 