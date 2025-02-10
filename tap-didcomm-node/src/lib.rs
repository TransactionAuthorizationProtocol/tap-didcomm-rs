//! Abstract DIDComm node implementation with Actix Actor support.
//!
//! This crate provides a DIDComm node implementation that can:
//! - Receive and process DIDComm messages asynchronously
//! - Subscribe to messages using Actix actors
//! - Dispatch messages to other nodes
//! - Support both native and WebAssembly environments
//!
//! # Architecture
//!
//! The crate is organized into several modules:
//! - `node`: Core DIDComm node implementation
//! - `actor`: Actix actor integration for message handling
//! - `dispatch`: Message dispatch functionality
//! - `error`: Error types and handling
//!
//! # Features
//!
//! - Full DIDComm v2 support via tap-didcomm-core
//! - Async/await throughout
//! - Pluggable architecture for customization
//! - Actix actor system integration
//! - Native and WASM compatibility
//! - Comprehensive error handling
//!
//! # Examples
//!
//! ```rust,no_run
//! use tap_didcomm_node::{DIDCommNode, NodeConfig, MessageHandler};
//! use tap_didcomm_core::Message;
//!
//! // Create a node with default configuration
//! let config = NodeConfig::default();
//! let mut node = DIDCommNode::new(config, your_plugin);
//!
//! // Register a message handler
//! node.register_handler("test", your_handler.recipient());
//!
//! // Receive and process a message
//! node.receive(&packed_message).await?;
//! ```
//!
//! # WASM Support
//!
//! When compiled with the `wasm` feature, the crate uses browser APIs
//! for network operations instead of native Rust libraries.

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
pub use actor::MessageHandler;
pub use dispatch::dispatch_message;
pub use error::{Error, Result};
pub use node::{DIDCommNode, NodeConfig}; 