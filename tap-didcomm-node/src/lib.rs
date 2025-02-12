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
//! #[cfg(feature = "wasm")]
//! use tap_didcomm_node::{DIDCommNode, NodeConfig};
//! #[cfg(feature = "wasm")]
//! use tap_didcomm_node::{error::Result, actor::Message, actor::HandlerHandle};
//! #[cfg(feature = "wasm")]
//! use tap_didcomm_node::actor::spawn_message_handler;
//! #[cfg(feature = "wasm")]
//! use tap_didcomm_core::{Message as CoreMessage, types::PackingType};
//! #[cfg(feature = "wasm")]
//! use serde_json::json;
//! #[cfg(feature = "wasm")]
//! use async_trait::async_trait;
//!
//! #[cfg(feature = "wasm")]
//! #[derive(Clone)]
//! struct TestPlugin;
//!
//! #[cfg(feature = "wasm")]
//! #[async_trait(?Send)]
//! impl tap_didcomm_core::plugin::DIDResolver for TestPlugin {
//!     async fn resolve(&self, _: &str) -> tap_didcomm_core::error::Result<String> {
//!         Ok("{}".into())
//!     }
//! }
//!
//! #[cfg(feature = "wasm")]
//! #[async_trait]
//! impl tap_didcomm_core::plugin::Signer for TestPlugin {
//!     async fn sign(&self, msg: &[u8], _: &str) -> tap_didcomm_core::error::Result<Vec<u8>> {
//!         Ok(msg.to_vec())
//!     }
//!
//!     async fn verify(&self, _: &[u8], _: &[u8], _: &str) -> tap_didcomm_core::error::Result<bool> {
//!         Ok(true)
//!     }
//! }
//!
//! #[cfg(feature = "wasm")]
//! #[async_trait]
//! impl tap_didcomm_core::plugin::Encryptor for TestPlugin {
//!     async fn encrypt(&self, msg: &[u8], _: Vec<String>, _: Option<String>) -> tap_didcomm_core::error::Result<Vec<u8>> {
//!         Ok(msg.to_vec())
//!     }
//!
//!     async fn decrypt(&self, msg: &[u8], _: String) -> tap_didcomm_core::error::Result<Vec<u8>> {
//!         Ok(msg.to_vec())
//!     }
//! }
//!
//! #[cfg(feature = "wasm")]
//! unsafe impl Send for TestPlugin {}
//! #[cfg(feature = "wasm")]
//! unsafe impl Sync for TestPlugin {}
//!
//! #[cfg(feature = "wasm")]
//! impl tap_didcomm_core::plugin::DIDCommPlugin for TestPlugin {
//!     fn as_resolver(&self) -> &dyn tap_didcomm_core::plugin::DIDResolver {
//!         self
//!     }
//!
//!     fn as_signer(&self) -> &dyn tap_didcomm_core::plugin::Signer {
//!         self
//!     }
//!
//!     fn as_encryptor(&self) -> &dyn tap_didcomm_core::plugin::Encryptor {
//!         self
//!     }
//! }
//!
//! #[cfg(feature = "wasm")]
//! async fn example() -> Result<()> {
//!     let config = NodeConfig::default();
//!     let plugin = TestPlugin;
//!     let mut node = DIDCommNode::new(config, plugin);
//!
//!     // Create a handler for test messages
//!     let handler = spawn_message_handler();
//!     node.register_handler(handler);
//!
//!     // Create and send a message
//!     let core_message = CoreMessage::new("test", json!({"hello": "world"}))?;
//!     let message = Message(core_message);
//!     node.send(&message, PackingType::AuthcryptV2).await?;
//!
//!     Ok(())
//! }
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

//! Node.js bindings for TAP DIDComm implementation.
//!
//! This crate provides Node.js bindings for the TAP DIDComm implementation,
//! allowing Node.js applications to use DIDComm messaging functionality.
//!
//! # Features
//!
//! - DIDComm message handling
//! - Message routing and dispatch
//! - Plugin system for DID resolution and crypto operations
//!
//! # Examples
//!
//! ```rust,no_run
//! #[cfg(feature = "wasm")]
//! use tap_didcomm_node::{DIDCommNode, NodeConfig};
//! #[cfg(feature = "wasm")]
//! use tap_didcomm_node::{error::Result, actor::Message, actor::HandlerHandle};
//! #[cfg(feature = "wasm")]
//! use tap_didcomm_node::actor::spawn_message_handler;
//! #[cfg(feature = "wasm")]
//! use tap_didcomm_core::{Message as CoreMessage, types::PackingType};
//! #[cfg(feature = "wasm")]
//! use serde_json::json;
//! #[cfg(feature = "wasm")]
//! use async_trait::async_trait;
//!
//! #[cfg(feature = "wasm")]
//! #[derive(Clone)]
//! struct TestPlugin;
//!
//! #[cfg(feature = "wasm")]
//! #[async_trait(?Send)]
//! impl tap_didcomm_core::plugin::DIDResolver for TestPlugin {
//!     async fn resolve(&self, _: &str) -> tap_didcomm_core::error::Result<String> {
//!         Ok("{}".into())
//!     }
//! }
//!
//! #[cfg(feature = "wasm")]
//! #[async_trait]
//! impl tap_didcomm_core::plugin::Signer for TestPlugin {
//!     async fn sign(&self, msg: &[u8], _: &str) -> tap_didcomm_core::error::Result<Vec<u8>> {
//!         Ok(msg.to_vec())
//!     }
//!
//!     async fn verify(&self, _: &[u8], _: &[u8], _: &str) -> tap_didcomm_core::error::Result<bool> {
//!         Ok(true)
//!     }
//! }
//!
//! #[cfg(feature = "wasm")]
//! #[async_trait]
//! impl tap_didcomm_core::plugin::Encryptor for TestPlugin {
//!     async fn encrypt(&self, msg: &[u8], _: Vec<String>, _: Option<String>) -> tap_didcomm_core::error::Result<Vec<u8>> {
//!         Ok(msg.to_vec())
//!     }
//!
//!     async fn decrypt(&self, msg: &[u8], _: String) -> tap_didcomm_core::error::Result<Vec<u8>> {
//!         Ok(msg.to_vec())
//!     }
//! }
//!
//! #[cfg(feature = "wasm")]
//! unsafe impl Send for TestPlugin {}
//! #[cfg(feature = "wasm")]
//! unsafe impl Sync for TestPlugin {}
//!
//! #[cfg(feature = "wasm")]
//! impl tap_didcomm_core::plugin::DIDCommPlugin for TestPlugin {
//!     fn as_resolver(&self) -> &dyn tap_didcomm_core::plugin::DIDResolver {
//!         self
//!     }
//!
//!     fn as_signer(&self) -> &dyn tap_didcomm_core::plugin::Signer {
//!         self
//!     }
//!
//!     fn as_encryptor(&self) -> &dyn tap_didcomm_core::plugin::Encryptor {
//!         self
//!     }
//! }
//!
//! #[cfg(feature = "wasm")]
//! async fn example() -> Result<()> {
//!     let config = NodeConfig::default();
//!     let plugin = TestPlugin;
//!     let mut node = DIDCommNode::new(config, plugin);
//!
//!     // Create a handler for test messages
//!     let handler = spawn_message_handler();
//!     node.register_handler(handler);
//!
//!     // Create and send a message
//!     let core_message = CoreMessage::new("test", json!({"hello": "world"}))?;
//!     let message = Message(core_message);
//!     node.send(&message, PackingType::AuthcryptV2).await?;
//!
//!     Ok(())
//! }

pub mod actor;
pub mod dispatch;
pub mod error;
pub mod node;
pub mod mock;

#[cfg(test)]
mod tests;

// Re-export main types for convenience
pub use actor::{HandlerHandle, Message};
pub use error::{Error, Result};
pub use node::{Node, NodeConfig};
