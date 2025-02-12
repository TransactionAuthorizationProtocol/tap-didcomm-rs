//! Node.js bindings for TAP `DIDComm` implementation.
//!
//! This crate provides Node.js bindings for the TAP `DIDComm` implementation,
//! allowing Node.js applications to use `DIDComm` messaging functionality.
//!
//! # Features
//!
//! - `DIDComm` message handling
//! - Message encryption and decryption
//! - DID resolution
//! - Signature verification
//! - WASM-based Node.js integration
//!
//! # Architecture
//!
//! The crate is organized into these main modules:
//! - `node`: Core `DIDComm` node implementation
//! - `actor`: Message handling and actor system
//! - `dispatch`: Message routing and dispatch
//! - `error`: Error types and handling
//!
//! # Examples
//!
//! ```rust,no_run
//! use tap_didcomm_node::{DIDCommNode, NodeConfig, HandlerHandle};
//! use tap_didcomm_core::Message;
//! use tap_didcomm_node::mock::MockPlugin;
//! use tokio::sync::mpsc;
//!
//! fn example() -> tap_didcomm_node::error::Result<()> {
//!     let config = NodeConfig::default();
//!     let mut node = DIDCommNode::new(config, MockPlugin::new());
//!     
//!     // Create a handler
//!     let (tx, _rx) = mpsc::channel(32);
//!     let handler = HandlerHandle::new(tx);
//!     
//!     // Register message handlers
//!     node.register_handler("test", handler);
//!     
//!     // Start processing messages
//!     node.start()
//! }
//! ```

#![deny(missing_docs)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod actor;
pub mod dispatch;
pub mod error;
pub mod mock;
pub mod node;

pub use actor::{HandlerHandle, HandlerMessage, HandlerRegistry, Message};
pub use dispatch::{dispatch_message, DispatchConfig};
pub use error::{Error, Result};
pub use node::{DIDCommNode, NodeConfig};
