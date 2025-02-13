//! Node.js optimized `DIDComm` v2 implementation.
//!
//! This crate provides Node.js-specific optimizations and bindings for the `DIDComm` v2
//! protocol implementation. It builds on top of `tap-didcomm-core` and adds Node.js-specific
//! features and optimizations.
//!
//! # Features
//!
//! - Node.js-optimized WASM bindings
//! - Integration with Node.js crypto modules
//! - Node.js-specific memory management
//! - Async/await support through Node.js promises
//! - TypeScript type definitions
//!
//! # Architecture
//!
//! The crate extends the core implementation with:
//! - Node.js-specific plugin implementations
//! - Optimized memory management for Node.js
//! - Integration with Node.js native modules
//! - Custom error handling for Node.js
//!
//! # Examples
//!
//! ```rust,no_run
//! use tap_didcomm_node::{NodePlugin, Message, PackingType};
//! use wasm_bindgen::prelude::*;
//!
//! #[wasm_bindgen]
//! pub async fn pack_message(
//!     message: &JsValue,
//!     plugin: &NodePlugin,
//!     packing: PackingType,
//! ) -> Result<JsValue, JsError> {
//!     let message: Message = serde_wasm_bindgen::from_value(message.clone())?;
//!     let packed = plugin.pack_message(&message, packing).await?;
//!     Ok(serde_wasm_bindgen::to_value(&packed)?)
//! }
//! ```
//!
//! # Node.js Usage
//!
//! ```typescript
//! import { NodePlugin, Message, PackingType } from '@tap-didcomm/node';
//!
//! const plugin = new NodePlugin();
//! const message = {
//!   id: 'msg-1',
//!   type: 'example/1.0',
//!   body: { text: 'Hello DIDComm!' }
//! };
//!
//! const packed = await plugin.packMessage(message, PackingType.AUTHCRYPT);
//! ```
//!
//! # Memory Management
//!
//! The crate implements custom memory management optimized for Node.js:
//! - Efficient buffer handling
//! - Automatic memory cleanup
//! - Integration with Node.js garbage collection
//!
//! # Error Handling
//!
//! Errors are converted to JavaScript errors with:
//! - Proper stack traces
//! - Error codes
//! - Descriptive messages
//! - TypeScript type definitions
//!
//! # Security Considerations
//!
//! - Use Node.js's secure random number generator
//! - Properly handle memory containing sensitive data
//! - Use appropriate key storage solutions
//! - Follow Node.js security best practices
//! - Keep dependencies up to date

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use wasm_bindgen::prelude::*;

mod error;
mod plugin;
mod types;
mod utils;

pub use error::{Error, Result};
pub use plugin::NodePlugin;
pub use types::*;

/// Initialize the WASM module with the given memory configuration.
#[wasm_bindgen]
pub async fn initialize(memory: &JsValue) -> Result<()> {
    utils::set_panic_hook();
    // Initialize memory and return
    Ok(())
}

/// Pack a message using the given plugin and packing type.
#[wasm_bindgen]
pub async fn pack_message(
    message: &JsValue,
    plugin: &NodePlugin,
    packing: PackingType,
) -> Result<JsValue> {
    let message: Message = serde_wasm_bindgen::from_value(message.clone())?;
    let packed = plugin.pack_message(&message, packing).await?;
    Ok(serde_wasm_bindgen::to_value(&packed)?)
}

/// Unpack a message using the given plugin.
#[wasm_bindgen]
pub async fn unpack_message(
    packed: &JsValue,
    plugin: &NodePlugin,
    recipient: Option<String>,
) -> Result<JsValue> {
    let packed: PackedMessage = serde_wasm_bindgen::from_value(packed.clone())?;
    let unpacked = plugin.unpack_message(&packed, recipient.as_deref()).await?;
    Ok(serde_wasm_bindgen::to_value(&unpacked)?)
}
