//! Error types for the tap-didcomm-node crate.
//!
//! This module provides a comprehensive error handling system for DIDComm node operations.
//! It includes errors that can occur during message processing, dispatch, actor communication,
//! and network operations.
//!
//! # Examples
//!
//! ```rust
//! use tap_didcomm_node::error::{Error, Result};
//!
//! fn process_message(msg: &str) -> Result<()> {
//!     if msg.is_empty() {
//!         return Err(Error::InvalidConfig("Empty message".into()));
//!     }
//!     Ok(())
//! }
//! ```

use tap_didcomm_core::error::Error as CoreError;
use thiserror::Error;

/// The main error type for tap-didcomm-node operations.
///
/// This enum represents all possible errors that can occur in the DIDComm node,
/// including core operations, message dispatch, actor system interactions, and
/// network operations.
#[derive(Debug, Error)]
pub enum Error {
    /// An error from the core crate.
    #[error("Core error: {0}")]
    Core(#[from] CoreError),

    /// An error occurred during message dispatch.
    ///
    /// This typically happens when there's a network issue or the recipient
    /// is unreachable.
    #[error("Dispatch error: {0}")]
    Dispatch(String),

    /// An error occurred in the actor system.
    ///
    /// This can happen when actors fail to communicate or when message
    /// handlers are not properly registered.
    #[error("Actor error: {0}")]
    Actor(String),

    /// An error occurred during HTTP operations.
    ///
    /// This represents network-level errors that occur when sending
    /// or receiving messages over HTTP.
    #[error("HTTP error: {0}")]
    Http(String),

    /// The node configuration is invalid.
    ///
    /// This error occurs when the node is configured with invalid
    /// parameters or missing required settings.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// An error occurred during serialization or deserialization.
    ///
    /// This happens when processing JSON messages or converting
    /// between different data formats.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid message format
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// An error occurred during WASM operations.
    ///
    /// This variant is only available when the crate is compiled with
    /// the `wasm` feature. It represents errors specific to the browser
    /// environment.
    #[cfg(feature = "wasm")]
    #[error("WASM error: {0}")]
    WASM(String),
}

/// A specialized Result type for tap-didcomm-node operations.
///
/// This type alias is used throughout the crate to provide a consistent
/// error handling interface.
pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for CoreError {
    fn from(err: Error) -> Self {
        match err {
            Error::Core(e) => e,
            Error::Dispatch(msg) => CoreError::PluginError(format!("Dispatch error: {msg}")),
            Error::Actor(msg) => CoreError::PluginError(format!("Actor error: {msg}")),
            Error::Http(msg) => CoreError::PluginError(format!("HTTP error: {msg}")),
            Error::InvalidConfig(msg) => {
                CoreError::InvalidFormat(format!("Invalid config: {}", msg))
            }
            Error::Serialization(e) => CoreError::SerializationError(e.to_string()),
            Error::InvalidFormat(msg) => CoreError::InvalidFormat(msg),
            #[cfg(feature = "wasm")]
            Error::WASM(msg) => CoreError::InvalidFormat(format!("WASM error: {}", msg)),
        }
    }
}
