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

/// The main error type for tap-didcomm-node operations.
///
/// This enum represents all possible errors that can occur in the DIDComm node,
/// including core operations, message dispatch, actor system interactions, and
/// network operations.
#[derive(Debug)]
pub enum Error {
    /// An error from the core crate.
    Core(tap_didcomm_core::error::Error),

    /// An error occurred during message dispatch.
    ///
    /// This typically happens when there's a network issue or the recipient
    /// is unreachable.
    Dispatch(String),

    /// An error occurred in the actor system.
    ///
    /// This can happen when actors fail to communicate or when message
    /// handlers are not properly registered.
    Actor(String),

    /// An error occurred during HTTP operations.
    ///
    /// This represents network-level errors that occur when sending
    /// or receiving messages over HTTP.
    Http(reqwest::Error),

    /// The node configuration is invalid.
    ///
    /// This error occurs when the node is configured with invalid
    /// parameters or missing required settings.
    InvalidConfig(String),

    /// An error occurred during serialization or deserialization.
    ///
    /// This happens when processing JSON messages or converting
    /// between different data formats.
    Serialization(serde_json::Error),

    /// An error occurred during WASM operations.
    ///
    /// This variant is only available when the crate is compiled with
    /// the `wasm` feature. It represents errors specific to the browser
    /// environment.
    #[cfg(feature = "wasm")]
    WASM(String),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Core(e) => write!(f, "Core error: {}", e),
            Error::Dispatch(e) => write!(f, "Dispatch error: {}", e),
            Error::Actor(e) => write!(f, "Actor error: {}", e),
            Error::Http(e) => write!(f, "HTTP error: {}", e),
            Error::InvalidConfig(e) => write!(f, "Invalid configuration: {}", e),
            Error::Serialization(e) => write!(f, "Serialization error: {}", e),
            #[cfg(feature = "wasm")]
            Error::WASM(e) => write!(f, "WASM error: {}", e),
        }
    }
}

/// A specialized Result type for tap-didcomm-node operations.
///
/// This type alias is used throughout the crate to provide a consistent
/// error handling interface.
pub type Result<T> = std::result::Result<T, Error>; 