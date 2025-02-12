//! Error types for the tap-didcomm-node crate.
//!
//! This module provides a comprehensive error handling system for `DIDComm` node operations.
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
//!         return Err(Error::Config("Empty message".into()));
//!     }
//!     Ok(())
//! }
//! ```

use tap_didcomm_core::Error as CoreError;

/// Custom error type for the node crate
#[derive(Debug)]
pub enum Error {
    /// Core `DIDComm` error
    Core(CoreError),
    /// Message dispatch error
    Dispatch(String),
    /// Actor system error
    Actor(String),
    /// HTTP error
    Http(String),
    /// Invalid configuration
    Config(String),
    /// Invalid format
    InvalidFormat(String),
}

/// Result type for the node crate
pub type Result<T> = std::result::Result<T, Error>;

impl From<CoreError> for Error {
    fn from(err: CoreError) -> Self {
        Error::Core(err)
    }
}

impl From<Error> for CoreError {
    fn from(err: Error) -> Self {
        match err {
            Error::Core(err) => err,
            Error::Dispatch(msg) => CoreError::Plugin(format!("Dispatch error: {msg}")),
            Error::Actor(msg) => CoreError::Plugin(format!("Actor error: {msg}")),
            Error::Http(msg) => CoreError::Plugin(format!("HTTP error: {msg}")),
            Error::Config(msg) => CoreError::Plugin(format!("Configuration error: {msg}")),
            Error::InvalidFormat(msg) => CoreError::Plugin(format!("Format error: {msg}")),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Core(err) => write!(f, "Core error: {err}"),
            Error::Dispatch(msg) => write!(f, "Dispatch error: {msg}"),
            Error::Actor(msg) => write!(f, "Actor error: {msg}"),
            Error::Http(msg) => write!(f, "HTTP error: {msg}"),
            Error::Config(msg) => write!(f, "Configuration error: {msg}"),
            Error::InvalidFormat(msg) => write!(f, "Format error: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Core(err) => Some(err),
            _ => None,
        }
    }
}
