//! Error types for the tap-didcomm-node crate.

use thiserror::Error;

/// The main error type for tap-didcomm-node operations.
#[derive(Error, Debug)]
pub enum Error {
    /// An error from the core crate.
    #[error("Core error: {0}")]
    Core(#[from] tap_didcomm_core::error::Error),

    /// An error occurred during message dispatch.
    #[error("Dispatch error: {0}")]
    Dispatch(String),

    /// An error occurred in the actor system.
    #[error("Actor error: {0}")]
    Actor(String),

    /// An error occurred during HTTP operations.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// The node configuration is invalid.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// An error occurred during serialization or deserialization.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// An error occurred during WASM operations.
    #[cfg(feature = "wasm")]
    #[error("WASM error: {0}")]
    WASM(String),
}

/// A specialized Result type for tap-didcomm-node operations.
pub type Result<T> = std::result::Result<T, Error>; 