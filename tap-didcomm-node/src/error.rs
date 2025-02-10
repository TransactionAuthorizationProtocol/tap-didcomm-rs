//! Error types for the tap-didcomm-node crate.

/// The main error type for tap-didcomm-node operations.
#[derive(Debug)]
pub enum Error {
    /// An error from the core crate.
    Core(tap_didcomm_core::error::Error),

    /// An error occurred during message dispatch.
    Dispatch(String),

    /// An error occurred in the actor system.
    Actor(String),

    /// An error occurred during HTTP operations.
    Http(reqwest::Error),

    /// The node configuration is invalid.
    InvalidConfig(String),

    /// An error occurred during serialization or deserialization.
    Serialization(serde_json::Error),

    /// An error occurred during WASM operations.
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
pub type Result<T> = std::result::Result<T, Error>; 