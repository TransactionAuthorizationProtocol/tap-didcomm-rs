//! Error types for the tap-didcomm-web crate.

use thiserror::Error;
use warp::http::StatusCode;
use warp::reject::Reject;

/// Error type for the web server.
#[derive(Debug, Error)]
pub enum Error {
    /// An error occurred while serializing or deserializing data.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// An error occurred while formatting data.
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// An error occurred while processing a message.
    #[error("Message error: {0}")]
    Message(String),

    /// An internal error occurred.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl Reject for Error {}

impl Error {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Error::Serialization(_) => StatusCode::BAD_REQUEST,
            Error::InvalidFormat(_) => StatusCode::BAD_REQUEST,
            Error::Message(_) => StatusCode::BAD_REQUEST,
            Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Result type for the web server.
pub type Result<T> = std::result::Result<T, Error>;
