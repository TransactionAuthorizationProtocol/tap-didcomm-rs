//! Error types for the tap-didcomm-web crate.

use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use thiserror::Error;

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

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .json(serde_json::json!({
                "error": self.to_string()
            }))
    }

    fn status_code(&self) -> StatusCode {
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