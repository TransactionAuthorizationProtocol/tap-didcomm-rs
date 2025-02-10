//! Error types for the tap-didcomm-web crate.

use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use thiserror::Error;

/// The main error type for tap-didcomm-web operations.
#[derive(Error, Debug)]
pub enum Error {
    /// An error from the core crate.
    #[error("Core error: {0}")]
    Core(#[from] tap_didcomm_core::error::Error),

    /// An error from the node crate.
    #[error("Node error: {0}")]
    Node(#[from] tap_didcomm_node::error::Error),

    /// An error occurred during serialization or deserialization.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The server configuration is invalid.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// The request is invalid.
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// The requested resource was not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// An internal server error occurred.
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let error = serde_json::json!({
            "error": self.to_string()
        });

        HttpResponse::build(self.status_code()).json(error)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::Core(_) | Self::Node(_) | Self::Serialization(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::InvalidConfig(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
        }
    }
}

/// A specialized Result type for tap-didcomm-web operations.
pub type Result<T> = std::result::Result<T, Error>; 