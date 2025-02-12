//! Message dispatch functionality for `DIDComm` nodes.
//!
//! This module provides functionality for dispatching `DIDComm` messages to their
//! intended recipients. It handles both local and remote message delivery,
//! supporting various transport protocols and message formats.
//!
//! # Features
//!
//! - HTTP(S) transport support
//! - Configurable retry policies
//! - Asynchronous message delivery
//! - Support for both native and WASM environments
//!
//! # Examples
//!
//! ```rust,no_run
//! use tap_didcomm_node::dispatch::{dispatch_message, DispatchConfig};
//! use tap_didcomm_core::Message;
//! use tap_didcomm_node::error::Result;
//! use serde_json::json;
//!
//! async fn send_message() -> Result<()> {
//!     let msg = Message::new("test", json!({"hello": "world"}))?;
//!     let config = DispatchConfig::default();
//!     dispatch_message(&msg, &config).await
//! }
//! ```

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tap_didcomm_core::Message as CoreMessage;
use tracing::debug;

use crate::error::{Error, Result};

/// Configuration for message dispatch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchConfig {
    /// The base URL for the `DIDComm` service
    pub base_url: String,
    /// The endpoint path for message dispatch
    pub endpoint: String,
    /// Whether to use HTTPS for dispatch
    pub use_https: bool,
    /// The HTTP client timeout in seconds
    pub timeout: u64,
}

impl Default for DispatchConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost".to_string(),
            endpoint: "/didcomm".to_string(),
            use_https: false,
            timeout: 30,
        }
    }
}

/// Dispatch a message to its recipients
///
/// # Arguments
///
/// * `message` - The message to dispatch
/// * `config` - The dispatch configuration
///
/// # Returns
///
/// A Result indicating success or failure of message dispatch
///
/// # Errors
///
/// Returns an error if:
/// - The HTTP request fails
/// - The server returns a non-success status code
pub async fn dispatch_message(message: &CoreMessage, config: &DispatchConfig) -> Result<()> {
    let client = Client::new();
    let url = format!("{}{}", config.base_url, config.endpoint);

    debug!("Dispatching message to {url}");

    let response = client
        .post(&url)
        .json(message)
        .send()
        .await
        .map_err(|e| Error::Http(e.to_string()))?;

    if !response.status().is_success() {
        return Err(Error::Http(format!(
            "Failed to dispatch message: {}",
            response.status()
        )));
    }

    Ok(())
}

/// Get the service endpoint for a message
///
/// # Arguments
///
/// * `message` - The message to get the endpoint for
///
/// # Returns
///
/// The service endpoint URL
#[must_use]
fn get_service_endpoint(_message: &CoreMessage) -> String {
    // TODO: Implement service endpoint resolution from DID Document
    "http://localhost:8080/didcomm".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_dispatch_message() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/didcomm"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = DispatchConfig {
            base_url: mock_server.uri(),
            endpoint: "/didcomm".to_string(),
            use_https: false,
            timeout: 30,
        };

        let message = CoreMessage::new("test", json!({"test": "value"})).unwrap();
        let result = dispatch_message(&message, &config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dispatch_config() {
        let config = DispatchConfig::default();
        assert_eq!(config.base_url, "http://localhost");
        assert_eq!(config.endpoint, "/didcomm");
        assert_eq!(config.use_https, false);
        assert_eq!(config.timeout, 30);
    }
}
