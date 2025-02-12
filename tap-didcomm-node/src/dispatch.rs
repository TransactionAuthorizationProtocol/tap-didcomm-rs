//! Message dispatch functionality for DIDComm nodes.
//!
//! This module provides functionality for dispatching DIDComm messages to their
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

use crate::error::{Error, Result};
use reqwest::Client;
use std::time::Duration;
use tap_didcomm_core::Message as CoreMessage;
use tracing::warn;
use std::sync::Arc;
use tokio::sync::mpsc;
use crate::{
    actor::{HandlerHandle, HandlerMessage},
    node::Node,
};
use serde_json::json;

/// Configuration for message dispatch.
///
/// This struct contains settings that control how messages are dispatched,
/// including retry policies, timeouts, and transport-specific options.
///
/// # Examples
///
/// ```rust
/// use tap_didcomm_node::dispatch::DispatchConfig;
///
/// let config = DispatchConfig {
///     max_retries: 3,
///     retry_delay: 1,
///     timeout: 30,
///     endpoint: "http://localhost:8080".to_string(),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct DispatchConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Base delay between retries in seconds
    pub retry_delay: u64,
    /// HTTP client timeout in seconds
    pub timeout: u64,
    /// Default endpoint for message dispatch
    pub endpoint: String,
}

impl Default for DispatchConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay: 1,
            timeout: 30,
            endpoint: "http://localhost:8080".to_string(),
        }
    }
}

/// Dispatch a DIDComm message to its recipient.
///
/// This function handles the delivery of a message to its intended recipient,
/// using the appropriate transport protocol based on the recipient's service
/// endpoints.
///
/// # Arguments
///
/// * `message` - The message to dispatch
/// * `config` - Configuration for the dispatch operation
///
/// # Returns
///
/// A Result indicating success or failure of the dispatch operation
///
/// # Examples
///
/// ```rust,no_run
/// use tap_didcomm_node::dispatch::{dispatch_message, DispatchConfig};
/// use tap_didcomm_core::Message;
/// use tap_didcomm_node::error::Result;
/// use serde_json::json;
///
/// async fn example() -> Result<()> {
///     let msg = Message::new("test", json!({"hello": "world"}))?;
///     let config = DispatchConfig::default();
///     dispatch_message(&msg, &config).await
/// }
/// ```
pub async fn dispatch_message(message: &CoreMessage, config: &DispatchConfig) -> Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout))
        .build()
        .map_err(|e| Error::Http(e))?;

    let endpoint = get_service_endpoint(message).unwrap_or_else(|_| config.endpoint.clone());

    for attempt in 0..config.max_retries {
        match send_message(&client, &endpoint, message, config).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                warn!("Dispatch attempt {} failed: {}", attempt + 1, e);
                if attempt < config.max_retries - 1 {
                    tokio::time::sleep(Duration::from_secs(config.retry_delay * 2u64.pow(attempt)))
                        .await;
                }
            }
        }
    }

    Err(Error::Dispatch("Max retries exceeded".into()))
}

/// Get the service endpoint for a message recipient.
///
/// This function resolves the appropriate service endpoint for the message
/// recipient by looking up their DID Document and selecting a suitable
/// endpoint based on the message type and transport requirements.
///
/// # Arguments
///
/// * `message` - The message to get the endpoint for
///
/// # Returns
///
/// The resolved service endpoint URL
fn get_service_endpoint(message: &CoreMessage) -> Result<String> {
    // TODO: Implement service endpoint resolution from DID Documents
    Ok("http://localhost:8080".to_string())
}

/// Send a message to a specific endpoint.
///
/// This function handles the actual HTTP request to deliver the message
/// to the recipient's endpoint.
///
/// # Arguments
///
/// * `client` - The HTTP client to use
/// * `endpoint` - The endpoint URL to send to
/// * `message` - The message to send
/// * `config` - Configuration for the send operation
///
/// # Returns
///
/// A Result indicating success or failure of the send operation
async fn send_message(
    client: &Client,
    endpoint: &str,
    message: &CoreMessage,
    _config: &DispatchConfig,
) -> Result<()> {
    let response = client
        .post(endpoint)
        .json(&json!({
            "message": message
        }))
        .send()
        .await
        .map_err(|e| Error::Http(e.to_string()))?;

    if !response.status().is_success() {
        return Err(Error::Http(format!(
            "Request failed with status {}: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        )));
    }

    Ok(())
}

/// A message dispatcher.
pub struct Dispatcher {
    node: Arc<Node>,
    handler: HandlerHandle,
    client: Client,
}

impl Dispatcher {
    /// Creates a new dispatcher.
    pub fn new(node: Arc<Node>, handler: HandlerHandle) -> Self {
        Self {
            node,
            handler,
            client: Client::new(),
        }
    }

    /// Dispatches a message to the appropriate handler.
    pub async fn dispatch(&self, message: CoreMessage) -> Result<()> {
        let endpoint = get_service_endpoint(&message)?;
        
        let response = self.client
            .post(&endpoint)
            .json(&message)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Error::Http(format!(
                "Request failed with status: {}",
                response.status()
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_dispatch_message() -> Result<()> {
        // Start a mock server
        let mock_server = MockServer::start().await;

        // Create a mock endpoint
        Mock::given(method("POST"))
            .and(path("/didcomm"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let message = CoreMessage::new("test", json!({"hello": "world"}))
            .map_err(|e| Error::Serialization(e))?
            .to(vec!["did:example:bob"]);

        let mut config = DispatchConfig::default();
        config.endpoint = mock_server.uri() + "/didcomm";

        dispatch_message(&message, &config).await
    }

    #[tokio::test]
    async fn test_dispatch_config() {
        let config = DispatchConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay, 1);
        assert_eq!(config.timeout, 30);
        assert_eq!(config.endpoint, "http://localhost:8080");
    }

    #[tokio::test]
    async fn test_get_service_endpoint() {
        let msg = CoreMessage::new("test", json!({"test": "data"})).unwrap();
        let result = get_service_endpoint(&msg);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dispatch() {
        let node = Arc::new(Node::new());
        let (tx, _rx) = tokio::sync::mpsc::channel(32);
        let handler = HandlerHandle { sender: tx };
        let dispatcher = Dispatcher::new(node, handler);

        let mut message = CoreMessage::new("test".into());
        message.body = json!({"test": "value"});

        let result = dispatcher.dispatch(message).await;
        assert!(result.is_ok());
    }
}
