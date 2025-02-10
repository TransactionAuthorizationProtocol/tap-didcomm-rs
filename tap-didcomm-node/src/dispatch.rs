//! Message dispatch functionality.

use tap_didcomm_core::{
    pack::pack_message,
    plugin::DIDCommPlugin,
    types::{Message, PackingType},
};

use crate::error::{Error, Result};

/// Options for message dispatch.
#[derive(Debug, Clone)]
pub struct DispatchOptions {
    /// The packing type to use.
    pub packing: PackingType,
    /// The base URL of the recipient node.
    pub endpoint: String,
}

/// Dispatches a DIDComm message to its recipients.
///
/// # Arguments
///
/// * `message` - The message to dispatch
/// * `plugin` - The plugin to use for DIDComm operations
/// * `options` - Dispatch options
///
/// # Returns
///
/// A future that resolves when the message has been dispatched.
#[cfg(not(feature = "wasm"))]
pub async fn dispatch_message(
    message: &Message,
    plugin: &dyn DIDCommPlugin,
    options: &DispatchOptions,
) -> Result<()> {
    // Pack the message
    let packed = pack_message(message, plugin, options.packing)
        .await
        .map_err(Error::Core)?;

    // Send the message using reqwest
    reqwest::Client::new()
        .post(&options.endpoint)
        .json(&packed)
        .send()
        .await
        .map_err(Error::Http)?;

    Ok(())
}

/// Dispatches a DIDComm message to its recipients (WASM version).
///
/// # Arguments
///
/// * `message` - The message to dispatch
/// * `plugin` - The plugin to use for DIDComm operations
/// * `options` - Dispatch options
///
/// # Returns
///
/// A future that resolves when the message has been dispatched.
#[cfg(feature = "wasm")]
pub async fn dispatch_message(
    message: &Message,
    plugin: &dyn DIDCommPlugin,
    options: &DispatchOptions,
) -> Result<()> {
    use wasm_bindgen::JsValue;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{RequestInit, RequestMode};

    // Pack the message
    let packed = pack_message(message, plugin, options.packing)
        .await
        .map_err(Error::Core)?;

    // Create request options
    let mut opts = RequestInit::new();
    opts.method("POST")
        .mode(RequestMode::Cors)
        .body(Some(&JsValue::from_str(
            &serde_json::to_string(&packed).map_err(Error::Serialization)?,
        )));

    // Create request
    let window = web_sys::window().ok_or_else(|| Error::WASM("No window available".into()))?;
    let request = web_sys::Request::new_with_str_and_init(&options.endpoint, &opts)
        .map_err(|e| Error::WASM(format!("Failed to create request: {:?}", e)))?;

    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(|e| Error::WASM(format!("Failed to set headers: {:?}", e)))?;

    // Send request
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| Error::WASM(format!("Failed to send request: {:?}", e)))?;

    let resp: web_sys::Response = resp_value
        .dyn_into()
        .map_err(|e| Error::WASM(format!("Failed to convert response: {:?}", e)))?;

    if !resp.ok() {
        return Err(Error::WASM(format!(
            "Request failed with status: {}",
            resp.status()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Mock plugin (same as in node.rs tests)
    struct MockPlugin;

    #[async_trait::async_trait]
    impl tap_didcomm_core::plugin::DIDResolver for MockPlugin {
        async fn resolve(&self, _did: &str) -> tap_didcomm_core::error::Result<String> {
            Ok("{}".to_string())
        }
    }

    #[async_trait::async_trait]
    impl tap_didcomm_core::plugin::Signer for MockPlugin {
        async fn sign(
            &self,
            message: &[u8],
            _from: &str,
        ) -> tap_didcomm_core::error::Result<Vec<u8>> {
            Ok(message.to_vec())
        }

        async fn verify(&self, _message: &[u8], _signature: &[u8], _from: &str) -> tap_didcomm_core::error::Result<bool> {
            Ok(true)
        }
    }

    #[async_trait::async_trait]
    impl tap_didcomm_core::plugin::Encryptor for MockPlugin {
        async fn encrypt(
            &self,
            message: &[u8],
            _to: Vec<String>,
            _from: Option<String>,
        ) -> tap_didcomm_core::error::Result<Vec<u8>> {
            Ok(message.to_vec())
        }

        async fn decrypt(
            &self,
            message: &[u8],
            _recipient: String,
        ) -> tap_didcomm_core::error::Result<Vec<u8>> {
            Ok(message.to_vec())
        }
    }

    impl tap_didcomm_core::plugin::DIDCommPlugin for MockPlugin {
        fn as_resolver(&self) -> &dyn tap_didcomm_core::plugin::DIDResolver {
            self
        }

        fn as_signer(&self) -> &dyn tap_didcomm_core::plugin::Signer {
            self
        }

        fn as_encryptor(&self) -> &dyn tap_didcomm_core::plugin::Encryptor {
            self
        }
    }

    #[tokio::test]
    async fn test_dispatch_message() {
        let message = Message::new("test", json!({"hello": "world"}))
            .unwrap()
            .to(vec!["did:example:bob"]);

        let options = DispatchOptions {
            packing: PackingType::Signed,
            endpoint: "http://localhost:8080/didcomm".to_string(),
        };

        let plugin = MockPlugin;

        // This will fail because we're not actually running a server
        let result = dispatch_message(&message, &plugin, &options).await;
        assert!(result.is_err());
    }
} 