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
    plugin: &impl DIDCommPlugin,
    options: DispatchOptions,
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
    plugin: &impl DIDCommPlugin,
    options: DispatchOptions,
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
    use tap_didcomm_core::Message as CoreMessage;

    // Mock plugin (same as in node.rs tests)
    struct MockPlugin;

    #[async_trait::async_trait]
    impl tap_didcomm_core::plugin::DIDResolver for MockPlugin {
        async fn resolve(&self, _did: &str) -> tap_didcomm_core::error::Result<serde_json::Value> {
            Ok(json!({}))
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

        async fn verify(&self, _message: &[u8], _from: &str) -> tap_didcomm_core::error::Result<()> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl tap_didcomm_core::plugin::Encryptor for MockPlugin {
        async fn encrypt(
            &self,
            message: &[u8],
            _to: &[String],
            _from: Option<&str>,
        ) -> tap_didcomm_core::error::Result<tap_didcomm_core::types::PackedMessage> {
            Ok(tap_didcomm_core::types::PackedMessage {
                data: String::from_utf8(message.to_vec()).unwrap(),
                packing: self.packing_type(),
            })
        }

        async fn decrypt(
            &self,
            message: &tap_didcomm_core::types::PackedMessage,
            _to: &str,
        ) -> tap_didcomm_core::error::Result<Vec<u8>> {
            Ok(message.data.as_bytes().to_vec())
        }

        fn packing_type(&self) -> PackingType {
            PackingType::Plain
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
    #[ignore] // This test requires a running server
    async fn test_dispatch_message() {
        let message = CoreMessage::new("test", json!({"hello": "world"}))
            .unwrap()
            .from("did:example:alice")
            .to(vec!["did:example:bob"]);

        let options = DispatchOptions {
            packing: PackingType::Plain,
            endpoint: "http://localhost:8080/didcomm".into(),
        };

        dispatch_message(&message, &MockPlugin, options)
            .await
            .unwrap();
    }
} 