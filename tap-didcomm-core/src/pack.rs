//! Message packing and unpacking functionality.
//!
//! This module provides functions for packing and unpacking `DIDComm` messages
//! using different methods (signed, authcrypt, anoncrypt).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;

use crate::{
    error::Result,
    plugin::DIDCommPlugin,
    types::PackingType,
    Error,
    Message,
};

/// Pack a `DIDComm` message using the specified packing type.
///
/// # Errors
///
/// Returns an error if:
/// - Message serialization fails
/// - Plugin operations (signing/encryption) fail
/// - Required fields are missing for the chosen packing type
pub async fn pack_message(
    message: &Message,
    plugin: &dyn DIDCommPlugin,
    packing_type: PackingType,
) -> Result<String> {
    let msg_json = serde_json::to_string(message)
        .map_err(|e| Error::SerializationError(e.to_string()))?;

    match packing_type {
        PackingType::Signed => {
            let from = message.from.as_deref().ok_or_else(|| {
                Error::InvalidFormat("Sender DID required for signed messages".into())
            })?;

            let signature = plugin
                .sign(msg_json.as_bytes(), from)
                .await
                .map_err(|e| Error::SigningFailed(e.to_string()))?;

            let packed = json!({
                "payload": URL_SAFE_NO_PAD.encode(msg_json),
                "signatures": [
                    {
                        "signature": URL_SAFE_NO_PAD.encode(signature),
                        "protected": URL_SAFE_NO_PAD.encode("{}"),
                    }
                ]
            });

            serde_json::to_string(&packed)
                .map_err(|e| Error::SerializationError(e.to_string()))
        }
        PackingType::AuthcryptV2 => {
            let from = message.from.as_deref().ok_or_else(|| {
                Error::InvalidFormat("Sender DID required for authcrypt".into())
            })?;

            let to = message.to.as_ref().ok_or_else(|| {
                Error::InvalidFormat("Recipients required for authcrypt".into())
            })?;

            let encrypted = plugin
                .encrypt(msg_json.as_bytes(), to.clone(), Some(from.to_string()))
                .await
                .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

            Ok(URL_SAFE_NO_PAD.encode(encrypted))
        }
        PackingType::AnonV2 => {
            let to = message.to.as_ref().ok_or_else(|| {
                Error::InvalidFormat("Recipients required for anoncrypt".into())
            })?;

            let encrypted = plugin
                .encrypt(msg_json.as_bytes(), to.clone(), None)
                .await
                .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

            Ok(URL_SAFE_NO_PAD.encode(encrypted))
        }
    }
}

/// Unpack a `DIDComm` message.
///
/// # Errors
///
/// Returns an error if:
/// - The packed message is not valid base64 or JSON
/// - Message verification fails
/// - Message decryption fails (for encrypted messages)
/// - The message format does not match the expected structure
pub async fn unpack_message(
    packed: &str,
    plugin: &dyn DIDCommPlugin,
    _recipient: Option<String>,
) -> Result<Message> {
    let packed_json: serde_json::Value = serde_json::from_str(packed)
        .map_err(|e| Error::InvalidFormat(format!("Invalid JSON: {e}")))?;

    let payload = URL_SAFE_NO_PAD
        .decode(packed_json["payload"].as_str().ok_or_else(|| {
            Error::InvalidFormat("Missing payload field".into())
        })?)
        .map_err(|e| Error::InvalidFormat(format!("Invalid base64: {e}")))?;

    if let Some(signatures) = packed_json["signatures"].as_array() {
        if let Some(sig) = signatures.first() {
            let signature = URL_SAFE_NO_PAD
                .decode(sig["signature"].as_str().ok_or_else(|| {
                    Error::InvalidFormat("Missing signature field".into())
                })?)
                .map_err(|e| Error::InvalidFormat(format!("Invalid base64: {e}")))?;

            let from = serde_json::from_slice::<Message>(&payload)
                .map_err(|e| Error::SerializationError(e.to_string()))?
                .from
                .ok_or_else(|| Error::InvalidFormat("Missing sender DID".into()))?;

            plugin
                .verify(&payload, &signature, &from)
                .await
                .map_err(|e| Error::VerificationFailed(e.to_string()))?;

            return serde_json::from_slice(&payload)
                .map_err(|e| Error::SerializationError(e.to_string()));
        }
    }

    Err(Error::InvalidFormat("Invalid message format".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::MockTestPlugin;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde_json::json;

    #[tokio::test]
    async fn test_pack_signed() -> Result<()> {
        let plugin = MockTestPlugin;
        let message = Message::new(
            "https://example.com/protocols/1.0/test",
            json!({ "hello": "world" })
        )?
        .from("did:example:alice")
        .to(vec!["did:example:bob"]);

        let packed = pack_message(&message, &plugin, PackingType::Signed).await?;
        
        // Parse the packed message as JSON
        let packed_json: serde_json::Value = serde_json::from_str(&packed)?;
        
        // Verify the structure
        assert!(packed_json["payload"].is_string());
        assert!(packed_json["signatures"].is_array());
        assert_eq!(packed_json["signatures"].as_array().unwrap().len(), 1);
        
        // Verify we can decode the payload
        let payload = URL_SAFE_NO_PAD.decode(
            packed_json["payload"].as_str().unwrap()
        )?;
        let decoded_message: Message = serde_json::from_slice(&payload)?;
        assert_eq!(decoded_message.from, Some("did:example:alice".to_string()));
        
        Ok(())
    }

    #[tokio::test]
    async fn test_pack_authcrypt() -> Result<()> {
        let plugin = MockTestPlugin;
        let message = Message::new(
            "https://example.com/protocols/1.0/test",
            json!({ "hello": "world" })
        )?
        .from("did:example:alice")
        .to(vec!["did:example:bob"]);

        let packed = pack_message(&message, &plugin, PackingType::AuthcryptV2).await?;
        
        // Verify the packed message can be decoded as base64
        let _decoded = STANDARD.decode(packed)?;
        
        Ok(())
    }
}
