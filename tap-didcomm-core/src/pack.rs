//! Message packing and unpacking functionality.
//!
//! This module provides functions for packing and unpacking `DIDComm` messages
//! using different methods (signed, authcrypt, anoncrypt).

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::crypto::sign_message;
use crate::jwe::{EncryptedMessageBuilder, Recipient};
use crate::plugin::DIDCommPlugins;
use crate::utils::validate_did;
use crate::{error::Result, plugin::DIDCommPlugin, types::PackingType, Error};

/// A DIDComm message
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Message {
    /// The message body
    pub body: String,
    /// The sender DID
    pub from: Option<String>,
    /// The recipient DIDs
    pub to: Option<Vec<String>>,
}

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
    let msg_json = serde_json::to_string(message)?;

    match packing_type {
        PackingType::Signed => {
            if let Some(from) = &message.from {
                let signature = plugin
                    .signer()
                    .sign(msg_json.as_bytes(), from)
                    .await
                    .map_err(|e| Error::SigningFailed(e.to_string()))?;

                Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature))
            } else {
                Err(Error::InvalidDIDDocument(
                    "Sender DID required for signed messages".into(),
                ))
            }
        }
        PackingType::AuthcryptV2 => {
            let from = message.from.as_ref().ok_or_else(|| {
                Error::InvalidDIDDocument("Sender DID required for authcrypt".into())
            })?;

            let to = message.to.as_ref().ok_or_else(|| {
                Error::InvalidDIDDocument("Recipient DIDs required for authcrypt".into())
            })?;

            let to_refs: Vec<&str> = to.iter().map(|s| s.as_str()).collect();

            let encrypted = plugin
                .encryptor()
                .encrypt(msg_json.as_bytes(), &to_refs, Some(from))
                .await
                .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

            Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&encrypted))
        }
        PackingType::AnonV2 => {
            let to = message.to.as_ref().ok_or_else(|| {
                Error::InvalidDIDDocument("Recipient DIDs required for anoncrypt".into())
            })?;

            let to_refs: Vec<&str> = to.iter().map(|s| s.as_str()).collect();

            let encrypted = plugin
                .encryptor()
                .encrypt(msg_json.as_bytes(), &to_refs, None)
                .await
                .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

            Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&encrypted))
        }
    }
}

/// Unpack a DIDComm message.
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
    recipient: Option<String>,
) -> Result<Message> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(packed)
        .map_err(|e| Error::Base64(format!("Invalid base64: {}", e)))?;

    // Try to parse as JSON first
    if let Ok(message) = serde_json::from_slice::<Message>(&decoded) {
        return Ok(message);
    }

    // If not JSON, try to verify as signed message
    if let Some(from) = recipient.as_ref() {
        let verified = plugin
            .signer()
            .verify(&decoded, &decoded, from)
            .await
            .map_err(|e| Error::VerificationFailed(e.to_string()))?;

        if verified {
            let message: Message = serde_json::from_slice(&decoded)?;
            return Ok(message);
        }
    }

    // If not signed, try to decrypt
    if let Some(recipient) = recipient {
        let decrypted = plugin
            .encryptor()
            .decrypt(&decoded, &recipient)
            .await
            .map_err(|e| Error::DecryptionFailed(e.to_string()))?;

        let message: Message = serde_json::from_slice(&decrypted)?;
        return Ok(message);
    }

    Err(Error::InvalidDIDDocument("Unable to unpack message".into()))
}

pub async fn pack_encrypted<'a>(
    plaintext: &[u8],
    to: &[String],
    from: Option<&str>,
    sign_by: Option<&str>,
    plugins: &impl DIDCommPlugins,
) -> Result<Vec<u8>> {
    // Use ref to avoid moving the value
    if let Some(ref from_did) = from {
        // Clone the string for the validation check
        validate_did(from_did.to_string())?;
    }

    // Validate recipient DIDs
    for recipient in to {
        validate_did(recipient.to_string())?;
    }

    let mut recipients = Vec::new();
    for to_did in to {
        // Clone to_did since we need it for multiple operations
        let to_did = to_did.clone();
        let recipient_key = plugins.resolve_did(&to_did).await?;
        recipients.push(Recipient {
            did: to_did,
            key: recipient_key,
        });
    }

    // Handle signing if requested
    let signed_data = if let Some(ref signer_did) = sign_by {
        // Clone for validation
        validate_did(signer_did.to_string())?;
        let signer = plugins.get_signer(signer_did).await?;
        sign_message(plaintext, signer).await?
    } else {
        plaintext.to_vec()
    };

    // Handle encryption
    let mut builder = EncryptedMessageBuilder::new();

    // Add sender if present
    if let Some(ref sender_did) = from {
        let sender_key = plugins.resolve_did(sender_did).await?;
        builder = builder.from(sender_did.to_string(), sender_key);
    }

    // Add all recipients
    for recipient in recipients {
        builder = builder.add_recipient(recipient.did.clone(), recipient.key);
    }

    // Build and return the encrypted message
    let encrypted = builder.plaintext(&signed_data).build().await?;

    Ok(encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::tests::MockTestPlugin;

    #[tokio::test]
    async fn test_pack_signed() -> Result<()> {
        let plugin = MockTestPlugin;
        let mut message = Message::default();
        message.body = "test".to_string();
        message.from = Some("did:example:alice".to_string());
        message.to = Some(vec!["did:example:bob".to_string()]);

        let packed = pack_message(&message, &plugin, PackingType::Signed).await?;
        let unpacked =
            unpack_message(&packed, &plugin, Some("did:example:alice".to_string())).await?;

        assert_eq!(unpacked.body, message.body);
        Ok(())
    }

    #[tokio::test]
    async fn test_pack_authcrypt() -> Result<()> {
        let plugin = MockTestPlugin;
        let mut message = Message::default();
        message.body = "test".to_string();
        message.from = Some("did:example:alice".to_string());
        message.to = Some(vec!["did:example:bob".to_string()]);

        let packed = pack_message(&message, &plugin, PackingType::AuthcryptV2).await?;
        let unpacked =
            unpack_message(&packed, &plugin, Some("did:example:bob".to_string())).await?;

        assert_eq!(unpacked.body, message.body);
        Ok(())
    }
}
