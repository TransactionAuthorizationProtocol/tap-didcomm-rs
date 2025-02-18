//! Message packing and unpacking functionality.
//!
//! This module provides functions for packing and unpacking `DIDComm` messages
//! using different methods (`Signed`, `AuthCrypt`, `AnonCrypt`).

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::jwe::EncryptedMessageBuilder;
use crate::plugin::DIDCommPlugin;
use crate::plugin::DIDCommPlugins;
use crate::types::PackingType;
use crate::utils::validate_did;

/// A recipient for an encrypted message.
#[derive(Debug, Clone)]
pub struct Recipient {
    /// The recipient's DID
    pub did: String,
    /// The recipient's encryption key
    pub key: Vec<u8>,
}

/// A `DIDComm` message.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Message {
    /// The unique identifier for this message
    pub id: String,

    /// The message body as a JSON value
    pub body: Value,

    /// The sender DID (optional)
    pub from: Option<String>,

    /// The recipient DIDs (optional)
    pub to: Option<Vec<String>>,
}

impl Message {
    /// Creates a new message with the given body.
    ///
    /// # Arguments
    /// * `body` - The message body that can be converted into a JSON value
    ///
    /// # Returns
    /// A new `Message` instance with the given body
    #[must_use]
    pub fn new<T: Into<Value>>(body: T) -> Self {
        Message {
            id: Uuid::new_v4().to_string(),
            body: body.into(),
            from: None,
            to: None,
        }
    }

    /// Sets the sender DID.
    ///
    /// # Arguments
    /// * `from` - The sender's DID as a string reference
    ///
    /// # Returns
    /// The modified `Message` instance
    #[must_use]
    pub fn from<S: AsRef<str>>(mut self, from: S) -> Self {
        self.from = Some(from.as_ref().to_string());
        self
    }

    /// Sets the recipients of the message.
    ///
    /// # Arguments
    /// * `to` - The recipient DIDs as an iterator of string references
    ///
    /// # Returns
    /// The modified `Message` instance
    #[must_use]
    pub fn to<S: AsRef<str>>(mut self, to: impl IntoIterator<Item = S>) -> Self {
        self.to = Some(to.into_iter().map(|s| s.as_ref().to_string()).collect());
        self
    }

    /// Gets the message body as a JSON string.
    ///
    /// # Errors
    /// Returns an error if the body cannot be serialized to JSON
    fn to_json_string(&self) -> Result<String> {
        serde_json::to_string(&self.body).map_err(Error::Json)
    }
}

/// Pack a message using the specified packing type.
///
/// # Arguments
/// * `message` - The message to pack
/// * `plugin` - Plugin providing cryptographic operations
/// * `packing_type` - Type of packing to use (`Signed`, `AuthCryptV2`, `AnonV2`)
///
/// # Returns
/// The packed message as a base64url-encoded string
///
/// # Errors
/// * `Error::InvalidDIDDocument` - If a DID is invalid or missing when required
/// * `Error::Base64` - If base64 encoding fails
/// * `Error::Json` - If JSON serialization fails
/// * `Error::SigningFailed` - If message signing fails
/// * `Error::EncryptionFailed` - If message encryption fails
pub async fn pack_message(
    message: &Message,
    plugin: &dyn DIDCommPlugin,
    packing_type: PackingType,
) -> Result<String> {
    let msg_json = message.to_json_string()?;
    match packing_type {
        PackingType::Signed => {
            let from = message.from.as_deref().ok_or_else(|| {
                Error::InvalidDIDDocument("Sender DID required for signed messages".into())
            })?;
            validate_did(from)?;
            let signed = plugin.signer().sign(msg_json.as_bytes(), from).await?;
            Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signed))
        }
        PackingType::AuthcryptV2 => {
            let from = message.from.as_deref().ok_or_else(|| {
                Error::InvalidDIDDocument("Sender DID required for authcrypt".into())
            })?;
            validate_did(from)?;
            let recipients = message.to.as_ref().ok_or_else(|| {
                Error::InvalidDIDDocument("At least one recipient required for authcrypt".into())
            })?;
            if recipients.is_empty() {
                return Err(Error::InvalidDIDDocument(
                    "At least one recipient required for authcrypt".into(),
                ));
            }
            for did in recipients {
                validate_did(did)?;
            }
            let to_refs: Vec<&str> = recipients.iter().map(String::as_str).collect();
            let encrypted = plugin
                .encryptor()
                .encrypt(msg_json.as_bytes(), &to_refs, Some(from))
                .await?;
            Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&encrypted))
        }
        PackingType::AnonV2 => {
            let recipients = message.to.as_ref().ok_or_else(|| {
                Error::InvalidDIDDocument("At least one recipient required for anoncrypt".into())
            })?;
            if recipients.is_empty() {
                return Err(Error::InvalidDIDDocument(
                    "At least one recipient required for anoncrypt".into(),
                ));
            }
            for did in recipients {
                validate_did(did)?;
            }
            let to_refs: Vec<&str> = recipients.iter().map(String::as_str).collect();
            let encrypted = plugin
                .encryptor()
                .encrypt(msg_json.as_bytes(), &to_refs, None)
                .await?;
            Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&encrypted))
        }
    }
}

/// Unpack a `DIDComm` message.
///
/// # Arguments
/// * `packed` - The packed message to unpack
/// * `plugin` - Plugin providing cryptographic operations
/// * `recipient` - Optional recipient DID to use for decryption
///
/// # Errors
/// * `Error::Base64` - If base64 decoding fails
/// * `Error::Json` - If JSON parsing fails
/// * `Error::InvalidDIDDocument` - If a DID document is invalid
/// * `Error::KeyAgreement` - If key agreement fails
/// * `Error::ContentEncryption` - If content decryption fails
pub async fn unpack_message(
    packed: &str,
    plugin: &dyn DIDCommPlugin,
    recipient: Option<String>,
) -> Result<Message> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(packed)
        .map_err(|e| Error::Base64(format!("Invalid base64: {e}")))?;

    // Try to parse as JSON first
    if let Ok(message) = serde_json::from_slice::<Message>(&decoded) {
        return Ok(message);
    }

    // If not JSON, try to verify as signed message
    if let Some(from) = recipient.as_ref() {
        validate_did(from)?;
        let verified = plugin.signer().verify(&decoded, &decoded, from).await?;
        if verified {
            let message: Message = serde_json::from_slice(&decoded)?;
            return Ok(message);
        }
    }

    // If not signed, try to decrypt
    if let Some(recipient) = recipient.as_ref() {
        validate_did(recipient)?;
        let decrypted = plugin.encryptor().decrypt(&decoded, recipient).await?;
        let message: Message = serde_json::from_slice(&decrypted)?;
        return Ok(message);
    }

    Err(Error::InvalidDIDDocument("Unable to unpack message".into()))
}

/// Packs a message with encryption for multiple recipients.
///
/// # Arguments
/// * `plaintext` - The message data to encrypt
/// * `to` - List of recipient DIDs
/// * `from` - Optional sender DID for authenticated encryption
/// * `sign_by` - Optional DID to sign the message with
/// * `plugins` - Plugin implementations for cryptographic operations
///
/// # Returns
/// The encrypted message bytes
///
/// # Errors
/// Returns an error if:
/// - DID validation fails
/// - Key resolution fails
/// - Encryption fails
/// - Signing fails (if requested)
pub async fn pack_encrypted(
    plaintext: &[u8],
    to: &[String],
    from: Option<&str>,
    sign_by: Option<&str>,
    plugins: &impl DIDCommPlugins,
) -> Result<Vec<u8>> {
    // Validate sender DID if present
    if let Some(from_did) = from {
        validate_did(from_did)?;
    }

    // Validate recipient DIDs
    for recipient in to {
        validate_did(recipient)?;
    }

    // Validate signer DID if present
    if let Some(signer_did) = sign_by {
        validate_did(signer_did)?;
    }

    let mut recipients = Vec::new();
    for to_did in to {
        let recipient_key = plugins.resolve_did(to_did).await?;
        recipients.push(Recipient {
            did: to_did.clone(),
            key: recipient_key,
        });
    }

    // Handle signing if requested
    let signed_data = if let Some(signer_did) = sign_by {
        let signer = plugins.get_signer(signer_did).await?;
        signer.sign(plaintext, signer_did).await?
    } else {
        plaintext.to_vec()
    };

    // Handle encryption
    let mut builder = EncryptedMessageBuilder::new();

    // Add sender if present
    if let Some(sender_did) = from {
        let sender_key = plugins.resolve_did(sender_did).await?;
        builder = builder.from(sender_did.to_string(), sender_key);
    }

    // Add all recipients
    for recipient in recipients {
        builder = builder.add_recipient(recipient.did, recipient.key);
    }

    // Build and return the encrypted message
    builder.plaintext(&signed_data).build().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::tests::MockTestPlugin;
    use serde_json::json;

    #[tokio::test]
    async fn test_pack_signed() -> Result<()> {
        let plugin = MockTestPlugin;
        let message = Message::new(json!("test"))
            .from("did:example:alice")
            .to(vec!["did:example:bob"]);

        let packed = pack_message(&message, &plugin, PackingType::Signed).await?;
        let unpacked =
            unpack_message(&packed, &plugin, Some("did:example:alice".to_string())).await?;

        assert_eq!(unpacked.body, message.body);
        Ok(())
    }

    #[tokio::test]
    async fn test_pack_authcrypt() -> Result<()> {
        let plugin = MockTestPlugin;
        let message = Message::new(json!("test"))
            .from("did:example:alice")
            .to(vec!["did:example:bob"]);

        let packed = pack_message(&message, &plugin, PackingType::AuthcryptV2).await?;
        let unpacked =
            unpack_message(&packed, &plugin, Some("did:example:bob".to_string())).await?;

        assert_eq!(unpacked.body, message.body);
        Ok(())
    }
}
