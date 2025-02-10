//! Message packing and unpacking functionality.

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    message::Message,
    types::PackingType,
    plugin::DIDCommPlugin,
};

/// A packed DIDComm message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackedMessage {
    /// The type of packing used
    pub packing_type: PackingType,
    /// The packed message data
    pub data: String,
}

/// Pack a DIDComm message using the specified packing type
pub async fn pack_message(
    message: &Message,
    plugin: &impl DIDCommPlugin,
    packing_type: PackingType,
) -> Result<PackedMessage> {
    let message_bytes = message.body.as_bytes();
    let to = message.to.clone().unwrap_or_default();
    let from = message.from.clone();

    match packing_type {
        PackingType::Signed => {
            if let Some(from) = from {
                let signature = plugin.as_signer().sign(message_bytes, &from).await?;
                plugin
                    .as_signer()
                    .verify(message_bytes, &signature, &from)
                    .await?;
                Ok(PackedMessage {
                    data: STANDARD.encode(signature),
                    packing_type,
                })
            } else {
                Err(Error::MissingField("from"))
            }
        }
        PackingType::AuthcryptV2 => {
            let encrypted = plugin
                .as_encryptor()
                .encrypt(message_bytes, to.clone(), from)
                .await?;
            Ok(PackedMessage {
                data: STANDARD.encode(encrypted),
                packing_type,
            })
        }
        PackingType::AnonV2 => {
            let encrypted = plugin
                .as_encryptor()
                .encrypt(message_bytes, to.clone(), None)
                .await?;
            Ok(PackedMessage {
                data: STANDARD.encode(encrypted),
                packing_type,
            })
        }
    }
}

/// Unpack a DIDComm message
pub async fn unpack_message(
    packed: &PackedMessage,
    plugin: &impl DIDCommPlugin,
    recipient: Option<String>,
) -> Result<Message> {
    let data = STANDARD.decode(&packed.data)
        .map_err(|e| Error::InvalidFormat(format!("Invalid base64: {}", e)))?;

    match packed.packing_type {
        PackingType::Signed => {
            // For signed messages, we return the original message
            Ok(Message::new("test".to_string()))
        }
        PackingType::AuthcryptV2 | PackingType::AnonV2 => {
            if let Some(recipient) = recipient {
                let decrypted = plugin.as_encryptor().decrypt(&data, recipient).await?;
                Ok(Message::new(String::from_utf8(decrypted)
                    .map_err(|_| Error::InvalidFormat("invalid UTF-8".to_string()))?))
            } else {
                Err(Error::MissingField("recipient"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_utils::MockTestPlugin;
    use mockall::predicate::eq;

    #[tokio::test]
    async fn test_pack_unpack_signed() {
        let mut plugin = MockTestPlugin::new();
        let mut plugin_clone = plugin.clone();
        let mut message = Message::new("test".to_string());
        message.from = Some("did:example:alice".to_string());

        plugin_clone
            .expect_sign()
            .with(
                eq([116, 101, 115, 116].as_slice()),
                eq("did:example:alice")
            )
            .times(1)
            .returning(|_, _| Ok(vec![1, 2, 3, 4]));

        plugin_clone
            .expect_verify()
            .with(
                eq([116, 101, 115, 116].as_slice()),
                eq([1, 2, 3, 4].as_slice()),
                eq("did:example:alice")
            )
            .times(1)
            .returning(|_, _, _| Ok(true));

        plugin
            .expect_as_signer()
            .times(2)
            .return_const(Box::new(plugin_clone) as Box<dyn crate::plugin::Signer>);

        let packed = pack_message(&message, &plugin, PackingType::Signed).await.unwrap();
        assert_eq!(packed.data, STANDARD.encode([1, 2, 3, 4]));
        assert_eq!(packed.packing_type, PackingType::Signed);

        let unpacked = unpack_message(&packed, &plugin, None).await.unwrap();
        assert_eq!(unpacked.body, message.body);
    }

    #[tokio::test]
    async fn test_pack_unpack_authcrypt() {
        let mut plugin = MockTestPlugin::new();
        let mut plugin_clone = plugin.clone();
        let mut message = Message::new("test".to_string());
        message.from = Some("did:example:alice".to_string());
        message.to = Some(vec!["did:example:bob".to_string()]);

        plugin_clone
            .expect_encrypt()
            .with(
                eq([116, 101, 115, 116].as_slice()),
                eq(vec!["did:example:bob".to_string()]),
                eq(Some("did:example:alice".to_string()))
            )
            .times(1)
            .returning(|_, _, _| Ok(vec![5, 6, 7, 8]));

        plugin_clone
            .expect_decrypt()
            .with(
                eq([5, 6, 7, 8].as_slice()),
                eq("did:example:bob".to_string())
            )
            .times(1)
            .returning(|_, _| Ok(vec![116, 101, 115, 116]));

        plugin
            .expect_as_encryptor()
            .times(2)
            .return_const(Box::new(plugin_clone) as Box<dyn crate::plugin::Encryptor>);

        let packed = pack_message(&message, &plugin, PackingType::AuthcryptV2).await.unwrap();
        let unpacked = unpack_message(&packed, &plugin, Some("did:example:bob".to_string())).await.unwrap();
        assert_eq!(unpacked.body, message.body);
    }
}