//! Message packing and unpacking functionality.

use base64::{Engine, engine::general_purpose::STANDARD};

use crate::{
    error::{Error, Result},
    types::{Message, PackingType},
    plugin::DIDCommPlugin,
};

/// Pack a DIDComm message using the specified packing type
pub async fn pack_message(
    message: &Message,
    plugin: &dyn DIDCommPlugin,
    packing_type: PackingType,
) -> Result<String> {
    let message_bytes = serde_json::to_vec(message).map_err(Error::Serialization)?;
    let to = message.to.clone().unwrap_or_default();
    let from = message.from.clone();

    match packing_type {
        PackingType::Signed => {
            if let Some(from) = from {
                let signature = plugin.as_signer().sign(&message_bytes, &from).await?;
                plugin
                    .as_signer()
                    .verify(&message_bytes, &signature, &from)
                    .await?;
                Ok(STANDARD.encode(signature))
            } else {
                Err(Error::MissingField("from"))
            }
        }
        PackingType::AuthcryptV2 => {
            let encrypted = plugin
                .as_encryptor()
                .encrypt(&message_bytes, to, from)
                .await?;
            Ok(STANDARD.encode(encrypted))
        }
        PackingType::AnonV2 => {
            let encrypted = plugin
                .as_encryptor()
                .encrypt(&message_bytes, to, None)
                .await?;
            Ok(STANDARD.encode(encrypted))
        }
    }
}

/// Unpack a DIDComm message
pub async fn unpack_message(
    packed: &str,
    plugin: &dyn DIDCommPlugin,
    recipient: Option<String>,
) -> Result<Message> {
    let data = STANDARD.decode(packed)
        .map_err(|e| Error::InvalidFormat(format!("Invalid base64: {}", e)))?;

    if let Some(recipient) = recipient {
        let decrypted = plugin.as_encryptor().decrypt(&data, recipient).await?;
        let message = serde_json::from_slice(&decrypted).map_err(Error::Serialization)?;
        Ok(message)
    } else {
        Err(Error::MissingField("recipient"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_utils::MockTestPlugin;
    use mockall::predicate::eq;
    use serde_json::json;

    #[tokio::test]
    async fn test_pack_unpack_signed() {
        let mut plugin = MockTestPlugin::new();
        let mut plugin_clone = plugin.clone();
        let message = Message::new("test", json!({"hello": "world"}))
            .unwrap()
            .from("did:example:alice");

        let message_bytes = serde_json::to_vec(&message).unwrap();
        let signature = vec![1, 2, 3, 4];
        let signature_for_sign = signature.clone();
        let signature_for_verify = signature.clone();

        plugin_clone
            .expect_sign()
            .with(eq(message_bytes.clone()), eq("did:example:alice"))
            .times(1)
            .returning(move |_, _| Ok(signature_for_sign.clone()));

        plugin_clone
            .expect_verify()
            .with(eq(message_bytes.clone()), eq(signature_for_verify.clone()), eq("did:example:alice"))
            .times(1)
            .returning(move |_, _, _| Ok(true));

        plugin
            .expect_as_signer()
            .times(2)
            .return_const(Box::new(plugin_clone) as Box<dyn crate::plugin::Signer>);

        let packed = pack_message(&message, &plugin, PackingType::Signed).await.unwrap();
        assert_eq!(packed, base64::engine::general_purpose::STANDARD.encode(&signature));
    }

    #[tokio::test]
    async fn test_pack_unpack_authcrypt() {
        let mut plugin = MockTestPlugin::new();
        let mut plugin_clone = plugin.clone();
        let message = Message::new("test", json!({"hello": "world"}))
            .unwrap()
            .from("did:example:alice")
            .to(vec!["did:example:bob"]);

        let message_bytes = serde_json::to_vec(&message).unwrap();
        let encrypted = vec![5, 6, 7, 8];
        let encrypted_for_encrypt = encrypted.clone();
        let encrypted_for_decrypt = encrypted.clone();
        let message_bytes_for_decrypt = message_bytes.clone();

        plugin_clone
            .expect_encrypt()
            .with(
                eq(message_bytes.clone()),
                eq(vec!["did:example:bob".to_string()]),
                eq(Some("did:example:alice".to_string())),
            )
            .times(1)
            .returning(move |_, _, _| Ok(encrypted_for_encrypt.clone()));

        plugin_clone
            .expect_decrypt()
            .with(eq(encrypted_for_decrypt.clone()), eq("did:example:bob".to_string()))
            .times(1)
            .returning(move |_, _| Ok(message_bytes_for_decrypt.clone()));

        plugin
            .expect_as_encryptor()
            .times(2)
            .return_const(Box::new(plugin_clone) as Box<dyn crate::plugin::Encryptor>);

        let packed = pack_message(&message, &plugin, PackingType::AuthcryptV2).await.unwrap();
        let unpacked = unpack_message(&packed, &plugin, Some("did:example:bob".to_string())).await.unwrap();
        assert_eq!(serde_json::to_value(&unpacked).unwrap(), serde_json::to_value(&message).unwrap());
    }
}