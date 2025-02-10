use mockall::mock;
use mockall::predicate::*;

/// Test utilities for the DIDComm core library
pub mod test_utils {
    use super::*;
    use crate::plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer};
    use crate::error::Result;
    use async_trait::async_trait;

    mock! {
        pub TestPlugin {}

        #[async_trait]
        impl DIDResolver for TestPlugin {
            async fn resolve(&self, did: &str) -> Result<String>;
        }

        #[async_trait]
        impl Signer for TestPlugin {
            async fn sign(&self, message: &[u8], key_id: &str) -> Result<Vec<u8>>;
            async fn verify(&self, message: &[u8], signature: &[u8], key_id: &str) -> Result<bool>;
        }

        #[async_trait]
        impl Encryptor for TestPlugin {
            async fn encrypt(&self, message: &[u8], recipients: Vec<String>, from: Option<String>) -> Result<Vec<u8>>;
            async fn decrypt(&self, message: &[u8], recipient: String) -> Result<Vec<u8>>;
        }

        impl DIDCommPlugin for TestPlugin {
            fn as_resolver(&self) -> &dyn DIDResolver {
                self
            }
            fn as_signer(&self) -> &dyn Signer {
                self
            }
            fn as_encryptor(&self) -> &dyn Encryptor {
                self
            }
        }
    }

    impl Clone for MockTestPlugin {
        fn clone(&self) -> Self {
            MockTestPlugin::new()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn test_resolve() {
            let mut plugin = MockTestPlugin::new();
            plugin
                .expect_resolve()
                .with(eq("did:example:123"))
                .returning(|_| Ok("resolved".to_string()));

            let result = plugin.resolve("did:example:123").await.unwrap();
            assert_eq!(result, "resolved");
        }

        #[tokio::test]
        async fn test_sign() {
            let mut plugin = MockTestPlugin::new();
            let test_bytes = b"test".as_slice();

            plugin
                .expect_sign()
                .with(eq(test_bytes), eq("key1"))
                .returning(|_, _| Ok(vec![1, 2, 3, 4]));

            let result = plugin.sign(test_bytes, "key1").await.unwrap();
            assert_eq!(result, vec![1, 2, 3, 4]);
        }

        #[tokio::test]
        async fn test_encrypt() {
            let mut plugin = MockTestPlugin::new();
            let test_bytes = b"test".as_slice();
            let recipients = vec![String::from("did:example:bob")];
            let from = Some(String::from("did:example:alice"));

            plugin
                .expect_encrypt()
                .with(eq(test_bytes), eq(recipients.clone()), eq(from.clone()))
                .returning(|_, _, _| Ok(vec![5, 6, 7, 8]));

            let result = plugin
                .encrypt(test_bytes, recipients, from)
                .await
                .unwrap();
            assert_eq!(result, vec![5, 6, 7, 8]);
        }
    }
} 