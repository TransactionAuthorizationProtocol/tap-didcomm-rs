//! Key wrapping algorithms for JWE.

use aes_kw::KekAes256;
use zeroize::Zeroize;

use super::error::{Error, Result};
use super::key_agreement::KeyEncryptionKey;

/// A content encryption key.
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct ContentEncryptionKey {
    /// The raw key material
    pub(crate) key: Vec<u8>,
}

impl ContentEncryptionKey {
    /// Creates a new content encryption key.
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Gets the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

/// Wraps a content encryption key using AES-KW.
pub fn wrap_key(kek: &KeyEncryptionKey, cek: &ContentEncryptionKey) -> Result<Vec<u8>> {
    let kek = KekAes256::from(kek.as_bytes());
    kek.wrap_key(cek.as_bytes())
        .map_err(|_| Error::KeyWrap("Failed to wrap key".to_string()))
}

/// Unwraps a content encryption key using AES-KW.
pub fn unwrap_key(kek: &KeyEncryptionKey, wrapped_key: &[u8]) -> Result<ContentEncryptionKey> {
    let kek = KekAes256::from(kek.as_bytes());
    let key = kek
        .unwrap_key(wrapped_key)
        .map_err(|_| Error::KeyWrap("Failed to unwrap key".to_string()))?;
    Ok(ContentEncryptionKey::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwe::algorithms::{ecdh_key_agreement, generate_ephemeral_keypair};
    use crate::jwe::key_agreement::derive_key_encryption_key_es;
    use crate::jwe::EcdhCurve;

    #[test]
    fn test_key_wrapping() {
        // Generate random content encryption key
        let cek = ContentEncryptionKey::new(vec![0x42; 32]);

        // Test with each curve
        for curve in [
            EcdhCurve::X25519,
            EcdhCurve::P256,
            EcdhCurve::P384,
            EcdhCurve::P521,
        ] {
            let (alice_private, alice_public) = generate_ephemeral_keypair(curve).unwrap();
            let (bob_private, bob_public) = generate_ephemeral_keypair(curve).unwrap();

            // Alice wraps the key
            let alice_shared = ecdh_key_agreement(curve, &alice_private, &bob_public).unwrap();
            let alice_kek = derive_key_encryption_key_es(&alice_shared, None, None).unwrap();
            let wrapped_key = wrap_key(&alice_kek, &cek).unwrap();

            // Bob unwraps the key
            let bob_shared = ecdh_key_agreement(curve, &bob_private, &alice_public).unwrap();
            let bob_kek = derive_key_encryption_key_es(&bob_shared, None, None).unwrap();
            let unwrapped_cek = unwrap_key(&bob_kek, &wrapped_key).unwrap();

            // Verify the unwrapped key matches the original
            assert_eq!(unwrapped_cek.as_bytes(), cek.as_bytes());
        }
    }

    #[test]
    fn test_invalid_key_wrapping() {
        let cek = ContentEncryptionKey::new(vec![0x42; 32]);
        let kek = KeyEncryptionKey::new(vec![0; 32]);

        // Wrap the key
        let wrapped_key = wrap_key(&kek, &cek).unwrap();

        // Try to unwrap with wrong key
        let wrong_kek = KeyEncryptionKey::new(vec![1; 32]);
        let result = unwrap_key(&wrong_kek, &wrapped_key);
        assert!(result.is_err());

        // Try to unwrap invalid data
        let result = unwrap_key(&kek, &[0; 32]);
        assert!(result.is_err());
    }
}
