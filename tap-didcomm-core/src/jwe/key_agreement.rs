//! Key agreement algorithms for JWE.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::error::{Error, Result};

/// Key agreement algorithms supported by JWE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum KeyAgreementAlgorithm {
    /// ECDH-ES with A256KW (anoncrypt)
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256kw,

    /// ECDH-1PU with A256KW (authcrypt)
    #[serde(rename = "ECDH-1PU+A256KW")]
    Ecdh1puA256kw,
}

/// A key encryption key derived from ECDH.
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct KeyEncryptionKey {
    /// The raw key material
    pub(crate) key: Vec<u8>,
}

impl KeyEncryptionKey {
    /// Creates a new key encryption key.
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Gets the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

/// Derives a key encryption key using ECDH-ES.
pub fn derive_key_encryption_key_es(
    shared_secret: &[u8],
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<KeyEncryptionKey> {
    // Validate APU/APV lengths if present
    if let Some(apu) = apu {
        if apu.len() > 512 {
            return Err(Error::InvalidKeyMaterial("APU too long (max 512 bytes)".to_string()));
        }
    }
    if let Some(apv) = apv {
        if apv.len() > 512 {
            return Err(Error::InvalidKeyMaterial("APV too long (max 512 bytes)".to_string()));
        }
    }

    let mut info = Vec::with_capacity(1024);
    info.extend_from_slice(b"A256KW");
    info.extend_from_slice(b"\0");
    
    // Add APU if present, otherwise add empty length
    match apu {
        Some(apu) => {
            info.extend_from_slice(&(apu.len() as u32).to_be_bytes());
            info.extend_from_slice(apu);
        }
        None => info.extend_from_slice(&[0, 0, 0, 0]),
    }
    info.extend_from_slice(b"\0");

    // Add APV if present, otherwise add empty length
    match apv {
        Some(apv) => {
            info.extend_from_slice(&(apv.len() as u32).to_be_bytes());
            info.extend_from_slice(apv);
        }
        None => info.extend_from_slice(&[0, 0, 0, 0]),
    }
    info.extend_from_slice(b"\0");
    info.extend_from_slice(&[0, 0, 1, 0]); // 256 bits

    let mut okm = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, shared_secret)
        .expand(&info, &mut okm)
        .map_err(|_| Error::KeyDerivation("Failed to derive key encryption key".to_string()))?;

    Ok(KeyEncryptionKey::new(okm.to_vec()))
}

/// Derives a key encryption key using ECDH-1PU.
pub fn derive_key_encryption_key_1pu(
    sender_shared_secret: &[u8],
    recipient_shared_secret: &[u8],
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<KeyEncryptionKey> {
    // Validate APU/APV lengths if present
    if let Some(apu) = apu {
        if apu.len() > 512 {
            return Err(Error::InvalidKeyMaterial("APU too long (max 512 bytes)".to_string()));
        }
    }
    if let Some(apv) = apv {
        if apv.len() > 512 {
            return Err(Error::InvalidKeyMaterial("APV too long (max 512 bytes)".to_string()));
        }
    }

    let mut info = Vec::with_capacity(1024);
    info.extend_from_slice(b"A256KW");
    info.extend_from_slice(b"\0");
    
    // Add APU if present, otherwise add empty length
    match apu {
        Some(apu) => {
            info.extend_from_slice(&(apu.len() as u32).to_be_bytes());
            info.extend_from_slice(apu);
        }
        None => info.extend_from_slice(&[0, 0, 0, 0]),
    }
    info.extend_from_slice(b"\0");

    // Add APV if present, otherwise add empty length
    match apv {
        Some(apv) => {
            info.extend_from_slice(&(apv.len() as u32).to_be_bytes());
            info.extend_from_slice(apv);
        }
        None => info.extend_from_slice(&[0, 0, 0, 0]),
    }
    info.extend_from_slice(b"\0");
    info.extend_from_slice(&[0, 0, 1, 0]); // 256 bits

    // Concatenate the shared secrets
    let mut ikm = Vec::with_capacity(sender_shared_secret.len() + recipient_shared_secret.len());
    ikm.extend_from_slice(sender_shared_secret);
    ikm.extend_from_slice(recipient_shared_secret);

    let mut okm = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, &ikm)
        .expand(&info, &mut okm)
        .map_err(|_| Error::KeyDerivation("Failed to derive key encryption key".to_string()))?;

    Ok(KeyEncryptionKey::new(okm.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwe::algorithms::{generate_ephemeral_keypair, ecdh_key_agreement};
    use crate::jwe::EcdhCurve;

    #[test]
    fn test_key_derivation_es() {
        for curve in [EcdhCurve::X25519, EcdhCurve::P256, EcdhCurve::P384, EcdhCurve::P521] {
            let (alice_private, alice_public) = generate_ephemeral_keypair(curve).unwrap();
            let (bob_private, bob_public) = generate_ephemeral_keypair(curve).unwrap();

            // Alice derives the key using Bob's public key
            let alice_shared = ecdh_key_agreement(curve, &alice_private, &bob_public).unwrap();
            let alice_kek = derive_key_encryption_key_es(
                &alice_shared,
                Some(b"alice"),
                Some(b"bob"),
            ).unwrap();

            // Bob derives the key using Alice's public key
            let bob_shared = ecdh_key_agreement(curve, &bob_private, &alice_public).unwrap();
            let bob_kek = derive_key_encryption_key_es(
                &bob_shared,
                Some(b"alice"),
                Some(b"bob"),
            ).unwrap();

            // Both should derive the same key
            assert_eq!(alice_kek.as_bytes(), bob_kek.as_bytes());
        }
    }

    #[test]
    fn test_key_derivation_1pu() {
        for curve in [EcdhCurve::X25519, EcdhCurve::P256, EcdhCurve::P384, EcdhCurve::P521] {
            let (alice_private, alice_public) = generate_ephemeral_keypair(curve).unwrap();
            let (bob_private, bob_public) = generate_ephemeral_keypair(curve).unwrap();
            let (ephemeral_private, ephemeral_public) = generate_ephemeral_keypair(curve).unwrap();

            // Alice (sender) derives the key using Bob's public key and ephemeral key
            let alice_shared = ecdh_key_agreement(curve, &alice_private, &bob_public).unwrap();
            let alice_ephemeral = ecdh_key_agreement(curve, &ephemeral_private, &bob_public).unwrap();
            let alice_kek = derive_key_encryption_key_1pu(
                &alice_shared,
                &alice_ephemeral,
                Some(b"alice"),
                Some(b"bob"),
            ).unwrap();

            // Bob (recipient) derives the key using Alice's public key and ephemeral key
            let bob_shared = ecdh_key_agreement(curve, &bob_private, &alice_public).unwrap();
            let bob_ephemeral = ecdh_key_agreement(curve, &bob_private, &ephemeral_public).unwrap();
            let bob_kek = derive_key_encryption_key_1pu(
                &bob_shared,
                &bob_ephemeral,
                Some(b"alice"),
                Some(b"bob"),
            ).unwrap();

            // Both should derive the same key
            assert_eq!(alice_kek.as_bytes(), bob_kek.as_bytes());
        }
    }

    #[test]
    fn test_key_derivation_with_apu_apv() {
        let shared_secret = vec![1u8; 32];
        let apu = b"Alice";
        let apv = b"Bob";

        let kek = derive_key_encryption_key_es(
            &shared_secret,
            Some(apu),
            Some(apv),
        ).unwrap();

        assert_eq!(kek.as_bytes().len(), 32);

        // Test with empty APU/APV
        let kek2 = derive_key_encryption_key_es(
            &shared_secret,
            None,
            None,
        ).unwrap();

        // Keys should be different with different APU/APV
        assert_ne!(kek.as_bytes(), kek2.as_bytes());
    }

    #[test]
    fn test_key_derivation_invalid_apu_apv() {
        let shared_secret = vec![1u8; 32];
        let long_apu = vec![0u8; 513]; // Too long
        let long_apv = vec![0u8; 513]; // Too long

        let result = derive_key_encryption_key_es(
            &shared_secret,
            Some(&long_apu),
            None,
        );
        assert!(result.is_err());

        let result = derive_key_encryption_key_es(
            &shared_secret,
            None,
            Some(&long_apv),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_key_agreement_algorithm_serde() {
        let alg = KeyAgreementAlgorithm::EcdhEsA256kw;
        let json = serde_json::to_string(&alg).unwrap();
        assert_eq!(json, "\"ECDH-ES+A256KW\"");

        let alg = KeyAgreementAlgorithm::Ecdh1puA256kw;
        let json = serde_json::to_string(&alg).unwrap();
        assert_eq!(json, "\"ECDH-1PU+A256KW\"");
    }
} 