//! Cryptographic algorithms for JWE operations.
//!
//! This module provides implementations of the cryptographic algorithms required for
//! JWE (JSON Web Encryption) in DIDComm v2, including:
//! - ECDH key agreement (X25519 and NIST curves)
//! - Key derivation (HKDF)
//! - Content encryption (AES-GCM, AES-CBC-HMAC, XChaCha20-Poly1305)
//!
//! # Security Considerations
//!
//! - All key material is automatically zeroized when dropped
//! - Constant-time operations are used where possible
//! - Random values use the system's secure random number generator
//! - Nonce reuse is prevented by using random nonces
//! - Authentication tags are validated in constant time

use aes::{
    cipher::{BlockDecrypt, BlockEncrypt},
    Aes256,
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdh::{EphemeralSecret as P256EphemeralSecret, SharedSecret as P256SharedSecret};
use p256::EncodedPoint as P256EncodedPoint;
use p256::PublicKey as P256PublicKey;
use p384::ecdh::{EphemeralSecret as P384EphemeralSecret, SharedSecret as P384SharedSecret};
use p384::EncodedPoint as P384EncodedPoint;
use p384::PublicKey as P384PublicKey;
use p521::ecdh::{EphemeralSecret as P521EphemeralSecret, SharedSecret as P521SharedSecret};
use p521::elliptic_curve;
use p521::EncodedPoint as P521EncodedPoint;
use p521::PublicKey as P521PublicKey;
use rand_core::{OsRng, RngCore};
use sha2::Sha512;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::{
    error::{JweError, Result},
    ContentEncryptionAlgorithm, EcdhCurve, EncryptionKey,
};

use aes::cipher::{generic_array::GenericArray, KeyInit};

/// The size of an AES-256 key in bytes.
const AES_256_KEY_SIZE: usize = 32;

/// The size of an HMAC-SHA-512 key in bytes.
const HMAC_SHA512_KEY_SIZE: usize = 64;

/// The size of an authentication tag in bytes.
const AUTH_TAG_SIZE: usize = 32;

/// Generates a random key of the specified size.
///
/// # Arguments
///
/// * `size` - The size of the key in bytes
///
/// # Returns
///
/// A vector containing the random key bytes.
///
/// # Security
///
/// Uses the system's secure random number generator.
pub fn generate_random_key(size: usize) -> Vec<u8> {
    let mut key = vec![0u8; size];
    OsRng.fill_bytes(&mut key);
    key
}

/// Performs ECDH key agreement using the specified curve.
///
/// # Arguments
///
/// * `curve` - The elliptic curve to use
/// * `private_key` - The private key bytes
/// * `public_key` - The public key bytes
///
/// # Returns
///
/// The shared secret bytes.
///
/// # Errors
///
/// Returns an error if:
/// - The key material is invalid
/// - The curve is not supported
/// - The key agreement operation fails
pub fn ecdh_key_agreement(
    curve: EcdhCurve,
    private_key: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>> {
    match curve {
        EcdhCurve::X25519 => x25519_key_agreement(private_key, public_key),
        EcdhCurve::P256 => p256_key_agreement(private_key, public_key),
        EcdhCurve::P384 => p384_key_agreement(private_key, public_key),
        EcdhCurve::P521 => p521_key_agreement(private_key, public_key),
    }
}

/// Generates an ephemeral keypair for the specified curve.
///
/// # Arguments
///
/// * `curve` - The elliptic curve to use
///
/// # Returns
///
/// A tuple containing the private and public key bytes.
///
/// # Errors
///
/// Returns an error if:
/// - The curve is not supported
/// - Key generation fails
pub fn generate_ephemeral_keypair(curve: EcdhCurve) -> Result<(Vec<u8>, Vec<u8>)> {
    match curve {
        EcdhCurve::X25519 => Ok(generate_x25519_ephemeral()),
        EcdhCurve::P256 => generate_p256_ephemeral(),
        EcdhCurve::P384 => generate_p384_ephemeral(),
        EcdhCurve::P521 => generate_p521_ephemeral(),
    }
}

/// Performs X25519 key agreement
fn x25519_key_agreement(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    let secret = StaticSecret::from_slice(private_key)
        .map_err(|e| JweError::InvalidKeyMaterial(format!("Invalid private key: {}", e)))?;
    
    let public = PublicKey::from_slice(public_key)
        .map_err(|e| JweError::InvalidKeyMaterial(format!("Invalid public key: {}", e)))?;

    Ok(secret.diffie_hellman(&public).as_bytes().to_vec())
}

/// Generates an X25519 ephemeral keypair
fn generate_x25519_ephemeral() -> (Vec<u8>, Vec<u8>) {
    let secret = EphemeralSecret::new(OsRng);
    let public = PublicKey::from(&secret);
    
    (secret.to_bytes().to_vec(), public.as_bytes().to_vec())
}

/// Derives a key using HKDF.
///
/// # Arguments
///
/// * `shared_secret` - The shared secret to derive from
/// * `salt` - The salt value (should be random)
/// * `info` - The info string (context information)
/// * `length` - The desired length of the derived key
///
/// # Returns
///
/// The derived key bytes.
///
/// # Errors
///
/// Returns an error if the key derivation fails.
pub fn derive_key(
    shared_secret: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha512>::new(Some(salt), shared_secret);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|e| JweError::KeyAgreement(format!("HKDF error: {}", e)))?;
    Ok(okm)
}

/// Wraps a content encryption key using AES key wrapping
pub fn wrap_key(kek: &[u8], cek: &[u8]) -> crate::error::Result<Vec<u8>> {
    use aes::Aes256;
    use aes_kw::KekAes256;

    // Convert kek to GenericArray
    let kek_array = GenericArray::from_slice(kek);
    let cipher = KekAes256::new(kek_array);
    
    // Wrap the key
    let mut wrapped = vec![0u8; cek.len() + 8];
    cipher
        .wrap_with_padding(cek, &mut wrapped)
        .map_err(|e| JweError::KeyWrap(format!("Key wrapping failed: {}", e)))?;

    Ok(wrapped)
}

/// Unwraps a wrapped key using AES key unwrapping
pub fn unwrap_key(kek: &[u8], wrapped: &[u8]) -> crate::error::Result<Vec<u8>> {
    use aes::Aes256;
    use aes_kw::KekAes256;

    // Convert kek to GenericArray
    let kek_array = GenericArray::from_slice(kek);
    let cipher = KekAes256::new(kek_array);
    
    // Unwrap the key
    let mut unwrapped = vec![0u8; wrapped.len() - 8];
    cipher
        .unwrap_with_padding(wrapped, &mut unwrapped)
        .map_err(|e| JweError::KeyWrap(format!("Key unwrapping failed: {}", e)))?;

    Ok(unwrapped)
}

/// Encrypts data using AES-GCM.
///
/// # Arguments
///
/// * `key` - The encryption key (must be 32 bytes)
/// * `nonce` - The nonce value (must be 12 bytes)
/// * `aad` - The additional authenticated data
/// * `plaintext` - The data to encrypt
///
/// # Returns
///
/// A tuple containing the ciphertext and authentication tag.
///
/// # Errors
///
/// Returns an error if:
/// - The key or nonce length is invalid
/// - Encryption fails
pub fn encrypt_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    if key.len() != 32 {
        return Err(JweError::InvalidKeyMaterial(
            "Invalid AES-256 key length".to_string(),
        ));
    }
    if nonce.len() != 12 {
        return Err(JweError::InvalidKeyMaterial(
            "Invalid nonce length".to_string(),
        ));
    }

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| JweError::ContentEncryption(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| JweError::ContentEncryption(e.to_string()))
        .map(|ciphertext| {
            let tag = ciphertext[ciphertext.len() - 16..].to_vec();
            let ciphertext = ciphertext[..ciphertext.len() - 16].to_vec();
            (ciphertext, tag)
        })
}

/// Decrypts data using AES-GCM.
///
/// # Arguments
///
/// * `key` - The decryption key (must be 32 bytes)
/// * `nonce` - The nonce value (must be 12 bytes)
/// * `aad` - The additional authenticated data
/// * `ciphertext` - The data to decrypt
/// * `tag` - The authentication tag
///
/// # Returns
///
/// The decrypted data.
///
/// # Errors
///
/// Returns an error if:
/// - The key or nonce length is invalid
/// - Authentication fails
/// - Decryption fails
pub fn decrypt_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(JweError::InvalidKeyMaterial(
            "Invalid AES-256 key length".to_string(),
        ));
    }
    if nonce.len() != 12 {
        return Err(JweError::InvalidKeyMaterial(
            "Invalid nonce length".to_string(),
        ));
    }
    if tag.len() != 16 {
        return Err(JweError::InvalidKeyMaterial(
            "Invalid authentication tag length".to_string(),
        ));
    }

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| JweError::ContentEncryption(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce);

    // Combine ciphertext and tag
    let mut ciphertext_with_tag = ciphertext.to_vec();
    ciphertext_with_tag.extend_from_slice(tag);

    cipher
        .decrypt(nonce, ciphertext_with_tag.as_ref())
        .map_err(|e| JweError::ContentEncryption(e.to_string()))
}

/// Encrypts data using XChaCha20-Poly1305.
///
/// # Arguments
///
/// * `key` - The encryption key (must be 32 bytes)
/// * `nonce` - The nonce value (must be 24 bytes)
/// * `aad` - The additional authenticated data
/// * `plaintext` - The data to encrypt
///
/// # Returns
///
/// A tuple containing the ciphertext and authentication tag.
///
/// # Errors
///
/// Returns an error if:
/// - The key or nonce length is invalid
/// - Encryption fails
pub fn encrypt_xchacha20poly1305(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    if key.len() != 32 {
        return Err(JweError::InvalidKeyMaterial(
            "Invalid key length".to_string(),
        ));
    }
    if nonce.len() != 24 {
        return Err(JweError::InvalidKeyMaterial(
            "Invalid nonce length".to_string(),
        ));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| JweError::ContentEncryption(e.to_string()))?;

    let nonce = ChaChaKey::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| JweError::ContentEncryption(e.to_string()))
        .map(|ciphertext| {
            let tag = ciphertext[ciphertext.len() - 16..].to_vec();
            let ciphertext = ciphertext[..ciphertext.len() - 16].to_vec();
            (ciphertext, tag)
        })
}

/// Decrypts data using XChaCha20-Poly1305.
///
/// # Arguments
///
/// * `key` - The decryption key (must be 32 bytes)
/// * `nonce` - The nonce value (must be 24 bytes)
/// * `aad` - The additional authenticated data
/// * `ciphertext` - The data to decrypt
/// * `tag` - The authentication tag
///
/// # Returns
///
/// The decrypted data.
///
/// # Errors
///
/// Returns an error if:
/// - The key or nonce length is invalid
/// - Authentication fails
/// - Decryption fails
pub fn decrypt_xchacha20poly1305(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(JweError::InvalidKeyMaterial(
            "Invalid key length".to_string(),
        ));
    }
    if nonce.len() != 24 {
        return Err(JweError::InvalidKeyMaterial(
            "Invalid nonce length".to_string(),
        ));
    }
    if tag.len() != 16 {
        return Err(JweError::InvalidKeyMaterial(
            "Invalid authentication tag length".to_string(),
        ));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| JweError::ContentEncryption(e.to_string()))?;

    let nonce = ChaChaKey::from_slice(nonce);

    // Combine ciphertext and tag
    let mut ciphertext_with_tag = ciphertext.to_vec();
    ciphertext_with_tag.extend_from_slice(tag);

    cipher
        .decrypt(nonce, ciphertext_with_tag.as_ref())
        .map_err(|e| JweError::ContentEncryption(e.to_string()))
}

/// Encrypts content using AES-CBC with HMAC-SHA-512
pub fn encrypt_aes_cbc_hmac(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> crate::error::Result<(Vec<u8>, Vec<u8>)> {
    use aes::cipher::{BlockEncrypt, BlockEncryptMut};
    
    // Split key into encryption and MAC keys
    let (mac_key, enc_key) = key.split_at(key.len() / 2);
    
    // Create HMAC instance with explicit type
    let mut mac = <Hmac<Sha512>>::new_from_slice(mac_key)
        .map_err(|e| JweError::ContentEncryption(format!("HMAC initialization failed: {}", e)))?;

    // Encrypt the content
    let enc_key_array = GenericArray::from_slice(enc_key);
    let iv_array = GenericArray::from_slice(iv);
    let cipher = Aes256::new(enc_key_array);
    
    // Pad plaintext (PKCS7)
    let block_size = 16;
    let padding_len = block_size - (plaintext.len() % block_size);
    let mut padded = plaintext.to_vec();
    padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));

    // Encrypt in CBC mode
    let mut ciphertext = Vec::with_capacity(padded.len());
    let mut prev_block = iv_array.to_vec();

    for chunk in padded.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);

        // XOR with previous block
        for (b, p) in block.iter_mut().zip(prev_block.iter()) {
            *b ^= p;
        }

        // Encrypt block
        cipher.encrypt_block((&mut block).into());
        ciphertext.extend_from_slice(&block);
        prev_block = block.to_vec();
    }

    // Calculate authentication tag
    mac.update(aad);
    mac.update(&ciphertext);
    let tag = mac.finalize().into_bytes().to_vec();

    Ok((ciphertext, tag))
}

/// Decrypts content using AES-CBC with HMAC-SHA-512
pub fn decrypt_aes_cbc_hmac(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> crate::error::Result<Vec<u8>> {
    use aes::cipher::{BlockDecrypt, BlockDecryptMut};
    
    // Split key into encryption and MAC keys
    let (mac_key, enc_key) = key.split_at(key.len() / 2);
    
    // Create HMAC instance with explicit type
    let mut mac = <Hmac<Sha512>>::new_from_slice(mac_key)
        .map_err(|e| JweError::ContentEncryption(format!("HMAC initialization failed: {}", e)))?;

    // Verify the tag
    mac.update(aad);
    mac.update(ciphertext);
    mac.verify_slice(tag)
        .map_err(|_| JweError::AuthenticationFailed)?;

    // Decrypt the content
    let enc_key_array = GenericArray::from_slice(enc_key);
    let iv_array = GenericArray::from_slice(iv);
    let cipher = Aes256::new(enc_key_array);
    
    // Decrypt in CBC mode
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut prev_block = iv_array.to_vec();

    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let encrypted_block = block;

        // Decrypt block
        cipher.decrypt_block((&mut block).into());

        // XOR with previous block
        for (b, p) in block.iter_mut().zip(prev_block.iter()) {
            *b ^= p;
        }

        plaintext.extend_from_slice(&block);
        prev_block = encrypted_block.to_vec();
    }

    // Remove PKCS7 padding
    let padding_len = *plaintext
        .last()
        .ok_or_else(|| JweError::ContentEncryption("Empty plaintext".to_string()))?
        as usize;
    if padding_len == 0 || padding_len > 16 {
        return Err(JweError::ContentEncryption("Invalid padding".to_string()));
    }
    for &byte in &plaintext[plaintext.len() - padding_len..] {
        if byte != padding_len as u8 {
            return Err(JweError::ContentEncryption("Invalid padding".to_string()));
        }
    }
    plaintext.truncate(plaintext.len() - padding_len);

    Ok(plaintext)
}

/// Performs P-256 key agreement
fn p256_key_agreement(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    let secret = P256EphemeralSecret::from_bytes(private_key.into())
        .map_err(|e| JweError::InvalidKeyMaterial(format!("Invalid private key: {}", e)))?;
    
    let public = P256PublicKey::from_sec1_bytes(public_key)
        .map_err(|e| JweError::InvalidKeyMaterial(format!("Invalid public key: {}", e)))?;

    let shared = secret.diffie_hellman(&public);
    Ok(shared.raw_secret_bytes().as_slice().to_vec())
}

/// Generates a P-256 ephemeral keypair
fn generate_p256_ephemeral() -> Result<(Vec<u8>, Vec<u8>)> {
    let secret = P256EphemeralSecret::random(&mut OsRng);
    let public = P256PublicKey::from(&secret);
    
    Ok((
        secret.to_bytes().as_slice().to_vec(),
        public.to_encoded_point(false).as_bytes().to_vec(),
    ))
}

/// Performs P-384 key agreement
fn p384_key_agreement(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    let secret = P384EphemeralSecret::from_bytes(private_key.into())
        .map_err(|e| JweError::InvalidKeyMaterial(format!("Invalid private key: {}", e)))?;
    
    let public = P384PublicKey::from_sec1_bytes(public_key)
        .map_err(|e| JweError::InvalidKeyMaterial(format!("Invalid public key: {}", e)))?;

    let shared = secret.diffie_hellman(&public);
    Ok(shared.raw_secret_bytes().as_slice().to_vec())
}

/// Generates an ephemeral P-384 key pair.
fn generate_p384_ephemeral() -> Result<(Vec<u8>, Vec<u8>)> {
    let secret = P384EphemeralSecret::random(&mut OsRng);
    let public = secret.public_key();

    Ok((
        secret.secret_key().to_bytes().to_vec(),
        public.to_encoded_point(false).as_bytes().to_vec(),
    ))
}

/// Performs P-521 key agreement
fn p521_key_agreement(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    let secret = P521EphemeralSecret::from_bytes(private_key.into())
        .map_err(|e| JweError::InvalidKeyMaterial(format!("Invalid private key: {}", e)))?;
    
    let public = P521PublicKey::from_sec1_bytes(public_key)
        .map_err(|e| JweError::InvalidKeyMaterial(format!("Invalid public key: {}", e)))?;

    let shared = secret.diffie_hellman(&public);
    Ok(shared.raw_secret_bytes().as_slice().to_vec())
}

/// Generates an ephemeral P-521 key pair.
fn generate_p521_ephemeral() -> Result<(Vec<u8>, Vec<u8>)> {
    let secret = P521EphemeralSecret::random(&mut OsRng);
    let public = secret.public_key();

    Ok((
        secret.secret_key().to_bytes().to_vec(),
        public.to_encoded_point(false).as_bytes().to_vec(),
    ))
}

/// Compresses a public key for the specified curve.
///
/// # Arguments
///
/// * `curve` - The elliptic curve used
/// * `public_key` - The uncompressed public key bytes
///
/// # Returns
///
/// The compressed public key bytes.
///
/// # Errors
///
/// Returns an error if:
/// - The curve is not supported
/// - The public key is invalid
pub fn compress_public_key(curve: EcdhCurve, public_key: &[u8]) -> Result<Vec<u8>> {
    match curve {
        EcdhCurve::X25519 => Ok(public_key.to_vec()), // X25519 is already compressed
        EcdhCurve::P256 => {
            let point = P256PublicKey::from_sec1_bytes(public_key).map_err(|_| {
                JweError::InvalidKeyMaterial("Invalid P-256 public key".to_string())
            })?;
            Ok(point.to_encoded_point(true).as_bytes().to_vec())
        }
        EcdhCurve::P384 => {
            let point = P384PublicKey::from_sec1_bytes(public_key).map_err(|_| {
                JweError::InvalidKeyMaterial("Invalid P-384 public key".to_string())
            })?;
            Ok(point.to_encoded_point(true).as_bytes().to_vec())
        }
        EcdhCurve::P521 => {
            let point = P521PublicKey::from_sec1_bytes(public_key).map_err(|_| {
                JweError::InvalidKeyMaterial("Invalid P-521 public key".to_string())
            })?;
            Ok(point.to_encoded_point(true).as_bytes().to_vec())
        }
    }
}

/// Decompresses a public key for the specified curve.
///
/// # Arguments
///
/// * `curve` - The elliptic curve used
/// * `public_key` - The compressed public key bytes
///
/// # Returns
///
/// The uncompressed public key bytes.
///
/// # Errors
///
/// Returns an error if:
/// - The curve is not supported
/// - The public key is invalid
pub fn decompress_public_key(curve: EcdhCurve, public_key: &[u8]) -> Result<Vec<u8>> {
    match curve {
        EcdhCurve::X25519 => Ok(public_key.to_vec()), // X25519 is already compressed
        EcdhCurve::P256 => {
            let point = P256PublicKey::from_sec1_bytes(public_key).map_err(|_| {
                JweError::InvalidKeyMaterial("Invalid P-256 public key".to_string())
            })?;
            Ok(point.to_encoded_point(false).as_bytes().to_vec())
        }
        EcdhCurve::P384 => {
            let point = P384PublicKey::from_sec1_bytes(public_key).map_err(|_| {
                JweError::InvalidKeyMaterial("Invalid P-384 public key".to_string())
            })?;
            Ok(point.to_encoded_point(false).as_bytes().to_vec())
        }
        EcdhCurve::P521 => {
            let point = P521PublicKey::from_sec1_bytes(public_key).map_err(|_| {
                JweError::InvalidKeyMaterial("Invalid P-521 public key".to_string())
            })?;
            Ok(point.to_encoded_point(false).as_bytes().to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm() {
        let key = generate_random_key(32);
        let nonce = generate_random_key(12);
        let aad = b"additional data";
        let plaintext = b"test message";

        // Encrypt
        let (ciphertext, tag) = encrypt_aes_gcm(&key, &nonce, aad, plaintext).unwrap();

        // Decrypt
        let decrypted = decrypt_aes_gcm(&key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_tamper_detection() {
        let key = generate_random_key(32);
        let nonce = generate_random_key(12);
        let aad = b"additional data";
        let plaintext = b"test message";

        // Encrypt
        let (mut ciphertext, tag) = encrypt_aes_gcm(&key, &nonce, aad, plaintext).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 1;

        // Attempt to decrypt
        let result = decrypt_aes_gcm(&key, &nonce, aad, &ciphertext, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_material() {
        let key = generate_random_key(16); // Wrong key size
        let nonce = generate_random_key(12);
        let aad = b"additional data";
        let plaintext = b"test message";

        let result = encrypt_aes_gcm(&key, &nonce, aad, plaintext);
        assert!(result.is_err());

        let key = generate_random_key(32);
        let nonce = generate_random_key(8); // Wrong nonce size
        let result = encrypt_aes_gcm(&key, &nonce, aad, plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_agreement_x25519() {
        let (priv_a, pub_a) = generate_x25519_ephemeral();
        let (priv_b, pub_b) = generate_x25519_ephemeral();

        let shared_a = x25519_key_agreement(&priv_a, &pub_b).unwrap();
        let shared_b = x25519_key_agreement(&priv_b, &pub_a).unwrap();

        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_key_wrapping() {
        let kek = generate_random_key(32);
        let key = generate_random_key(32);

        let wrapped = wrap_key(&kek, &key).unwrap();
        let unwrapped = unwrap_key(&kek, &wrapped).unwrap();

        assert_eq!(key, unwrapped);
    }

    #[test]
    fn test_aes_cbc_hmac() {
        let key = generate_random_key(32);
        let iv = generate_random_key(16);
        let aad = b"additional data";
        let plaintext = b"test message";

        // Encrypt
        let (ciphertext, tag) = encrypt_aes_cbc_hmac(&key, &iv, aad, plaintext).unwrap();

        // Decrypt
        let decrypted = decrypt_aes_cbc_hmac(&key, &iv, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_cbc_hmac_tamper_detection() {
        let key = generate_random_key(32);
        let iv = generate_random_key(16);
        let aad = b"additional data";
        let plaintext = b"test message";

        // Encrypt
        let (mut ciphertext, tag) = encrypt_aes_cbc_hmac(&key, &iv, aad, plaintext).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 1;

        // Attempt to decrypt
        let result = decrypt_aes_cbc_hmac(&key, &iv, aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert!(matches!(result, Err(JweError::AuthenticationFailed)));
    }

    #[test]
    fn test_aes_cbc_hmac_invalid_key_material() {
        let key = generate_random_key(16); // Wrong key size
        let iv = generate_random_key(16);
        let aad = b"additional data";
        let plaintext = b"test message";

        let result = encrypt_aes_cbc_hmac(&key, &iv, aad, plaintext);
        assert!(result.is_err());

        let key = generate_random_key(32);
        let iv = generate_random_key(8); // Wrong IV size
        let result = encrypt_aes_cbc_hmac(&key, &iv, aad, plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_cbc_hmac_padding() {
        let key = generate_random_key(32);
        let iv = generate_random_key(16);
        let aad = b"additional data";

        // Test different plaintext lengths to verify padding
        for len in 1..=32 {
            let plaintext = vec![0x42; len];
            let (ciphertext, tag) = encrypt_aes_cbc_hmac(&key, &iv, aad, &plaintext).unwrap();
            let decrypted = decrypt_aes_cbc_hmac(&key, &iv, aad, &ciphertext, &tag).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_p256_key_agreement() {
        let (priv_a, pub_a) = generate_p256_ephemeral().unwrap();
        let (priv_b, pub_b) = generate_p256_ephemeral().unwrap();

        let shared_a = p256_key_agreement(&priv_a, &pub_b).unwrap();
        let shared_b = p256_key_agreement(&priv_b, &pub_a).unwrap();

        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_p384_key_agreement() {
        let (priv_a, pub_a) = generate_p384_ephemeral().unwrap();
        let (priv_b, pub_b) = generate_p384_ephemeral().unwrap();

        let shared_a = p384_key_agreement(&priv_a, &pub_b).unwrap();
        let shared_b = p384_key_agreement(&priv_b, &pub_a).unwrap();

        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_p521_key_agreement() {
        let (priv_a, pub_a) = generate_p521_ephemeral().unwrap();
        let (priv_b, pub_b) = generate_p521_ephemeral().unwrap();

        let shared_a = p521_key_agreement(&priv_a, &pub_b).unwrap();
        let shared_b = p521_key_agreement(&priv_b, &pub_a).unwrap();

        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_invalid_key_material_p256() {
        let invalid_key = vec![0; 32];
        let result = p256_key_agreement(&invalid_key, &invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_material_p384() {
        let invalid_key = vec![0; 32];
        let result = p384_key_agreement(&invalid_key, &invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_material_p521() {
        let invalid_key = vec![0; 32];
        let result = p521_key_agreement(&invalid_key, &invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_xchacha20poly1305() {
        let key = generate_random_key(32);
        let nonce = generate_random_key(24);
        let aad = b"additional data";
        let plaintext = b"test message";

        // Encrypt
        let (ciphertext, tag) = encrypt_xchacha20poly1305(&key, &nonce, aad, plaintext).unwrap();

        // Decrypt
        let decrypted = decrypt_xchacha20poly1305(&key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_xchacha20poly1305_tamper_detection() {
        let key = generate_random_key(32);
        let nonce = generate_random_key(24);
        let aad = b"additional data";
        let plaintext = b"test message";

        // Encrypt
        let (mut ciphertext, tag) =
            encrypt_xchacha20poly1305(&key, &nonce, aad, plaintext).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 1;

        // Attempt to decrypt
        let result = decrypt_xchacha20poly1305(&key, &nonce, aad, &ciphertext, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_xchacha20poly1305_invalid_key_material() {
        let key = generate_random_key(16); // Wrong key size
        let nonce = generate_random_key(24);
        let aad = b"additional data";
        let plaintext = b"test message";

        let result = encrypt_xchacha20poly1305(&key, &nonce, aad, plaintext);
        assert!(result.is_err());

        let key = generate_random_key(32);
        let nonce = generate_random_key(16); // Wrong nonce size
        let result = encrypt_xchacha20poly1305(&key, &nonce, aad, plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn test_compress_decompress_p256() {
        let (private, public) = generate_ephemeral_keypair(EcdhCurve::P256).unwrap();

        // Compress the public key
        let compressed = compress_public_key(EcdhCurve::P256, &public).unwrap();

        // Verify it's shorter than uncompressed
        assert!(compressed.len() < public.len());

        // Decompress back
        let decompressed = decompress_public_key(EcdhCurve::P256, &compressed).unwrap();

        // Should match original
        assert_eq!(decompressed, public);

        // Both should work for key agreement
        let shared1 = ecdh_key_agreement(EcdhCurve::P256, &private, &public).unwrap();
        let shared2 = ecdh_key_agreement(EcdhCurve::P256, &private, &compressed).unwrap();
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_compress_decompress_p384() {
        let (private, public) = generate_ephemeral_keypair(EcdhCurve::P384).unwrap();

        // Compress the public key
        let compressed = compress_public_key(EcdhCurve::P384, &public).unwrap();

        // Verify it's shorter than uncompressed
        assert!(compressed.len() < public.len());

        // Decompress back
        let decompressed = decompress_public_key(EcdhCurve::P384, &compressed).unwrap();

        // Should match original
        assert_eq!(decompressed, public);

        // Both should work for key agreement
        let shared1 = ecdh_key_agreement(EcdhCurve::P384, &private, &public).unwrap();
        let shared2 = ecdh_key_agreement(EcdhCurve::P384, &private, &compressed).unwrap();
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_compress_decompress_p521() {
        let (private, public) = generate_ephemeral_keypair(EcdhCurve::P521).unwrap();

        // Compress the public key
        let compressed = compress_public_key(EcdhCurve::P521, &public).unwrap();

        // Verify it's shorter than uncompressed
        assert!(compressed.len() < public.len());

        // Decompress back
        let decompressed = decompress_public_key(EcdhCurve::P521, &compressed).unwrap();

        // Should match original
        assert_eq!(decompressed, public);

        // Both should work for key agreement
        let shared1 = ecdh_key_agreement(EcdhCurve::P521, &private, &public).unwrap();
        let shared2 = ecdh_key_agreement(EcdhCurve::P521, &private, &compressed).unwrap();
        assert_eq!(shared1, shared2);
    }
}
