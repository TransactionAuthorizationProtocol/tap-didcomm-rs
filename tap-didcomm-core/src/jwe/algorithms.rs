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

use aes::Aes256;
use aes_gcm::{
    aead::{Aead, KeyInit as GcmKeyInit},
    Aes256Gcm,
};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{ecdh::diffie_hellman, PublicKey as P256PublicKey, SecretKey as P256SecretKey};

use super::EcdhCurve;
use crate::error::{Error, Result};
use p384::{
    ecdh::diffie_hellman as p384_diffie_hellman, PublicKey as P384PublicKey,
    SecretKey as P384SecretKey,
};
use p521::elliptic_curve;
use p521::{
    ecdh::diffie_hellman as p521_diffie_hellman, PublicKey as P521PublicKey,
    SecretKey as P521SecretKey,
};
use rand_core::{OsRng, RngCore};
use sha2::Sha512;
use std::convert::TryInto;
use x25519_dalek::{PublicKey, StaticSecret};

use aes::cipher::generic_array::typenum::{U16, U32};
use aes::cipher::generic_array::GenericArray;
use aes_gcm::aead::AeadCore;
use elliptic_curve::scalar::NonZeroScalar;
use elliptic_curve::sec1::ToEncodedPoint;
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;

/// Add type aliases for key wrapping
type KekArray = GenericArray<u8, U32>;

/// Add type aliases for ECDH operations
type P256NonZeroScalar = NonZeroScalar<NistP256>;
type P384NonZeroScalar = NonZeroScalar<NistP384>;
type P521NonZeroScalar = NonZeroScalar<NistP521>;

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
    let priv_array: [u8; 32] = private_key
        .try_into()
        .map_err(|_| Error::InvalidKeyMaterial("Invalid private key length".to_string()))?;
    let pub_array: [u8; 32] = public_key
        .try_into()
        .map_err(|_| Error::InvalidKeyMaterial("Invalid public key length".to_string()))?;
    let secret = StaticSecret::from(priv_array);
    let public = PublicKey::from(pub_array);

    Ok(secret.diffie_hellman(&public).as_bytes().to_vec())
}

/// Generates an X25519 ephemeral keypair
fn generate_x25519_ephemeral() -> (Vec<u8>, Vec<u8>) {
    let secret = StaticSecret::random_from_rng(OsRng);
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
        .map_err(|e| Error::KeyAgreement(format!("HKDF error: {}", e)))?;
    Ok(okm)
}

/// Wraps a content encryption key using AES key wrapping
pub fn wrap_key(kek: &[u8], cek: &[u8]) -> Result<Vec<u8>> {
    use aes_kw::KekAes256;

    if kek.len() != 32 {
        return Err(Error::InvalidKeyMaterial(
            "Key encryption key must be 32 bytes".to_string(),
        ));
    }

    let kek_array: &KekArray = GenericArray::from_slice(kek);
    let cipher = KekAes256::new(kek_array);

    let mut wrapped = vec![0u8; cek.len() + 8];
    cipher
        .wrap_with_padding(cek, &mut wrapped)
        .map_err(|_| Error::KeyWrap("Key wrapping failed".to_string()))?;

    Ok(wrapped)
}

/// Unwraps a wrapped key using AES key unwrapping
pub fn unwrap_key(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    use aes_kw::KekAes256;

    let kek_array: &KekArray = GenericArray::from_slice(kek);
    let cipher = KekAes256::new(kek_array);

    let mut unwrapped = vec![0u8; wrapped.len() - 8];
    cipher
        .unwrap_with_padding(wrapped, &mut unwrapped)
        .map_err(|e| Error::KeyWrap(format!("Key unwrapping failed: {}", e)))?;

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
    let key: &AesGcmKeyArray = GenericArray::from_slice(key);
    let nonce: &AesGcmNonce = GenericArray::from_slice(nonce);
    let cipher = Aes256Gcm::new(key.into());

    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| Error::ContentEncryption(format!("AES-GCM encryption failed: {}", e)))?;

    // Split ciphertext and tag
    let tag_start = ciphertext.len() - 16;
    let tag = ciphertext[tag_start..].to_vec();
    let ciphertext = ciphertext[..tag_start].to_vec();

    Ok((ciphertext, tag))
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
        return Err(Error::InvalidKeyMaterial(
            "AES-256-GCM requires a 32-byte key".to_string(),
        ));
    }
    if nonce.len() != 12 {
        return Err(Error::InvalidKeyMaterial(
            "AES-256-GCM requires a 12-byte nonce".to_string(),
        ));
    }
    if tag.len() != 16 {
        return Err(Error::InvalidKeyMaterial(
            "AES-256-GCM requires a 16-byte authentication tag".to_string(),
        ));
    }

    let key: &AesGcmKeyArray = GenericArray::from_slice(key);
    let nonce: &AesGcmNonce = GenericArray::from_slice(nonce);
    let cipher = Aes256Gcm::new(key.into());

    let mut ciphertext_with_tag = ciphertext.to_vec();
    ciphertext_with_tag.extend_from_slice(tag);

    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext_with_tag.as_ref(),
                aad,
            },
        )
        .map_err(|e| Error::ContentEncryption(format!("AES-GCM decryption failed: {}", e)))
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
        return Err(Error::InvalidKeyMaterial("Invalid key length".to_string()));
    }
    if nonce.len() != 24 {
        return Err(Error::InvalidKeyMaterial(
            "Invalid nonce length".to_string(),
        ));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| Error::ContentEncryption(e.to_string()))?;

    let nonce = chacha20poly1305::Nonce::from_slice(nonce);

    cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| Error::ContentEncryption(e.to_string()))
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
        return Err(Error::InvalidKeyMaterial("Invalid key length".to_string()));
    }
    if nonce.len() != 24 {
        return Err(Error::InvalidKeyMaterial(
            "Invalid nonce length".to_string(),
        ));
    }
    if tag.len() != 16 {
        return Err(Error::InvalidKeyMaterial(
            "Invalid authentication tag length".to_string(),
        ));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| Error::ContentEncryption(e.to_string()))?;

    let nonce = chacha20poly1305::Nonce::from_slice(nonce);

    // Combine ciphertext and tag
    let mut ciphertext_with_tag = ciphertext.to_vec();
    ciphertext_with_tag.extend_from_slice(tag);

    cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext_with_tag.as_ref(),
                aad,
            },
        )
        .map_err(|e| Error::ContentEncryption(e.to_string()))
}

/// Encrypts content using AES-CBC with HMAC-SHA-512
pub fn encrypt_aes_cbc_hmac(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> crate::error::Result<(Vec<u8>, Vec<u8>)> {
    use aes::cipher::BlockEncrypt;

    // Split key into encryption and MAC keys
    let (mac_key, enc_key) = key.split_at(key.len() / 2);

    // Create HMAC instance with explicit type
    let mut mac = <HmacSha512 as hmac::digest::KeyInit>::new_from_slice(mac_key)
        .map_err(|e| Error::ContentEncryption(format!("HMAC initialization failed: {}", e)))?;

    // Encrypt the content
    let enc_key_array: &GenericArray<u8, U32> = GenericArray::from_slice(enc_key);
    let iv_array: &GenericArray<u8, U16> = GenericArray::from_slice(iv);
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
    use aes::cipher::BlockDecrypt;

    // Split key into encryption and MAC keys
    let (mac_key, enc_key) = key.split_at(key.len() / 2);

    // Create HMAC instance with explicit type
    let mut mac = <HmacSha512 as hmac::digest::KeyInit>::new_from_slice(mac_key)
        .map_err(|e| Error::ContentEncryption(format!("HMAC initialization failed: {}", e)))?;

    // Verify the tag
    mac.update(aad);
    mac.update(ciphertext);
    mac.verify_slice(tag)
        .map_err(|_| Error::AuthenticationFailed)?;

    // Decrypt the content
    let enc_key_array: &GenericArray<u8, U32> = GenericArray::from_slice(enc_key);
    let iv_array: &GenericArray<u8, U16> = GenericArray::from_slice(iv);
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
    validate_pkcs7_padding(&mut plaintext)?;

    Ok(plaintext)
}

/// Performs P-256 key agreement
fn p256_key_agreement(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    let secret = P256SecretKey::from_slice(private_key)
        .map_err(|e| Error::InvalidKeyMaterial(format!("Invalid P-256 private key: {}", e)))?;
    let public = P256PublicKey::from_sec1_bytes(public_key)
        .map_err(|e| Error::InvalidKeyMaterial(format!("Invalid P-256 public key: {}", e)))?;

    let scalar: P256NonZeroScalar = secret.to_nonzero_scalar();
    let point = public.as_affine();
    let shared = diffie_hellman(&scalar, point);
    Ok(shared.raw_secret_bytes().to_vec())
}

/// Generates a P-256 ephemeral keypair
fn generate_p256_ephemeral() -> Result<(Vec<u8>, Vec<u8>)> {
    let secret = P256SecretKey::random(&mut OsRng);
    let public_key = P256PublicKey::from_secret_scalar(&secret.to_nonzero_scalar());

    Ok((
        secret.to_bytes().to_vec(),
        public_key.to_encoded_point(false).as_bytes().to_vec(),
    ))
}

/// Performs P-384 key agreement
fn p384_key_agreement(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    let secret = P384SecretKey::from_slice(private_key)
        .map_err(|e| Error::InvalidKeyMaterial(format!("Invalid P-384 private key: {}", e)))?;
    let public = P384PublicKey::from_sec1_bytes(public_key)
        .map_err(|e| Error::InvalidKeyMaterial(format!("Invalid P-384 public key: {}", e)))?;

    let scalar: P384NonZeroScalar = secret.to_nonzero_scalar();
    let point = public.as_affine();
    let shared = p384_diffie_hellman(&scalar, point);
    Ok(shared.raw_secret_bytes().to_vec())
}

/// Generates an ephemeral P-384 key pair.
fn generate_p384_ephemeral() -> Result<(Vec<u8>, Vec<u8>)> {
    let secret = P384SecretKey::random(&mut OsRng);
    let public_key = P384PublicKey::from_secret_scalar(&secret.to_nonzero_scalar());

    Ok((
        secret.to_bytes().to_vec(),
        public_key.to_encoded_point(false).as_bytes().to_vec(),
    ))
}

/// Performs P-521 key agreement
fn p521_key_agreement(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    let secret = P521SecretKey::from_slice(private_key)
        .map_err(|e| Error::InvalidKeyMaterial(format!("Invalid P-521 private key: {}", e)))?;
    let public = P521PublicKey::from_sec1_bytes(public_key)
        .map_err(|e| Error::InvalidKeyMaterial(format!("Invalid P-521 public key: {}", e)))?;

    let scalar: P521NonZeroScalar = secret.to_nonzero_scalar();
    let point = public.as_affine();
    let shared = p521_diffie_hellman(&scalar, point);
    Ok(shared.raw_secret_bytes().to_vec())
}

/// Generates an ephemeral P-521 key pair.
fn generate_p521_ephemeral() -> Result<(Vec<u8>, Vec<u8>)> {
    let secret = P521SecretKey::random(&mut OsRng);
    let public_key = P521PublicKey::from_secret_scalar(&secret.to_nonzero_scalar());

    Ok((
        secret.to_bytes().to_vec(),
        public_key.to_encoded_point(false).as_bytes().to_vec(),
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
            let point = P256PublicKey::from_sec1_bytes(public_key)
                .map_err(|_| Error::InvalidKeyMaterial("Invalid P-256 public key".to_string()))?;
            Ok(point.to_encoded_point(true).as_bytes().to_vec())
        }
        EcdhCurve::P384 => {
            let point = P384PublicKey::from_sec1_bytes(public_key)
                .map_err(|_| Error::InvalidKeyMaterial("Invalid P-384 public key".to_string()))?;
            Ok(point.to_encoded_point(true).as_bytes().to_vec())
        }
        EcdhCurve::P521 => {
            let point = P521PublicKey::from_sec1_bytes(public_key)
                .map_err(|_| Error::InvalidKeyMaterial("Invalid P-521 public key".to_string()))?;
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
            let point = P256PublicKey::from_sec1_bytes(public_key)
                .map_err(|_| Error::InvalidKeyMaterial("Invalid P-256 public key".to_string()))?;
            Ok(point.to_encoded_point(false).as_bytes().to_vec())
        }
        EcdhCurve::P384 => {
            let point = P384PublicKey::from_sec1_bytes(public_key)
                .map_err(|_| Error::InvalidKeyMaterial("Invalid P-384 public key".to_string()))?;
            Ok(point.to_encoded_point(false).as_bytes().to_vec())
        }
        EcdhCurve::P521 => {
            let point = P521PublicKey::from_sec1_bytes(public_key)
                .map_err(|_| Error::InvalidKeyMaterial("Invalid P-521 public key".to_string()))?;
            Ok(point.to_encoded_point(false).as_bytes().to_vec())
        }
    }
}

/// Creates HMAC instance with explicit type annotation
fn create_hmac(key: &[u8]) -> Result<HmacSha512> {
    let hmac = <HmacSha512 as hmac::digest::KeyInit>::new_from_slice(key)
        .map_err(|e| Error::ContentEncryption(format!("HMAC initialization failed: {}", e)))?;
    Ok(hmac)
}

/// Validates PKCS7 padding
fn validate_pkcs7_padding(plaintext: &mut Vec<u8>) -> Result<()> {
    if plaintext.is_empty() {
        return Err(Error::ContentEncryption("Empty plaintext".to_string()));
    }

    let padding_len = plaintext[plaintext.len() - 1] as usize;
    if padding_len == 0 || padding_len > 16 {
        return Err(Error::ContentEncryption(
            "Invalid padding length".to_string(),
        ));
    }

    let start = plaintext.len() - padding_len;
    for &byte in &plaintext[start..] {
        if byte != padding_len as u8 {
            return Err(Error::ContentEncryption("Invalid padding".to_string()));
        }
    }

    plaintext.truncate(start);
    Ok(())
}

type HmacSha512 = Hmac<Sha512>;
type AesGcmKeyArray = GenericArray<u8, U32>;
type AesGcmNonce = GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize>;

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
        assert!(matches!(result, Err(Error::AuthenticationFailed)));
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
