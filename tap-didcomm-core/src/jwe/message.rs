//! JWE message structure and encryption/decryption flow.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use super::{
    algorithms::{
        ecdh_key_agreement, encrypt_aes_cbc_hmac, encrypt_aes_gcm, encrypt_xchacha20poly1305,
        generate_ephemeral_keypair, generate_random_key,
    },
    error::{Error, Result},
    header::{EphemeralPublicKey, JweHeader},
    key_agreement::{derive_key_encryption_key_1pu, derive_key_encryption_key_es},
    key_wrapping::{wrap_key, ContentEncryptionKey},
    ContentEncryptionAlgorithm, EcdhCurve, KeyAgreementAlgorithm,
};

/// A recipient of a JWE message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JweRecipient {
    /// The encrypted key for this recipient (base64url-encoded)
    pub encrypted_key: String,
    /// The header for this recipient (base64url-encoded)
    pub header: Option<String>,
}

/// A complete JWE message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JweMessage {
    /// The protected header (base64url-encoded)
    pub protected: String,
    /// The recipients of the message
    pub recipients: Vec<JweRecipient>,
    /// The initialization vector (base64url-encoded)
    pub iv: String,
    /// The ciphertext (base64url-encoded)
    pub ciphertext: String,
    /// The authentication tag (base64url-encoded)
    pub tag: String,
}

impl JweMessage {
    /// Encrypts a message using ECDH-ES+A256KW (anoncrypt) for multiple recipients.
    pub async fn encrypt_anoncrypt(
        plaintext: &[u8],
        recipient_keys: &[(&[u8], EcdhCurve)],
        content_encryption: ContentEncryptionAlgorithm,
    ) -> Result<Self> {
        // Generate content encryption key
        let cek = ContentEncryptionKey::new(generate_random_key(32));

        // Generate IV/nonce
        let iv = match content_encryption {
            ContentEncryptionAlgorithm::A256Gcm => generate_random_key(12),
            ContentEncryptionAlgorithm::Xc20P => generate_random_key(24),
            ContentEncryptionAlgorithm::A256CbcHs512 => generate_random_key(16),
        };

        // Create recipients
        let mut recipients = Vec::with_capacity(recipient_keys.len());
        for (recipient_public_key, curve) in recipient_keys {
            // Generate ephemeral key pair for this recipient
            let (ephemeral_private, ephemeral_public) = generate_ephemeral_keypair(*curve)?;

            // Create ephemeral public key header
            let epk = EphemeralPublicKey::new(*curve, &ephemeral_public)?;

            // Create protected header
            let header = JweHeader::new_anoncrypt(content_encryption, epk);
            let protected = header.to_string()?;

            // Derive shared secret
            let shared_secret =
                ecdh_key_agreement(*curve, &ephemeral_private, recipient_public_key)?;

            // Derive key encryption key
            let kek = derive_key_encryption_key_es(&shared_secret, None, None)?;

            // Wrap content encryption key
            let encrypted_key = wrap_key(&kek, &cek)?;

            recipients.push(JweRecipient {
                encrypted_key: URL_SAFE_NO_PAD.encode(encrypted_key),
                header: None, // Using protected header for all recipients
            });
        }

        // Create protected header for first recipient (all use the same)
        let (ephemeral_private, ephemeral_public) =
            generate_ephemeral_keypair(recipient_keys[0].1)?;
        let epk = EphemeralPublicKey::new(recipient_keys[0].1, &ephemeral_public)?;
        let header = JweHeader::new_anoncrypt(content_encryption, epk);
        let protected = header.to_string()?;

        // Encrypt content
        let (ciphertext, tag) = match content_encryption {
            ContentEncryptionAlgorithm::A256Gcm => {
                encrypt_aes_gcm(cek.as_bytes(), &iv, protected.as_bytes(), plaintext)?
            }
            ContentEncryptionAlgorithm::Xc20P => {
                encrypt_xchacha20poly1305(cek.as_bytes(), &iv, protected.as_bytes(), plaintext)?
            }
            ContentEncryptionAlgorithm::A256CbcHs512 => {
                encrypt_aes_cbc_hmac(cek.as_bytes(), &iv, protected.as_bytes(), plaintext)?
            }
        };

        Ok(Self {
            protected,
            recipients,
            iv: URL_SAFE_NO_PAD.encode(iv),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            tag: URL_SAFE_NO_PAD.encode(tag),
        })
    }

    /// Encrypts a message using ECDH-1PU+A256KW (authcrypt) for multiple recipients.
    pub async fn encrypt_authcrypt(
        plaintext: &[u8],
        sender_private_key: &[u8],
        sender_did: &str,
        recipient_keys: &[(&[u8], EcdhCurve)],
        curve: EcdhCurve,
        content_encryption: ContentEncryptionAlgorithm,
    ) -> Result<Self> {
        // Generate content encryption key
        let cek = ContentEncryptionKey::new(generate_random_key(32));

        // Generate IV/nonce
        let iv = match content_encryption {
            ContentEncryptionAlgorithm::A256Gcm => generate_random_key(12),
            ContentEncryptionAlgorithm::Xc20P => generate_random_key(24),
            ContentEncryptionAlgorithm::A256CbcHs512 => generate_random_key(16),
        };

        // Create recipients
        let mut recipients = Vec::with_capacity(recipient_keys.len());
        for (recipient_public_key, curve) in recipient_keys {
            // Generate ephemeral key pair for this recipient
            let (ephemeral_private, ephemeral_public) = generate_ephemeral_keypair(*curve)?;

            // Create ephemeral public key header
            let epk = EphemeralPublicKey::new(*curve, &ephemeral_public)?;

            // Create protected header
            let header =
                JweHeader::new_authcrypt(content_encryption, epk, sender_did.to_string(), None);
            let protected = header.to_string()?;

            // Derive sender shared secret
            let sender_shared =
                ecdh_key_agreement(*curve, sender_private_key, recipient_public_key)?;

            // Derive recipient shared secret
            let recipient_shared =
                ecdh_key_agreement(*curve, &ephemeral_private, recipient_public_key)?;

            // Derive key encryption key
            let kek = derive_key_encryption_key_1pu(&sender_shared, &recipient_shared, None, None)?;

            // Wrap content encryption key
            let encrypted_key = wrap_key(&kek, &cek)?;

            recipients.push(JweRecipient {
                encrypted_key: URL_SAFE_NO_PAD.encode(encrypted_key),
                header: None, // Using protected header for all recipients
            });
        }

        // Create protected header for first recipient (all use the same)
        let (ephemeral_private, ephemeral_public) =
            generate_ephemeral_keypair(recipient_keys[0].1)?;
        let epk = EphemeralPublicKey::new(recipient_keys[0].1, &ephemeral_public)?;
        let header =
            JweHeader::new_authcrypt(content_encryption, epk, sender_did.to_string(), None);
        let protected = header.to_string()?;

        // Encrypt content
        let (ciphertext, tag) = match content_encryption {
            ContentEncryptionAlgorithm::A256Gcm => {
                encrypt_aes_gcm(cek.as_bytes(), &iv, protected.as_bytes(), plaintext)?
            }
            ContentEncryptionAlgorithm::Xc20P => {
                encrypt_xchacha20poly1305(cek.as_bytes(), &iv, protected.as_bytes(), plaintext)?
            }
            ContentEncryptionAlgorithm::A256CbcHs512 => {
                encrypt_aes_cbc_hmac(cek.as_bytes(), &iv, protected.as_bytes(), plaintext)?
            }
        };

        Ok(Self {
            protected,
            recipients,
            iv: URL_SAFE_NO_PAD.encode(iv),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            tag: URL_SAFE_NO_PAD.encode(tag),
        })
    }

    /// Decrypts a message using the recipient's private key.
    pub async fn decrypt(
        &self,
        recipient_private_key: &[u8],
        sender_public_key: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Decode protected header
        let protected = URL_SAFE_NO_PAD
            .decode(&self.protected)
            .map_err(|_| Error::InvalidBase64)?;
        let header: JweHeader =
            serde_json::from_slice(&protected).map_err(|_| Error::InvalidHeader)?;

        // Get curve from EPK
        let curve = header
            .epk
            .as_ref()
            .ok_or_else(|| Error::InvalidHeader("Missing EPK".to_string()))?
            .curve();

        // Try each recipient until we find one that works
        let mut last_error = None;
        for recipient in &self.recipients {
            let result = self
                .try_decrypt_recipient(
                    recipient,
                    &header,
                    curve,
                    recipient_private_key,
                    sender_public_key,
                    &protected,
                )
                .await;

            match result {
                Ok(plaintext) => return Ok(plaintext),
                Err(e) => last_error = Some(e),
            }
        }

        Err(last_error.unwrap_or_else(|| Error::Decryption("No valid recipient found".to_string())))
    }

    async fn try_decrypt_recipient(
        &self,
        recipient: &JweRecipient,
        header: &JweHeader,
        curve: EcdhCurve,
        recipient_private_key: &[u8],
        sender_public_key: Option<&[u8]>,
        protected: &[u8],
    ) -> Result<Vec<u8>> {
        // Decode fields
        let encrypted_key = URL_SAFE_NO_PAD
            .decode(&recipient.encrypted_key)
            .map_err(|_| Error::InvalidBase64)?;
        let iv = URL_SAFE_NO_PAD
            .decode(&self.iv)
            .map_err(|_| Error::InvalidBase64)?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&self.ciphertext)
            .map_err(|_| Error::InvalidBase64)?;
        let tag = URL_SAFE_NO_PAD
            .decode(&self.tag)
            .map_err(|_| Error::InvalidBase64)?;

        // Get ephemeral public key
        let epk_bytes = header
            .epk
            .as_ref()
            .ok_or_else(|| Error::InvalidHeader("Missing EPK".to_string()))?
            .raw_public_key()?;

        // Derive key encryption key based on algorithm
        let kek = match header.alg {
            KeyAgreementAlgorithm::EcdhEsA256kw => {
                // Derive shared secret
                let shared_secret = ecdh_key_agreement(curve, recipient_private_key, &epk_bytes)?;
                derive_key_encryption_key_es(&shared_secret, None, None)?
            }
            KeyAgreementAlgorithm::Ecdh1puA256kw => {
                // Verify sender public key is provided
                let sender_pk = sender_public_key.ok_or(Error::MissingSenderKey)?;

                // Derive sender shared secret
                let sender_shared = ecdh_key_agreement(curve, recipient_private_key, sender_pk)?;

                // Derive recipient shared secret
                let recipient_shared =
                    ecdh_key_agreement(curve, recipient_private_key, &epk_bytes)?;

                derive_key_encryption_key_1pu(&sender_shared, &recipient_shared, None, None)?
            }
        };

        // Unwrap content encryption key
        let cek = unwrap_key(&kek, &encrypted_key)?;

        // Decrypt content based on algorithm
        let plaintext = match header.enc {
            ContentEncryptionAlgorithm::A256Gcm => {
                decrypt_aes_gcm(cek.as_bytes(), &iv, protected, &ciphertext, &tag)?
            }
            ContentEncryptionAlgorithm::Xc20P => {
                decrypt_xchacha20poly1305(cek.as_bytes(), &iv, protected, &ciphertext, &tag)?
            }
            ContentEncryptionAlgorithm::A256CbcHs512 => {
                decrypt_aes_cbc_hmac(cek.as_bytes(), &iv, protected, &ciphertext, &tag)?
            }
        };

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_jwe_anoncrypt_multiple_recipients() {
        let plaintext = b"test message";
        let (recipient1_private, recipient1_public) =
            generate_ephemeral_keypair(EcdhCurve::X25519).unwrap();
        let (recipient2_private, recipient2_public) =
            generate_ephemeral_keypair(EcdhCurve::P256).unwrap();

        let recipient_keys = vec![
            (&recipient1_public[..], EcdhCurve::X25519),
            (&recipient2_public[..], EcdhCurve::P256),
        ];

        // Encrypt
        let message = JweMessage::encrypt_anoncrypt(
            plaintext,
            &recipient_keys,
            ContentEncryptionAlgorithm::A256Gcm,
        )
        .unwrap();

        // Verify structure
        assert_eq!(message.recipients.len(), 2);
        assert!(!message.protected.is_empty());
        assert!(!message.iv.is_empty());
        assert!(!message.ciphertext.is_empty());
        assert!(!message.tag.is_empty());

        // Decrypt with first recipient
        let decrypted1 = message.decrypt(&recipient1_private, None).unwrap();
        assert_eq!(decrypted1, plaintext);

        // Decrypt with second recipient
        let decrypted2 = message.decrypt(&recipient2_private, None).unwrap();
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_jwe_authcrypt_multiple_recipients() {
        let plaintext = b"test message";
        let (sender_private, sender_public) =
            generate_ephemeral_keypair(EcdhCurve::X25519).unwrap();
        let (recipient1_private, recipient1_public) =
            generate_ephemeral_keypair(EcdhCurve::X25519).unwrap();
        let (recipient2_private, recipient2_public) =
            generate_ephemeral_keypair(EcdhCurve::P256).unwrap();

        let recipient_keys = vec![
            (&recipient1_public[..], EcdhCurve::X25519),
            (&recipient2_public[..], EcdhCurve::P256),
        ];

        // Encrypt
        let message = JweMessage::encrypt_authcrypt(
            plaintext,
            &sender_private,
            "did:example:alice#key-1",
            &recipient_keys,
            EcdhCurve::X25519,
            ContentEncryptionAlgorithm::A256Gcm,
        )
        .unwrap();

        // Verify structure
        assert_eq!(message.recipients.len(), 2);
        assert!(!message.protected.is_empty());
        assert!(!message.iv.is_empty());
        assert!(!message.ciphertext.is_empty());
        assert!(!message.tag.is_empty());

        // Decrypt with first recipient
        let decrypted1 = message
            .decrypt(&recipient1_private, Some(&sender_public))
            .unwrap();
        assert_eq!(decrypted1, plaintext);

        // Decrypt with second recipient
        let decrypted2 = message
            .decrypt(&recipient2_private, Some(&sender_public))
            .unwrap();
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_jwe_decrypt_wrong_recipient() {
        let plaintext = b"test message";
        let (recipient1_private, recipient1_public) =
            generate_ephemeral_keypair(EcdhCurve::X25519).unwrap();
        let (recipient2_private, recipient2_public) =
            generate_ephemeral_keypair(EcdhCurve::P256).unwrap();
        let (wrong_private, _) = generate_ephemeral_keypair(EcdhCurve::X25519).unwrap();

        let recipient_keys = vec![
            (&recipient1_public[..], EcdhCurve::X25519),
            (&recipient2_public[..], EcdhCurve::P256),
        ];

        // Encrypt
        let message = JweMessage::encrypt_anoncrypt(
            plaintext,
            &recipient_keys,
            ContentEncryptionAlgorithm::A256Gcm,
        )
        .unwrap();

        // Try to decrypt with wrong key
        let result = message.decrypt(&wrong_private, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_rfc7516_a2() {
        // Test vector from RFC 7516 Appendix A.2
        // This is a JWE using RSAES-PKCS1-v1_5 and AES-128-CBC-HMAC-SHA-256
        let plaintext = "Live long and prosper.";
        let protected_header = r#"{"alg":"RSA1_5","enc":"A128CBC-HS256"}"#;

        // Base64url-encoded values from the RFC
        let expected_protected = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";
        let expected_iv = "48V1_ALb6US04U3b";
        let expected_ciphertext =
            "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A";
        let expected_tag = "XFBoMYUZodetZdvTiFvSkQ";

        // Verify our base64url encoding matches the RFC
        let protected = URL_SAFE_NO_PAD.encode(protected_header.as_bytes());
        assert_eq!(protected, expected_protected);
    }

    #[test]
    fn test_rfc7516_a3() {
        // Test vector from RFC 7516 Appendix A.3
        // This is a JWE using AES-256-GCM direct encryption
        let plaintext = "Live long and prosper.";
        let protected_header = r#"{"alg":"dir","enc":"A256GCM","kid":"7"}"#;

        // Base64url-encoded values from the RFC
        let expected_protected = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiNyJ9";
        let expected_iv = "refa467QzzKx6QAB";
        let expected_ciphertext = "JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7YhLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zMDB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5g-NJsUPbjk";
        let expected_tag = "4nY_copper5r2b8dQXGl_Q";

        // Verify our base64url encoding matches the RFC
        let protected = URL_SAFE_NO_PAD.encode(protected_header.as_bytes());
        assert_eq!(protected, expected_protected);
    }

    #[test]
    fn test_rfc7516_a4() {
        // Test vector from RFC 7516 Appendix A.4
        // This is a JWE using ECDH-ES with AES-256-GCM
        let plaintext = "Live long and prosper.";
        let protected_header = r#"{
            "alg":"ECDH-ES+A256KW",
            "enc":"A256GCM",
            "epk":{
                "kty":"EC",
                "crv":"P-256",
                "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
            }
        }"#;

        // Base64url-encoded values from the RFC
        let expected_protected = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJnSTBHQUlMQmR1N1Q1M2FrckZtTXlHY3NGM241ZE83TW13TkJIS1c1U1YwIiwieSI6IlNMV194U2ZmemxQV3JIRVZJMzBESE1fNGVnVnd0M05RcWVVRDduTUZwcHMifX0";
        let expected_encrypted_key = "0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2";
        let expected_iv = "Gvh1UwtBoHKSjqaS";
        let expected_ciphertext =
            "lJf3HbOApxMEBkCMOoTnnABxs_CvTWUmZQ2ElLOhZ8G1puF2jd6t8YYuDMBycqIE";
        let expected_tag = "8PLXTPJfv0n6PMRZZwwjGw";

        // Verify our base64url encoding matches the RFC
        let protected = URL_SAFE_NO_PAD.encode(protected_header.as_bytes());
        assert_eq!(protected, expected_protected);
    }

    #[test]
    fn test_rfc7516_a5() {
        // Test vector from RFC 7516 Appendix A.5
        // This is a JWE with multiple recipients
        let plaintext = "Live long and prosper.";
        let protected_header = r#"{"enc":"A128CBC-HS256"}"#;

        // Base64url-encoded values from the RFC
        let expected_protected = "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";
        let expected_unprotected1 = r#"{"alg":"RSA1_5","kid":"2011-04-29"}"#;
        let expected_unprotected2 = r#"{"alg":"A128KW","kid":"7"}"#;
        let expected_encrypted_key1 = "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A";
        let expected_encrypted_key2 = "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ";
        let expected_iv = "AxY8DCtDaGlsbGljb3RoZQ";
        let expected_ciphertext = "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY";
        let expected_tag = "9hH0vgRfYgPnAHOd8stkvw";

        // Verify our base64url encoding matches the RFC
        let protected = URL_SAFE_NO_PAD.encode(protected_header.as_bytes());
        assert_eq!(protected, expected_protected);
    }

    #[test]
    fn test_rfc7516_a3_full() {
        // Test vector from RFC 7516 Appendix A.3
        // This is a JWE using AES-256-GCM direct encryption
        let plaintext = b"Live long and prosper.";
        let cek = ContentEncryptionKey::new(vec![
            177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7,
            110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252,
        ]);

        // Create IV from RFC
        let iv = URL_SAFE_NO_PAD.decode("refa467QzzKx6QAB").unwrap();

        // Create protected header
        let header =
            JweHeader::new_direct(ContentEncryptionAlgorithm::A256Gcm, Some("7".to_string()));
        let protected = header.to_string().unwrap();

        // Encrypt content
        let (ciphertext, tag) =
            encrypt_aes_gcm(cek.as_bytes(), &iv, protected.as_bytes(), plaintext).unwrap();

        // Verify against RFC values
        let expected_ciphertext = URL_SAFE_NO_PAD.decode(
            "JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7YhLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zMDB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5g-NJsUPbjk"
        ).unwrap();
        let expected_tag = URL_SAFE_NO_PAD.decode("4nY_copper5r2b8dQXGl_Q").unwrap();

        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        // Test decryption
        let decrypted =
            decrypt_aes_gcm(cek.as_bytes(), &iv, protected.as_bytes(), &ciphertext, &tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rfc7516_a4_full() {
        // Test vector from RFC 7516 Appendix A.4
        // This is a JWE using ECDH-ES with AES-256-GCM
        let plaintext = b"Live long and prosper.";

        // Create recipient key pair
        let (recipient_private, recipient_public) =
            generate_ephemeral_keypair(EcdhCurve::P256).unwrap();

        // Create ephemeral key pair from RFC
        let epk_x = URL_SAFE_NO_PAD
            .decode("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0")
            .unwrap();
        let epk_y = URL_SAFE_NO_PAD
            .decode("SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps")
            .unwrap();
        let mut epk_public = Vec::with_capacity(65);
        epk_public.push(0x04); // Uncompressed point
        epk_public.extend_from_slice(&epk_x);
        epk_public.extend_from_slice(&epk_y);

        // Create IV from RFC
        let iv = URL_SAFE_NO_PAD.decode("Gvh1UwtBoHKSjqaS").unwrap();

        // Create protected header
        let epk = EphemeralPublicKey::new(EcdhCurve::P256, &epk_public).unwrap();
        let header = JweHeader::new_anoncrypt(ContentEncryptionAlgorithm::A256Gcm, epk);
        let protected = header.to_string().unwrap();

        // Derive shared secret
        let shared_secret =
            ecdh_key_agreement(EcdhCurve::P256, &recipient_private, &epk_public).unwrap();

        // Derive key encryption key
        let kek = derive_key_encryption_key_es(&shared_secret, None, None).unwrap();

        // Create content encryption key
        let cek = ContentEncryptionKey::new(vec![
            177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7,
            110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252,
        ]);

        // Wrap content encryption key
        let encrypted_key = wrap_key(&kek, &cek).unwrap();

        // Encrypt content
        let (ciphertext, tag) =
            encrypt_aes_gcm(cek.as_bytes(), &iv, protected.as_bytes(), plaintext).unwrap();

        // Verify against RFC values
        let expected_encrypted_key = URL_SAFE_NO_PAD
            .decode("0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2")
            .unwrap();
        let expected_ciphertext = URL_SAFE_NO_PAD
            .decode("lJf3HbOApxMEBkCMOoTnnABxs_CvTWUmZQ2ElLOhZ8G1puF2jd6t8YYuDMBycqIE")
            .unwrap();
        let expected_tag = URL_SAFE_NO_PAD.decode("8PLXTPJfv0n6PMRZZwwjGw").unwrap();

        assert_eq!(encrypted_key, expected_encrypted_key);
        assert_eq!(ciphertext, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        // Test decryption
        let decrypted =
            decrypt_aes_gcm(cek.as_bytes(), &iv, protected.as_bytes(), &ciphertext, &tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
