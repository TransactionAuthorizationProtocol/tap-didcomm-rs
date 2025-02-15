//! JWE header types and functionality.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;

use super::{ContentEncryptionAlgorithm, EcdhCurve, KeyAgreementAlgorithm};
use crate::jwe::error::{JweError, Result};

/// The protected header of a JWE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JweHeader {
    /// The key agreement algorithm
    pub alg: KeyAgreementAlgorithm,

    /// The content encryption algorithm
    pub enc: ContentEncryptionAlgorithm,

    /// The ephemeral public key (for ECDH-ES)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epk: Option<EphemeralPublicKey>,

    /// The sender key ID (for authcrypt)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skid: Option<String>,

    /// The agreement PartyUInfo (APU, for authcrypt)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apu: Option<String>,

    /// The agreement PartyVInfo (APV)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apv: Option<String>,

    /// Additional header parameters
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// An ephemeral public key for ECDH.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralPublicKey {
    /// The key type (always "EC" or "OKP")
    pub kty: String,

    /// The curve used
    pub crv: EcdhCurve,

    /// The public key x-coordinate (base64url-encoded)
    pub x: String,

    /// The public key y-coordinate (base64url-encoded, only for NIST curves)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

impl JweHeader {
    /// Creates a new JWE header for anoncrypt (ECDH-ES+A256KW).
    pub fn new_anoncrypt(
        content_encryption: ContentEncryptionAlgorithm,
        epk: EphemeralPublicKey,
    ) -> Self {
        Self {
            alg: KeyAgreementAlgorithm::EcdhEsA256kw,
            enc: content_encryption,
            epk: Some(epk),
            skid: None,
            apu: None,
            apv: None,
            additional: HashMap::new(),
        }
    }

    /// Creates a new JWE header for authcrypt (ECDH-1PU+A256KW).
    pub fn new_authcrypt(
        content_encryption: ContentEncryptionAlgorithm,
        epk: EphemeralPublicKey,
        skid: String,
        apu: Option<String>,
    ) -> Self {
        Self {
            alg: KeyAgreementAlgorithm::Ecdh1puA256kw,
            enc: content_encryption,
            epk: Some(epk),
            skid: Some(skid),
            apu,
            apv: None,
            additional: HashMap::new(),
        }
    }

    /// Serializes the header to a base64url-encoded string.
    pub fn to_string(&self) -> Result<String> {
        let json = serde_json::to_string(self)?;
        Ok(URL_SAFE_NO_PAD.encode(json.as_bytes()))
    }

    /// Deserializes a header from a base64url-encoded string.
    pub fn from_string(s: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(s).map_err(JweError::Base64)?;
        serde_json::from_slice(&bytes).map_err(JweError::Json)
    }
}

impl EphemeralPublicKey {
    /// Creates a new ephemeral public key.
    pub fn new(curve: EcdhCurve, public_key: &[u8]) -> Result<Self> {
        match curve {
            EcdhCurve::X25519 => {
                if public_key.len() != 32 {
                    return Err(JweError::InvalidKeyMaterial(
                        "Invalid X25519 public key length".to_string(),
                    ));
                }
                Ok(Self {
                    kty: "OKP".to_string(),
                    crv: curve,
                    x: URL_SAFE_NO_PAD.encode(public_key),
                    y: None,
                })
            }
            EcdhCurve::P256 | EcdhCurve::P384 | EcdhCurve::P521 => {
                // For NIST curves, the public key is encoded in uncompressed form:
                // 0x04 || x || y
                if public_key[0] != 0x04 {
                    return Err(JweError::InvalidKeyMaterial(
                        "Invalid NIST curve public key format".to_string(),
                    ));
                }

                let key_size = match curve {
                    EcdhCurve::P256 => 32,
                    EcdhCurve::P384 => 48,
                    EcdhCurve::P521 => 66,
                    _ => unreachable!(),
                };

                if public_key.len() != 1 + 2 * key_size {
                    return Err(JweError::InvalidKeyMaterial(
                        "Invalid NIST curve public key length".to_string(),
                    ));
                }

                let x = &public_key[1..1 + key_size];
                let y = &public_key[1 + key_size..];

                Ok(Self {
                    kty: "EC".to_string(),
                    crv: curve,
                    x: URL_SAFE_NO_PAD.encode(x),
                    y: Some(URL_SAFE_NO_PAD.encode(y)),
                })
            }
        }
    }

    /// Gets the raw public key bytes.
    pub fn raw_public_key(&self) -> Result<Vec<u8>> {
        match self.crv {
            EcdhCurve::X25519 => URL_SAFE_NO_PAD
                .decode(&self.x)
                .map_err(|e| JweError::Base64("Failed to decode X25519 public key", e)),
            EcdhCurve::P256 | EcdhCurve::P384 | EcdhCurve::P521 => {
                let x = URL_SAFE_NO_PAD
                    .decode(&self.x)
                    .map_err(|e| JweError::Base64("Failed to decode x coordinate", e))?;

                let y = self.y.as_ref().ok_or_else(|| {
                    JweError::InvalidKeyMaterial("Missing y coordinate for NIST curve".to_string())
                })?;
                let y = URL_SAFE_NO_PAD
                    .decode(y)
                    .map_err(|e| JweError::Base64("Failed to decode y coordinate", e))?;

                let mut key = Vec::with_capacity(1 + x.len() + y.len());
                key.push(0x04); // Uncompressed point format
                key.extend_from_slice(&x);
                key.extend_from_slice(&y);
                Ok(key)
            }
        }
    }
}

impl ToString for JweHeader {
    fn to_string(&self) -> String {
        let json = serde_json::to_string(self).expect("JweHeader serialization failed");
        URL_SAFE_NO_PAD.encode(json.as_bytes())
    }
}

impl FromStr for JweHeader {
    type Err = JweError;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(s)?;
        serde_json::from_slice(&bytes).map_err(JweError::Serialization)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwe::algorithms::generate_ephemeral_keypair;
    use serde_json::json;

    #[test]
    fn test_header_anoncrypt() {
        let (_, public) = generate_ephemeral_keypair(EcdhCurve::X25519).unwrap();
        let epk = EphemeralPublicKey::new(EcdhCurve::X25519, &public).unwrap();
        let header = JweHeader::new_anoncrypt(ContentEncryptionAlgorithm::A256Gcm, epk);

        assert_eq!(header.alg, KeyAgreementAlgorithm::EcdhEsA256kw);
        assert_eq!(header.enc, ContentEncryptionAlgorithm::A256Gcm);
        assert!(header.epk.is_some());
        assert!(header.skid.is_none());
        assert!(header.apu.is_none());
        assert!(header.apv.is_none());
    }

    #[test]
    fn test_header_authcrypt() {
        let (_, public) = generate_ephemeral_keypair(EcdhCurve::X25519).unwrap();
        let epk = EphemeralPublicKey::new(EcdhCurve::X25519, &public).unwrap();
        let header = JweHeader::new_authcrypt(
            ContentEncryptionAlgorithm::A256Gcm,
            epk,
            "did:example:alice#key-1".to_string(),
            Some("alice".to_string()),
        );

        assert_eq!(header.alg, KeyAgreementAlgorithm::Ecdh1puA256kw);
        assert_eq!(header.enc, ContentEncryptionAlgorithm::A256Gcm);
        assert!(header.epk.is_some());
        assert_eq!(header.skid, Some("did:example:alice#key-1".to_string()));
        assert_eq!(header.apu, Some("alice".to_string()));
        assert!(header.apv.is_none());
    }

    #[test]
    fn test_header_serialization() {
        let (_, public) = generate_ephemeral_keypair(EcdhCurve::X25519).unwrap();
        let epk = EphemeralPublicKey::new(EcdhCurve::X25519, &public).unwrap();
        let header = JweHeader::new_anoncrypt(ContentEncryptionAlgorithm::A256Gcm, epk);

        let encoded = header.to_string().unwrap();
        let decoded = JweHeader::from_string(&encoded).unwrap();

        assert_eq!(decoded.alg, header.alg);
        assert_eq!(decoded.enc, header.enc);
        assert_eq!(decoded.epk.unwrap().x, header.epk.unwrap().x);
    }

    #[test]
    fn test_ephemeral_key_x25519() {
        let (_, public) = generate_ephemeral_keypair(EcdhCurve::X25519).unwrap();
        let epk = EphemeralPublicKey::new(EcdhCurve::X25519, &public).unwrap();

        assert_eq!(epk.kty, "OKP");
        assert_eq!(epk.crv, EcdhCurve::X25519);
        assert!(epk.y.is_none());

        let raw = epk.raw_public_key().unwrap();
        assert_eq!(raw, public);
    }

    #[test]
    fn test_ephemeral_key_nist() {
        for curve in [EcdhCurve::P256, EcdhCurve::P384, EcdhCurve::P521] {
            let (_, public) = generate_ephemeral_keypair(curve).unwrap();
            let epk = EphemeralPublicKey::new(curve, &public).unwrap();

            assert_eq!(epk.kty, "EC");
            assert_eq!(epk.crv, curve);
            assert!(epk.y.is_some());

            let raw = epk.raw_public_key().unwrap();
            assert_eq!(raw, public);
        }
    }

    #[test]
    fn test_invalid_key_material() {
        // Invalid X25519 key length
        let result = EphemeralPublicKey::new(EcdhCurve::X25519, &[0; 31]);
        assert!(result.is_err());

        // Invalid NIST curve format (not uncompressed)
        let result = EphemeralPublicKey::new(EcdhCurve::P256, &[0x03; 65]);
        assert!(result.is_err());

        // Invalid NIST curve length
        let result = EphemeralPublicKey::new(EcdhCurve::P256, &[0x04; 64]);
        assert!(result.is_err());
    }
}
