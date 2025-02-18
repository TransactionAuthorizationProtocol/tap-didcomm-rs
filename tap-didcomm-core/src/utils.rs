use crate::error::Result;

/// Validates a DID string
pub fn validate_did(did: String) -> Result<()> {
    // Basic validation - can be expanded
    if !did.starts_with("did:") {
        return Err(crate::Error::InvalidDIDDocument(
            "Invalid DID format".into(),
        ));
    }
    Ok(())
}
