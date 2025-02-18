use crate::error::Result;

/// Validates a DID string according to the DID syntax specification.
///
/// # Arguments
/// * `did` - The DID string to validate
///
/// # Errors
/// * `Error::InvalidDID` - If the DID string does not match the required format
pub fn validate_did(did: &str) -> Result<()> {
    // Basic validation - can be expanded
    if !did.starts_with("did:") {
        return Err(crate::Error::InvalidDIDDocument(
            "Invalid DID format".into(),
        ));
    }
    Ok(())
}
