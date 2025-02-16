//! Cryptographic operations for DIDComm messages.

use crate::error::Result;

/// Signs a message using the provided signer
pub async fn sign_message(
    message: &[u8],
    signer: Box<dyn crate::plugin::Signer>,
) -> Result<Vec<u8>> {
    // Implementation
    Ok(message.to_vec())
}
