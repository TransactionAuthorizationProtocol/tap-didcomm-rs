//! HTTP server wrapper for DIDComm node.
//!
//! This crate provides an HTTP server implementation that wraps a DIDComm node.
//! It exposes endpoints for:
//! - Receiving DIDComm messages
//! - Sending DIDComm messages
//! - Node status and information
//!
//! It also includes middleware for CORS, logging, and error handling.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod handlers;
pub mod server;

/// Mock implementations for testing.
pub mod mock;

/// Test utilities and mock implementations.
#[cfg(test)]
pub mod tests;

// Re-export main types for convenience
pub use error::{Error, Result};
pub use handlers::*;
pub use server::{DIDCommServer, ServerConfig}; 