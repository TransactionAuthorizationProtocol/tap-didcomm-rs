# tap-didcomm-core

Core implementation of the DIDComm protocol for the TAP (Trust Anchor Protocol) system.

## Overview

`tap-didcomm-core` provides the foundational components for DIDComm messaging, including:
- Message encryption and decryption
- Message signing and verification
- DID resolution
- Plugin system for extensibility

## Features

- **DIDComm v2 Support**: Implements the DIDComm v2 specification
- **Flexible Encryption**: Supports multiple encryption algorithms:
  - ECDH-ES+A256KW (Anoncrypt)
  - ECDH-1PU+A256KW (Authcrypt)
  - A256CBC-HS512
  - XC20P
- **Pluggable Architecture**: Extensible design allowing custom implementations of:
  - DID Resolution
  - Cryptographic Operations
  - Key Management
- **Async/Await**: Built on Rust's async/await for efficient I/O operations
- **Cross-Platform**: Core functionality works across different platforms
- **WASM Support**: Can be compiled to WebAssembly for browser use

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
tap-didcomm-core = { path = "../tap-didcomm-core" }
```

Basic example:

```rust
use tap_didcomm_core::{
    plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer},
    types::{Message, PackingType},
};

// Create a message
let message = Message::new("Hello DIDComm!")
    .from("did:example:sender")
    .to(vec!["did:example:recipient"]);

// Use a plugin for DIDComm operations
let plugin: Box<dyn DIDCommPlugin> = // ... initialize your plugin
let packed = message.pack(&plugin, PackingType::AuthcryptV2).await?;
```

## Architecture

The crate is organized into several modules:

- `plugin`: Trait definitions for the plugin system
- `types`: Core data structures and types
- `error`: Error types and handling
- `jwe`: JWE (JSON Web Encryption) implementation
- `pack`: Message packing and unpacking logic

### Plugin System

The plugin system is based on three main traits:

```rust
pub trait DIDResolver {
    async fn resolve(&self, did: &str) -> Result<String>;
}

pub trait Signer {
    async fn sign(&self, message: &[u8], from: &str) -> Result<Vec<u8>>;
    async fn verify(&self, message: &[u8], signature: &[u8], from: &str) -> Result<bool>;
}

pub trait Encryptor {
    async fn encrypt(&self, message: &[u8], to: &[&str], from: Option<&str>) -> Result<Vec<u8>>;
    async fn decrypt(&self, message: &[u8], recipient: &str) -> Result<Vec<u8>>;
}
```

## Testing

Run the test suite:

```bash
cargo test
```

For more detailed test output:

```bash
cargo test -- --nocapture
```

## Security

This crate implements cryptographic operations and should be used with care. See the [SECURITY.md](../SECURITY.md) file for security considerations and reporting vulnerabilities.

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## Contributing

Please read [CONTRIBUTING.md](../CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 