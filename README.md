# tap-didcomm

A modular DIDComm v2 library in Rust that can run both natively and in WebAssembly (WASM) environments. This project provides a complete implementation of the DIDComm v2 specification with support for message packing/unpacking, signing, encryption, and verification.

## Architecture

The project is organized as a Rust workspace with three main crates:

### tap-didcomm-core

Core library that handles message packing/unpacking with full async signing, encryption, and verification using the `ssi` crate. It exposes a plugin mechanism to allow custom DID resolvers, signers, encryptors, etc.

Key features:
- Async message packing/unpacking
- Support for signing, encryption, and verification
- Pluggable DID resolvers, signers, and encryptors
- Built on the `ssi` crate for cryptographic operations
- Comprehensive JWE support:
  - ECDH-ES+A256KW for anoncrypt
  - ECDH-1PU+A256KW for authcrypt
  - Multiple content encryption algorithms (A256CBC-HS512, A256GCM, XC20P)
  - Support for multiple recipients
  - NIST curves (P-256, P-384, P-521) and X25519
  - APU/APV parameter support in key derivation
  - Compressed NIST curve point support

### tap-didcomm-node

An abstract DIDComm node implementation that builds on tap-didcomm-core. It provides:
- Async message receiving and processing
- Actix Actor integration for message handling
- Flexible message dispatch (native and WASM)
- Example logging actor implementation
- Pluggable architecture for custom message handlers

### tap-didcomm-web

HTTP server implementation wrapping a DIDComm node. Features include:
- RESTful API endpoints for message handling
- CORS support
- Actix-web integration
- Comprehensive error handling
- Logging middleware

## Features

- Full DIDComm v2 specification support
- Async/await throughout
- Pluggable architecture for customization
- Native and WASM compatibility
- Comprehensive test coverage
- Modern Rust error handling
- Detailed documentation

## Getting Started

### Prerequisites

- Rust 2021 edition or later
- Cargo with workspace support
- For WASM builds:
  - wasm-pack
  - Node.js and npm (for testing)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/your-org/tap-didcomm.git
cd tap-didcomm
```

2. Build the project:
```bash
cargo build --all-features
```

3. Run tests:
```bash
cargo test --all
```

### WASM Build

To build for WASM:

```bash
wasm-pack build --target web
```

## Usage

### Basic Message Handling

```rust
use tap_didcomm_core::{Message, PackingType};
use tap_didcomm_node::{DIDCommNode, NodeConfig};

// Create a node with default configuration
let config = NodeConfig::default();
let node = DIDCommNode::new(config, your_plugin);

// Create and pack a message
let message = Message::new("test", json!({"hello": "world"}))?
    .from("did:example:alice")
    .to(vec!["did:example:bob"]);

// Pack the message
let packed = pack_message(&message, &your_plugin, PackingType::Signed).await?;

// Receive and process the message
node.receive(&packed).await?;
```

### Using the Web Server

```rust
use tap_didcomm_web::{DIDCommServer, ServerConfig};

// Create and start the server
let config = ServerConfig {
    host: "127.0.0.1".to_string(),
    port: 8080,
    cors: CorsConfig::default(),
};

let server = DIDCommServer::new(config, node_config, your_plugin);
server.run().await?;
```

## Testing

The project includes comprehensive test coverage:

```bash
# Run all tests
cargo test --all

# Run specific crate tests
cargo test -p tap-didcomm-core
cargo test -p tap-didcomm-node
cargo test -p tap-didcomm-web
```

## Documentation

Generate documentation:

```bash
cargo doc --no-deps
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 