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

### tap-didcomm-node

An abstract DIDComm node implementation that builds on tap-didcomm-core. It provides:
- Message receiving via `receive()` function
- Actix Actor interface for message subscription
- Message dispatch functionality using `reqwest` (native) or `fetch` (WASM)

### tap-didcomm-web

An HTTP server implementation using Actix-web that wraps a tap-didcomm-node instance. It provides:
- HTTP endpoints for receiving and sending DIDComm messages
- Example logging actor implementation
- Built-in error handling and logging

## Installation

Add the desired crate to your `Cargo.toml`:

```toml
[dependencies]
tap-didcomm-core = "0.1"
tap-didcomm-node = "0.1"  # If you need the node functionality
tap-didcomm-web = "0.1"   # If you need the web server
```

## Usage

Example usage will be added as the implementation progresses.

## Development

### Prerequisites

- Rust 1.70 or later
- Cargo

### Building

```bash
# Build all crates
cargo build

# Run tests
cargo test

# Build documentation
cargo doc
```

### Testing

The project includes comprehensive test coverage:
- Unit tests in each module
- Integration tests for the node and web components
- WASM-specific tests for browser compatibility

Run all tests with:
```bash
cargo test --workspace
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 