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

The project includes comprehensive test coverage across all crates:

#### Running Tests
```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p tap-didcomm-core
cargo test -p tap-didcomm-node
cargo test -p tap-didcomm-web

# Run tests with logging output
RUST_LOG=debug cargo test
```

#### Test Coverage
Each crate includes:
- Unit tests in each module
- Integration tests for public APIs
- Mock implementations for testing
- WASM-specific tests for browser compatibility

### Running a Test Server

1. Start the test server:
```bash
cargo run -p tap-didcomm-web --bin web_server
```

2. The server will start on `http://localhost:8080` with the following endpoints:
   - `GET /status` - Check server status
   - `POST /didcomm` - Receive DIDComm messages
   - `POST /didcomm/send` - Send DIDComm messages

3. Test the endpoints:
```bash
# Check server status
curl -X GET http://localhost:8080/status

# Send a message
curl -X POST http://localhost:8080/didcomm/send \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "id": "1234567890",
      "typ": "test",
      "from": "did:example:alice",
      "to": ["did:example:bob"],
      "created_time": 1677721600,
      "body": {"hello": "world"}
    },
    "packing": "Signed",
    "endpoint": "http://localhost:8080/didcomm"
  }'

# Receive a message
curl -X POST http://localhost:8080/didcomm \
  -H "Content-Type: application/json" \
  -d '{
    "data": "base64_encoded_message_here"
  }'
```

### Configuring Custom Actors

The node crate supports custom actors for handling DIDComm messages. Here's how to create and configure them:

1. Create a custom actor:
```rust
use actix::prelude::*;
use tap_didcomm_node::actor::{Message, MessageHandler};

struct CustomActor {
    name: String,
}

impl Actor for CustomActor {
    type Context = Context<Self>;
}

impl Handler<Message> for CustomActor {
    type Result = ();

    fn handle(&mut self, msg: Message, _ctx: &mut Self::Context) {
        println!("Actor {} received message: {:?}", self.name, msg);
    }
}

impl MessageHandler for CustomActor {
    fn handle_message(&mut self, message: Message, ctx: &mut Self::Context) {
        self.handle(message, ctx);
    }
}
```

2. Register the actor with a DIDComm node:
```rust
use tap_didcomm_node::{DIDCommNode, NodeConfig};

#[actix_rt::main]
async fn main() {
    // Create and start the actor
    let actor = CustomActor {
        name: "custom".to_string(),
    }.start();

    // Create a node with default config
    let mut node = DIDCommNode::new(
        NodeConfig::default(),
        YourPlugin::new(), // Your DIDCommPlugin implementation
    );

    // Register the actor to handle specific message types
    node.register_handler("test", actor.recipient());
}
```

3. Use with the web server:
```rust
use tap_didcomm_web::server::{ServerConfig, CorsConfig, DIDCommServer};

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    // Create and configure the actor
    let actor = CustomActor {
        name: "custom".to_string(),
    }.start();

    // Create node config
    let node_config = NodeConfig::default();
    
    // Create server config
    let server_config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: 8080,
        cors: CorsConfig {
            allowed_origins: vec!["*".to_string()],
            allow_credentials: true,
        },
    };

    // Create and configure the server
    let mut server = DIDCommServer::new(
        server_config,
        node_config,
        YourPlugin::new(),
    );

    // Register the actor
    server.node_mut().register_handler("test", actor.recipient());

    // Run the server
    server.run().await
}
```

### Plugin System

The core crate provides a plugin system for customizing DIDComm functionality. Implement the following traits for your custom plugin:

- `DIDResolver` - For resolving DIDs to DID Documents
- `Signer` - For message signing and verification
- `Encryptor` - For message encryption and decryption
- `DIDCommPlugin` - Combines the above traits into a complete plugin

See the `TestPlugin` in the web server binary for a simple example implementation.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 