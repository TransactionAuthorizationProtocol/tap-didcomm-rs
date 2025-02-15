# tap-didcomm-node

Node.js-specific implementation of the DIDComm protocol for the TAP (Trust Anchor Protocol) system.

## Overview

`tap-didcomm-node` extends the core DIDComm functionality with Node.js-specific features and optimizations. It provides:
- Native Node.js bindings for DIDComm operations
- Message handling and routing
- Actor-based message processing
- HTTP transport layer

## Features

- **Node.js Integration**: Native bindings optimized for Node.js environment
- **Actor System**: 
  - Message handling through actors
  - Concurrent message processing
  - Automatic message routing
- **HTTP Transport**:
  - Built-in HTTP server
  - Configurable endpoints
  - CORS support
- **Plugin Extensions**:
  - Node-specific plugin implementations
  - HTTP-based DID resolution
  - File system key storage
- **Performance Optimizations**:
  - Async I/O operations
  - Thread pool management
  - Memory efficient message handling

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
tap-didcomm-node = { path = "../tap-didcomm-node" }
```

Basic example:

```rust
use tap_didcomm_node::{DIDCommNode, NodeConfig, HandlerRegistry};
use tap_didcomm_core::types::Message;

// Configure the node
let config = NodeConfig::default();
let plugin = // ... initialize your plugin
let mut node = DIDCommNode::new(config, plugin);

// Register message handlers
let mut registry = HandlerRegistry::new();
registry.register(handler);
node.start(registry).await?;

// Send a message
let message = Message::new("Hello from Node!")
    .from("did:example:sender")
    .to(vec!["did:example:recipient"]);
node.send(&message).await?;
```

## Architecture

The crate is organized into several modules:

- `node`: Core Node.js integration and server implementation
- `actor`: Actor system for message handling
- `dispatch`: Message routing and dispatch logic
- `plugin`: Node-specific plugin implementations
- `transport`: HTTP transport layer

### Actor System

The actor system provides a concurrent message processing framework:

```rust
pub struct Handler {
    node: Arc<DIDCommNode>,
}

impl Handler {
    async fn handle_message(&self, message: Message) -> Result<()> {
        // Process the message
    }
}

// Register the handler
let handler = spawn_message_handler();
registry.register("message_type", handler);
```

### Configuration

The node can be configured through `NodeConfig`:

```rust
pub struct NodeConfig {
    pub port: u16,
    pub host: String,
    pub use_https: bool,
    pub max_message_size: usize,
    pub dispatch: DispatchConfig,
}
```

## Testing

Run the test suite:

```bash
cargo test
```

For integration tests:

```bash
cargo test --test '*'
```

## WebAssembly Support

This crate includes WebAssembly bindings for use in Node.js:

```javascript
import { DIDCommNode } from '@tap-didcomm/node';

const node = new DIDCommNode({
  port: 8000,
  host: 'localhost'
});

await node.initialize();
```

## Security

This crate handles cryptographic operations and network communication. See the [SECURITY.md](../SECURITY.md) file for security considerations and reporting vulnerabilities.

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## Contributing

Please read [CONTRIBUTING.md](../CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 