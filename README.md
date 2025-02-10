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

## Setting up a Web DID with DIDKit

This section explains how to create and use a web DID for your DIDComm server using DIDKit.

### Prerequisites

1. Install DIDKit CLI:
```bash
cargo install didkit-cli
```

2. Create a directory structure:
```bash
mkdir -p ~/.didcomm/keys
mkdir -p ~/.didcomm/did-documents
```

### Generating Keys

1. Generate an Ed25519 key pair:
```bash
didkit generate-ed25519-key > ~/.didcomm/keys/key.jwk
```

2. Get the DID from the key:
```bash
export DID=$(didkit key-to-did web -k ~/.didcomm/keys/key.jwk)
echo $DID  # Should output something like: did:web:example.com
```

### Creating the DID Document

1. Create the initial DID document using `didkit create`:
```bash
didkit did-create web \
  --key-path ~/.didcomm/keys/key.jwk \
  --did-domain example.com \
  --verification-method-id "#key-1" \
  --verification-relationship authentication \
  --verification-relationship assertionMethod \
  > ~/.didcomm/did-documents/did.json
```

2. Add the DIDComm service endpoint:
```bash
didkit did-update \
  --did-path ~/.didcomm/did-documents/did.json \
  --key-path ~/.didcomm/keys/key.jwk \
  --add-service '{
    "id": "#didcomm",
    "type": "DIDCommMessaging",
    "serviceEndpoint": "https://example.com/didcomm"
  }' \
  > ~/.didcomm/did-documents/did.json.tmp && \
  mv ~/.didcomm/did-documents/did.json.tmp ~/.didcomm/did-documents/did.json
```

3. Add key agreement capability:
```bash
didkit did-update \
  --did-path ~/.didcomm/did-documents/did.json \
  --key-path ~/.didcomm/keys/key.jwk \
  --verification-relationship keyAgreement \
  > ~/.didcomm/did-documents/did.json.tmp && \
  mv ~/.didcomm/did-documents/did.json.tmp ~/.didcomm/did-documents/did.json
```

4. Verify the DID document:
```bash
didkit did-verify \
  --did-path ~/.didcomm/did-documents/did.json \
  --key-path ~/.didcomm/keys/key.jwk
```

### Hosting the DID Document

For a web DID (did:web), you need to host the DID Document at a specific URL pattern:
- For domain-based DIDs (e.g., `did:web:example.com`): `https://example.com/.well-known/did.json`
- For path-based DIDs (e.g., `did:web:example.com:user:alice`): `https://example.com/user/alice/did.json`

1. Configure your web server to serve the DID Document:
```bash
# For Apache
cp ~/.didcomm/did-documents/did.json /var/www/html/.well-known/did.json

# For Nginx
cp ~/.didcomm/did-documents/did.json /usr/share/nginx/html/.well-known/did.json
```

2. Ensure the document is accessible via HTTPS.

### Configuring the DIDComm Server

Create a custom plugin that uses your DID and key:

```rust
use serde_json::Value;
use std::fs;
use tap_didcomm_core::plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer};

struct WebDIDPlugin {
    key: Value,
    did_document: Value,
}

impl WebDIDPlugin {
    fn new() -> std::io::Result<Self> {
        let key = fs::read_to_string(std::env::var("HOME").unwrap() + "/.didcomm/keys/key.jwk")?;
        let did_document = fs::read_to_string(std::env::var("HOME").unwrap() + "/.didcomm/did-documents/did.json")?;
        
        Ok(Self {
            key: serde_json::from_str(&key)?,
            did_document: serde_json::from_str(&did_document)?,
        })
    }
}

#[async_trait::async_trait]
impl DIDResolver for WebDIDPlugin {
    async fn resolve(&self, did: &str) -> tap_didcomm_core::error::Result<String> {
        if did == self.did_document["id"].as_str().unwrap() {
            Ok(serde_json::to_string(&self.did_document)?)
        } else {
            // Fallback to HTTP resolution for other DIDs
            let url = format!("https://{}/did.json", did.strip_prefix("did:web:").unwrap());
            let response = reqwest::get(&url).await?.text().await?;
            Ok(response)
        }
    }
}

#[async_trait::async_trait]
impl Signer for WebDIDPlugin {
    async fn sign(&self, data: &[u8], _key_id: &str) -> tap_didcomm_core::error::Result<Vec<u8>> {
        // Use DIDKit to sign the data
        let signature = didkit::sign(data, &self.key)?;
        Ok(signature)
    }

    async fn verify(&self, data: &[u8], signature: &[u8], _key_id: &str) -> tap_didcomm_core::error::Result<bool> {
        // Use DIDKit to verify the signature
        Ok(didkit::verify(data, signature, &self.key)?)
    }
}

#[async_trait::async_trait]
impl Encryptor for WebDIDPlugin {
    async fn encrypt(&self, data: &[u8], recipients: Vec<String>, from: Option<String>) -> tap_didcomm_core::error::Result<Vec<u8>> {
        // Use DIDKit for encryption
        let encrypted = didkit::encrypt(data, &recipients, from.as_deref(), &self.key)?;
        Ok(encrypted)
    }

    async fn decrypt(&self, data: &[u8], recipient: String) -> tap_didcomm_core::error::Result<Vec<u8>> {
        // Use DIDKit for decryption
        let decrypted = didkit::decrypt(data, &recipient, &self.key)?;
        Ok(decrypted)
    }
}

impl DIDCommPlugin for WebDIDPlugin {
    fn as_resolver(&self) -> &dyn DIDResolver { self }
    fn as_signer(&self) -> &dyn Signer { self }
    fn as_encryptor(&self) -> &dyn Encryptor { self }
}
```

Now use this plugin with your server:

```rust
#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    // Load the plugin
    let plugin = WebDIDPlugin::new()?;
    
    // Get DID from environment or config
    let did = std::env::var("DIDCOMM_DID").unwrap_or_else(|_| {
        let doc = &plugin.did_document;
        doc["id"].as_str().unwrap().to_string()
    });
    
    // Configure the node
    let node_config = NodeConfig {
        did,
        default_packing: PackingType::AuthcryptV2,
        base_url: Some("https://example.com/didcomm".to_string()),
    };
    
    // Configure the server
    let server_config = ServerConfig {
        host: "0.0.0.0".to_string(),
        port: 8080,
        cors: CorsConfig {
            allowed_origins: vec!["*".to_string()],
            allow_credentials: true,
        },
    };
    
    // Create and run the server
    let server = DIDCommServer::new(server_config, node_config, plugin);
    server.run().await
}
```

### Testing the Setup

1. Start the server:
```bash
RUST_LOG=debug DIDCOMM_DID="did:web:example.com" cargo run -p tap-didcomm-web --bin web_server
```

2. Test DID resolution:
```bash
curl http://localhost:8080/status
```

3. Send a test message:
```bash
curl -X POST http://localhost:8080/didcomm/send \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "id": "1234567890",
      "typ": "test",
      "from": "did:web:example.com",
      "to": ["did:web:recipient.com"],
      "created_time": 1677721600,
      "body": {"hello": "world"}
    },
    "packing": "AuthcryptV2",
    "endpoint": "https://recipient.com/didcomm"
  }'
```

The server will use your web DID and associated keys for all DIDComm operations.

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

### Using the Universal Resolver Plugin

The `ssi` crate provides a universal resolver that supports many popular DID methods. Here's how to use it:

```rust
use ssi::did_resolve::{DIDResolver as SSIResolver, HTTPDIDResolver};
use tap_didcomm_core::plugin::SSIDIDResolverWrapper;

// Create a resolver that supports multiple DID methods
async fn create_universal_resolver() -> impl DIDCommPlugin {
    // Create a universal resolver with default configuration
    let http_resolver = HTTPDIDResolver::new(
        // Universal Resolver endpoint (or use your own)
        "https://dev.uniresolver.io/1.0/identifiers/",
        // Supported methods
        vec![
            "did:web",      // Web DIDs
            "did:key",      // Key DIDs
            "did:ethr",     // Ethereum DIDs
            "did:ion",      // ION DIDs (Sidetree)
            "did:sov",      // Sovrin DIDs
            // Add more methods as needed
        ],
    );

    // Wrap the universal resolver
    SSIDIDResolverWrapper::new(http_resolver)
}

// Use it in your server
#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    // Create the universal resolver plugin
    let resolver_plugin = create_universal_resolver().await;
    
    // Create a combined plugin that uses:
    // - Universal resolver for DID resolution
    // - Your custom implementation for signing/encryption
    struct CombinedPlugin {
        resolver: Box<dyn DIDResolver>,
        signer: Box<dyn Signer>,
        encryptor: Box<dyn Encryptor>,
    }

    impl DIDCommPlugin for CombinedPlugin {
        fn as_resolver(&self) -> &dyn DIDResolver { &*self.resolver }
        fn as_signer(&self) -> &dyn Signer { &*self.signer }
        fn as_encryptor(&self) -> &dyn Encryptor { &*self.encryptor }
    }

    // Create your server with the combined plugin
    let server = DIDCommServer::new(
        server_config,
        node_config,
        CombinedPlugin {
            resolver: Box::new(resolver_plugin),
            signer: Box::new(YourSigner::new()),
            encryptor: Box::new(YourEncryptor::new()),
        },
    );

    server.run().await
}
```

The universal resolver supports these DID methods out of the box:

- `did:web` - Web DIDs
- `did:key` - Key DIDs
- `did:ethr` - Ethereum DIDs
- `did:ion` - ION DIDs (Sidetree)
- `did:sov` - Sovrin DIDs
- `did:elem` - Element DIDs
- `did:github` - GitHub DIDs
- `did:peer` - Peer DIDs
- And more...

You can also configure it to use your own resolver endpoint or add support for additional DID methods.

#### Custom Resolver Endpoint

If you want to use a different resolver endpoint or run your own universal resolver:

```rust
let http_resolver = HTTPDIDResolver::new(
    // Your custom endpoint
    "https://your-resolver.example.com/resolve/",
    // Your supported methods
    vec!["did:web", "did:key", "your:custom:method"],
);
```

#### Caching Support

For better performance, you can add caching to the resolver:

```rust
use ssi::did_resolve::CachingDIDResolver;
use std::time::Duration;

let cached_resolver = CachingDIDResolver::new(
    http_resolver,
    Duration::from_secs(3600), // Cache for 1 hour
);

let plugin = SSIDIDResolverWrapper::new(cached_resolver);
```

### Example Server Configuration

The project includes a default server implementation that uses environment variables for configuration and the universal resolver for DID resolution. You can use this as a starting point for your own implementation:

#### Environment Variables

- `PORT` - The HTTP port to listen on (default: 8080)
- `SIGNING_JWK` - A JWK (JSON Web Key) for signing and encryption. Must be an Ed25519 key for signing and an ECDH key for encryption
- `RUST_LOG` - Logging level (e.g., "debug", "info")

#### Key Configuration

The server uses JSON Web Key (JWK) format for cryptographic operations. For DIDComm v2 compatibility, you should use:

1. For Signing/Verification (Ed25519):
```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "your-public-key-base64",
  "d": "your-private-key-base64",
  "use": "sig"
}
```

2. For Encryption/Decryption (ECDH-ES):
```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "your-public-key-x-base64",
  "y": "your-public-key-y-base64",
  "d": "your-private-key-base64",
  "use": "enc"
}
```

The server supports:
- **Signing**: EdDSA with Ed25519 keys
- **Encryption**: ECDH-ES+A256KW for key wrapping and A256GCM for content encryption
- **Multiple Recipients**: Can encrypt messages for multiple DIDs
- **Key Resolution**: Automatically resolves recipient keys from DID documents

#### Running the Example Server

1. First, generate your keys:
```bash
# Generate Ed25519 key for signing
didkit generate-ed25519-key > signing.jwk

# Generate ECDH key for encryption
didkit generate-p256-key > encryption.jwk

# Combine the keys (you'll need to manually merge the JWKs)
cat signing.jwk encryption.jwk | jq -s add > combined.jwk

# Set the environment variables
export SIGNING_JWK=$(cat combined.jwk)
export PORT=9000  # Optional, defaults to 8080
export RUST_LOG=debug  # Optional
```

2. Run the server:
```bash
cargo run -p tap-didcomm-web --bin web_server
```

The server will start with:
- Universal resolver support for major DID methods
- CORS enabled for all origins
- Credentials allowed
- Base URL set to the server's address
- Full JWE encryption and JWS signing support

#### Testing Encrypted Messages

1. Send an encrypted message:
```bash
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
    "packing": "AuthcryptV2",  // Use encryption
    "endpoint": "http://localhost:8080/didcomm"
  }'
```

The message will be:
1. Signed using EdDSA (Ed25519)
2. Encrypted using ECDH-ES key agreement
3. Content encrypted with A256GCM
4. Packaged as a JWE with all necessary headers

When receiving messages, the server will:
1. Decrypt the JWE using the node's private key
2. Verify the signature using the sender's public key from their DID document
3. Process the decrypted message

#### Supported DID Methods

The universal resolver supports the following DID methods through the `UniversalPlugin`:

| Method | Specification | Verification | Encryption | Notes |
|--------|--------------|--------------|------------|-------|
| `did:web` | [DID Web Spec](https://w3c-ccg.github.io/did-method-web/) | ✅ | ✅ | Best for controlled domains. Supports both Ed25519 and ECDH keys. |
| `did:key` | [DID Key Spec](https://w3c-ccg.github.io/did-method-key/) | ✅ | ✅ | Simple, portable. Good for testing. Supports multiple key types. |
| `did:ethr` | [DID Ethr Spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md) | ✅ | ✅ | Ethereum-based. Uses secp256k1 keys. |
| `did:ion` | [DID ION Spec](https://github.com/decentralized-identity/ion-did-method) | ✅ | ✅ | Bitcoin-anchored Sidetree. Good for long-term DIDs. |
| `did:sov` | [DID Sov Spec](https://sovrin-foundation.github.io/sovrin/spec/did-method-spec-template.html) | ✅ | ✅ | Sovrin network. Uses Ed25519 keys. |
| `did:elem` | [DID Element Spec](https://github.com/transmute-industries/sidetree.js/blob/main/docs/did-method-spec.md) | ✅ | ✅ | Sidetree-based. Multiple blockchain support. |
| `did:peer` | [DID Peer Spec](https://identity.foundation/peer-did-method-spec/) | ✅ | ✅ | P2P interactions. No ledger required. |
| `did:github` | [DID GitHub Spec](https://github.com/decentralized-identity/github-did/blob/master/docs/did-method-spec.md) | ✅ | ❌ | GitHub-based identity. Limited to verification. |
| `did:pkh` | [DID PKH Spec](https://github.com/w3c-ccg/did-pkh/blob/main/did-pkh-method-spec.md) | ✅ | ❌ | For blockchain accounts. Verification only. |
| `did:jwk` | [DID JWK Spec](https://github.com/quartzjer/did-jwk/blob/main/spec.md) | ✅ | ✅ | Direct JWK embedding. Good for testing. |
| `did:tz` | [DID Tezos Spec](https://did-tezos.spruceid.com/) | ✅ | ✅ | Tezos blockchain-based. |
| `did:sol` | [DID Solana Spec](https://github.com/identity-com/sol-did) | ✅ | ✅ | Solana blockchain-based. |
| `did:indy` | [DID Indy Spec](https://hyperledger.github.io/indy-did-method/) | ✅ | ✅ | Hyperledger Indy networks. |
| `did:keri` | [DID KERI Spec](https://identity.foundation/keri/did_methods/) | ✅ | ✅ | KERI protocol. Key event receipts. |

Key capabilities:
- **Verification**: Method supports key verification for signing/authentication
- **Encryption**: Method supports key agreement for encryption
- ✅ = Supported
- ❌ = Not supported

Recommendations:
1. For **Web Services**:
   - Primary: `did:web` - Easy to control and update
   - Fallback: `did:key` - Simple and portable

2. For **Enterprise**:
   - Primary: `did:ion` - Robust and decentralized
   - Alternatives: `did:indy`, `did:sov` - Good governance

3. For **Blockchain Integration**:
   - Primary: `did:ethr` - Widely supported
   - Alternatives: `did:tz`, `did:sol` - Platform specific

4. For **Testing**:
   - Primary: `did:key` - Simple setup
   - Alternative: `did:jwk` - Direct key control

5. For **P2P Applications**:
   - Primary: `did:peer` - Purpose-built for P2P
   - Alternative: `did:key` - Simple but less flexible

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 