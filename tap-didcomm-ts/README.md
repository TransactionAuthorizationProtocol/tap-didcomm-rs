# TAP DIDComm TypeScript

A TypeScript implementation of the DIDComm v2 protocol with WASM support.

## Features

- 🔒 **Secure Messaging**: Full support for DIDComm v2 encrypted messaging
- 🌐 **Cross-Platform**: Works in both Node.js and browser environments
- ⚡ **WASM-Powered**: High-performance cryptographic operations using WebAssembly
- 🔌 **Plugin System**: Extensible architecture for custom DID resolution and cryptographic operations
- 📦 **Modern Package**: Built with TypeScript, offering full type safety
- 🧪 **Well-Tested**: Comprehensive test suite covering both Node.js and browser environments

## Installation

```bash
# Using pnpm (recommended)
pnpm add tap-didcomm-ts

# Using npm
npm install tap-didcomm-ts

# Using yarn
yarn add tap-didcomm-ts
```

## Quick Start

```typescript
import { DIDCommClient, DefaultDIDCommPlugin, PackingType } from 'tap-didcomm-ts';

async function main() {
  // Initialize the client
  const client = new DIDCommClient(
    {
      defaultPacking: PackingType.ANONCRYPT,
      useHttps: true,
    },
    new DefaultDIDCommPlugin()
  );

  // Initialize WASM (required before any operations)
  await client.initialize();

  // Create a message
  const message = {
    id: `msg-${Date.now()}`,
    type: 'example/1.0',
    body: { text: 'Hello, DIDComm!' },
  };

  // Encrypt the message
  const encrypted = await client.encrypt(message, {
    to: ['did:example:recipient'],
    from: 'did:example:sender',
    packing: PackingType.AUTHCRYPT,
  });

  // Decrypt the message
  const decrypted = await client.decrypt(encrypted.data!, {
    recipient: 'did:example:recipient',
  });

  console.log('Decrypted message:', decrypted.data);
}

main().catch(console.error);
```

## Architecture

The package is structured into several key components:

- **Core Client**: The main `DIDCommClient` class handling message operations
- **Plugin System**: Interfaces for DID resolution, signing, and encryption
- **WASM Integration**: WebAssembly modules for cryptographic operations
- **Types**: Comprehensive TypeScript type definitions

### Plugin System

The package uses a plugin-based architecture for extensibility:

```typescript
interface DIDCommPlugin {
  readonly resolver: DIDResolver;
  readonly signer: Signer;
  readonly encryptor: Encryptor;
}
```

You can implement custom plugins by implementing these interfaces:

```typescript
class CustomPlugin implements DIDCommPlugin {
  // Implement resolver, signer, and encryptor
}
```

## API Reference

### DIDCommClient

The main client class for DIDComm operations.

```typescript
class DIDCommClient {
  constructor(config: DIDCommConfig, plugin: DIDCommPlugin);
  
  async initialize(): Promise<DIDCommResult<void>>;
  async encrypt(message: Message, options: EncryptOptions): Promise<DIDCommResult<Uint8Array>>;
  async decrypt(data: Uint8Array, options: DecryptOptions): Promise<DIDCommResult<Message>>;
  async sign(message: Message, options: SignOptions): Promise<DIDCommResult<Uint8Array>>;
  async verify(data: Uint8Array, signature: Uint8Array, keyId: string): Promise<DIDCommResult<boolean>>;
}
```

### Message Types

```typescript
interface Message {
  id: string;
  type: string;
  body: Record<string, unknown>;
  from?: string;
  to?: string[];
  created_time?: number;
  expires_time?: number;
  attachments?: Attachment[];
}
```

### Configuration

```typescript
interface DIDCommConfig {
  defaultPacking: PackingType;
  maxMessageSize?: number;
  useHttps?: boolean;
  headers?: Record<string, string>;
}
```

## Browser Support

The package supports all modern browsers with WebAssembly capabilities:

- Chrome/Edge (v79+)
- Firefox (v72+)
- Safari (v13.1+)
- Node.js (v18+)

## Development

```bash
# Install dependencies
pnpm install

# Build WASM modules
pnpm run build:wasm

# Build TypeScript
pnpm run build

# Run tests
pnpm test          # Unit tests
pnpm test:browser  # Browser tests
pnpm test:coverage # Coverage report
```

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

This package implements the DIDComm v2 specification with a focus on security. However, it should be noted that:

- The implementation is currently in beta
- A security audit is pending
- Use in production systems should be carefully evaluated

Please report security issues via our [security policy](SECURITY.md).

## License

MIT License - see [LICENSE](LICENSE) for details. 