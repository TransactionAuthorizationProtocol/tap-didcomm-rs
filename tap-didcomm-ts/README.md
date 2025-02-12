# TAP DIDComm TypeScript

TypeScript wrapper for the TAP DIDComm implementation with WASM support. This package provides a high-level API for DIDComm v2 operations in both Node.js and browser environments.

## Features

- Full DIDComm v2 support
- Cross-platform (Node.js and browser)
- WebAssembly-powered cryptographic operations
- Pluggable architecture for DID resolution, signing, and encryption
- TypeScript types and documentation
- Comprehensive test suite
- Memory-efficient WASM loading

## Installation

```bash
npm install tap-didcomm-ts
# or
pnpm add tap-didcomm-ts
# or
yarn add tap-didcomm-ts
```

## Quick Start

```typescript
import { DIDCommClient, DefaultDIDCommPlugin, PackingType } from 'tap-didcomm-ts';

async function main() {
  // Create a client with default configuration
  const client = new DIDCommClient({
    defaultPacking: PackingType.ANONCRYPT,
    useHttps: true
  }, new DefaultDIDCommPlugin());

  // Initialize WASM module
  await client.initialize();

  // Create a message
  const message = {
    id: 'example-1',
    type: 'example/1.0',
    body: { hello: 'world' }
  };

  // Encrypt message
  const encrypted = await client.encrypt(message, {
    to: ['did:example:recipient'],
    from: 'did:example:sender'
  });

  // Decrypt message
  const decrypted = await client.decrypt(encrypted.data, {
    recipient: 'did:example:recipient'
  });

  console.log(decrypted.data);
}

main().catch(console.error);
```

## API Reference

### DIDCommClient

The main client for DIDComm operations.

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

### Plugin System

The package uses a plugin system for extensibility:

```typescript
interface DIDCommPlugin {
  readonly resolver: DIDResolver;
  readonly signer: Signer;
  readonly encryptor: Encryptor;
}

interface DIDResolver {
  resolve(did: string): Promise<DIDCommResult<DIDDocument>>;
}

interface Signer {
  sign(data: Uint8Array, keyId: string): Promise<DIDCommResult<Uint8Array>>;
  verify(data: Uint8Array, signature: Uint8Array, keyId: string): Promise<DIDCommResult<boolean>>;
}

interface Encryptor {
  encrypt(data: Uint8Array, recipientKeys: string[], senderKey?: string): Promise<DIDCommResult<Uint8Array>>;
  decrypt(data: Uint8Array, recipientKey: string): Promise<DIDCommResult<Uint8Array>>;
}
```

## Browser Support

The package supports modern browsers through WASM. For optimal performance, the WASM module is loaded dynamically:

```typescript
import { DIDCommClient, detectEnvironment } from 'tap-didcomm-ts';

const env = detectEnvironment();
const client = new DIDCommClient({
  wasmUrl: env.isBrowser ? '/path/to/didcomm_core.wasm' : undefined
});
```

## Node.js Support

In Node.js environments, the package automatically uses Node-optimized WASM bindings:

```typescript
import { DIDCommClient } from 'tap-didcomm-ts';

const client = new DIDCommClient({
  useNode: true // Enable Node.js optimizations
});
```

## Security Considerations

- The package uses WebAssembly for cryptographic operations
- All cryptographic material is zeroized after use
- Memory is managed efficiently to prevent leaks
- Input validation is performed on all messages
- Error handling preserves security properties

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes. 