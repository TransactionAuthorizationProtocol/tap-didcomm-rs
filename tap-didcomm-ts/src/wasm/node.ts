import type { NodeWasmModule } from './types';

/**
 * Node.js-specific WASM module for DIDComm operations.
 */
const nodeModule: NodeWasmModule = {
  memory: new WebAssembly.Memory({ initial: 16, maximum: 100 }),

  async initialize(memory: WebAssembly.Memory): Promise<void> {
    this.memory = memory;
  },

  async encrypt(message: string, recipients: string[]): Promise<string> {
    if (!this.memory) {
      throw new Error('Module not initialized');
    }
    // Mock encryption - base64 encode for testing
    return Buffer.from(message).toString('base64');
  },

  async decrypt(message: string, key: string): Promise<string> {
    if (!this.memory) {
      throw new Error('Module not initialized');
    }
    // Mock decryption - base64 decode for testing
    return Buffer.from(message, 'base64').toString();
  },

  async sign(message: string, key: string): Promise<string> {
    if (!this.memory) {
      throw new Error('Module not initialized');
    }
    // Mock signing - append a test signature
    return `${message}.sig`;
  },

  async verify(message: string, key: string): Promise<boolean> {
    if (!this.memory) {
      throw new Error('Module not initialized');
    }
    // Mock verification - check for .sig suffix
    return message.endsWith('.sig');
  },

  async resolveIdentifier(did: string): Promise<string> {
    if (!this.memory) {
      throw new Error('Module not initialized');
    }
    // Mock DID resolution - return a simple DID document
    return JSON.stringify({
      id: did,
      verificationMethod: [
        {
          id: `${did}#key-1`,
          type: 'Ed25519VerificationKey2020',
          controller: did,
          publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        },
      ],
    });
  },
};

export default nodeModule;
