import type { CoreWasmModule } from './types';

/**
 * Core WASM module for DIDComm operations.
 */
const coreModule: CoreWasmModule = {
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
};

export default coreModule;
