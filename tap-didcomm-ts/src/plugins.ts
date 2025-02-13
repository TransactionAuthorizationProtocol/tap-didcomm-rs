/**
 * Plugin interfaces for DIDComm operations.
 * @module
 */

import { Resolver } from 'did-resolver';
import type { DIDDocument, DIDCommResult, VerificationMethod } from './types';

/**
 * Interface for DID resolution.
 */
export interface DIDResolver {
  /**
   * Resolve a DID to its DID Document.
   *
   * @param did - The DID to resolve
   * @returns A promise that resolves to the DID Document
   */
  resolve(did: string): Promise<DIDCommResult<DIDDocument>>;
}

/**
 * Interface for signing operations.
 */
export interface Signer {
  /**
   * Sign a message with a private key.
   *
   * @param data - The data to sign
   * @param keyId - The ID of the key to use for signing
   * @returns A promise that resolves to the signature
   */
  sign(data: Uint8Array, keyId: string): Promise<DIDCommResult<Uint8Array>>;

  /**
   * Verify a signature.
   *
   * @param data - The original data that was signed
   * @param signature - The signature to verify
   * @param keyId - The ID of the key to use for verification
   * @returns A promise that resolves to whether the signature is valid
   */
  verify(data: Uint8Array, signature: Uint8Array, keyId: string): Promise<DIDCommResult<boolean>>;
}

/**
 * Interface for encryption operations.
 */
export interface Encryptor {
  /**
   * Encrypt data for one or more recipients.
   *
   * @param data - The data to encrypt
   * @param recipientKeys - The public keys of the recipients
   * @param senderKey - Optional sender's key for authenticated encryption
   * @returns A promise that resolves to the encrypted data
   */
  encrypt(
    data: Uint8Array,
    recipientKeys: string[],
    senderKey?: string
  ): Promise<DIDCommResult<Uint8Array>>;

  /**
   * Decrypt data.
   *
   * @param data - The encrypted data
   * @param recipientKey - The recipient's key ID
   * @returns A promise that resolves to the decrypted data
   */
  decrypt(data: Uint8Array, recipientKey: string): Promise<DIDCommResult<Uint8Array>>;
}

/**
 * Interface for a complete DIDComm plugin.
 */
export interface DIDCommPlugin {
  /** The DID resolver implementation */
  readonly resolver: DIDResolver;
  /** The signer implementation */
  readonly signer: Signer;
  /** The encryptor implementation */
  readonly encryptor: Encryptor;
}

/**
 * Default implementation of the DIDComm plugin.
 */
export class DefaultDIDCommPlugin implements DIDCommPlugin {
  private readonly didResolver: Resolver;

  constructor(methods = {}) {
    this.didResolver = new Resolver(methods);
  }

  public readonly resolver: DIDResolver = {
    resolve: async (did: string): Promise<DIDCommResult<DIDDocument>> => {
      try {
        const doc = await this.didResolver.resolve(did);
        return {
          success: true,
          data: doc.didDocument as DIDDocument,
        };
      } catch (error) {
        return {
          success: false,
          error: {
            code: 'RESOLUTION_ERROR',
            message: error instanceof Error ? error.message : 'Unknown error during DID resolution',
          },
        };
      }
    },
  };

  public readonly signer: Signer = {
    async sign(data: Uint8Array, keyId: string): Promise<DIDCommResult<Uint8Array>> {
      // Implementation will be provided by WASM module
      return {
        success: false,
        error: {
          code: 'NOT_IMPLEMENTED',
          message: 'Signing not implemented in default plugin',
        },
      };
    },

    async verify(
      data: Uint8Array,
      signature: Uint8Array,
      keyId: string
    ): Promise<DIDCommResult<boolean>> {
      // Implementation will be provided by WASM module
      return {
        success: false,
        error: {
          code: 'NOT_IMPLEMENTED',
          message: 'Verification not implemented in default plugin',
        },
      };
    },
  };

  public readonly encryptor: Encryptor = {
    async encrypt(
      data: Uint8Array,
      recipientKeys: string[],
      senderKey?: string
    ): Promise<DIDCommResult<Uint8Array>> {
      // Implementation will be provided by WASM module
      return {
        success: false,
        error: {
          code: 'NOT_IMPLEMENTED',
          message: 'Encryption not implemented in default plugin',
        },
      };
    },

    async decrypt(data: Uint8Array, recipientKey: string): Promise<DIDCommResult<Uint8Array>> {
      // Implementation will be provided by WASM module
      return {
        success: false,
        error: {
          code: 'NOT_IMPLEMENTED',
          message: 'Decryption not implemented in default plugin',
        },
      };
    },
  };
}

/**
 * Mock implementation of the DIDComm plugin for testing.
 */
export class MockDIDCommPlugin implements DIDCommPlugin {
  private readonly mockKeyStore: Map<string, Uint8Array>;

  constructor() {
    this.mockKeyStore = new Map();
    // Initialize with some mock keys
    this.mockKeyStore.set('did:example:123#key-1', new Uint8Array([1, 2, 3, 4]));
    this.mockKeyStore.set('did:example:456#key-1', new Uint8Array([5, 6, 7, 8]));
  }

  public readonly resolver: DIDResolver = {
    resolve: async (did: string): Promise<DIDCommResult<DIDDocument>> => {
      if (!did || !did.startsWith('did:')) {
        return {
          success: false,
          error: {
            code: 'INVALID_DID',
            message: 'Invalid DID format',
          },
        };
      }

      // Return a mock DID document
      return {
        success: true,
        data: {
          id: did,
          verificationMethod: [
            {
              id: `${did}#key-1`,
              type: 'Ed25519VerificationKey2020',
              controller: did,
              publicKeyMultibase: 'mock-key',
            } as VerificationMethod,
          ],
          authentication: [`${did}#key-1`],
          assertionMethod: [`${did}#key-1`],
          keyAgreement: [`${did}#key-1`],
        },
      };
    },
  };

  public readonly signer: Signer = {
    sign: async (data: Uint8Array, keyId: string): Promise<DIDCommResult<Uint8Array>> => {
      const key = this.mockKeyStore.get(keyId);
      if (!key) {
        return {
          success: false,
          error: {
            code: 'KEY_NOT_FOUND',
            message: `Key ${keyId} not found`,
          },
        };
      }

      // Mock signature by concatenating data with key
      const signature = new Uint8Array(data.length + key.length);
      signature.set(data);
      signature.set(key, data.length);

      return {
        success: true,
        data: signature,
      };
    },

    verify: async (
      data: Uint8Array,
      signature: Uint8Array,
      keyId: string
    ): Promise<DIDCommResult<boolean>> => {
      const key = this.mockKeyStore.get(keyId);
      if (!key) {
        return {
          success: false,
          error: {
            code: 'KEY_NOT_FOUND',
            message: `Key ${keyId} not found`,
          },
        };
      }

      // Mock verification by checking if signature ends with key
      const expectedSignature = new Uint8Array(data.length + key.length);
      expectedSignature.set(data);
      expectedSignature.set(key, data.length);

      return {
        success: true,
        data: signature.every((byte, i) => byte === expectedSignature[i]),
      };
    },
  };

  public readonly encryptor: Encryptor = {
    async encrypt(
      data: Uint8Array,
      recipientKeys: string[],
      senderKey?: string
    ): Promise<DIDCommResult<Uint8Array>> {
      if (!recipientKeys.length) {
        return {
          success: false,
          error: {
            code: 'NO_RECIPIENTS',
            message: 'No recipient keys provided',
          },
        };
      }

      // Mock encryption by XORing with a fixed key
      const mockKey = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
      const encrypted = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i++) {
        encrypted[i] = data[i] ^ mockKey[i % mockKey.length];
      }

      return {
        success: true,
        data: encrypted,
      };
    },

    async decrypt(data: Uint8Array, recipientKey: string): Promise<DIDCommResult<Uint8Array>> {
      // Mock decryption by XORing with the same fixed key
      const mockKey = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
      const decrypted = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i++) {
        decrypted[i] = data[i] ^ mockKey[i % mockKey.length];
      }

      return {
        success: true,
        data: decrypted,
      };
    },
  };
}
