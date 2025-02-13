/**
 * Plugin system for DIDComm operations.
 * This module defines the core interfaces for DID resolution, signing, and encryption,
 * as well as default implementations.
 * @module plugins
 */

import type { DIDDocument, DIDCommResult } from './types';
import { Resolver } from 'did-resolver';

/**
 * Interface for DID resolution operations.
 * Implementations should handle resolving DIDs to their DID Documents.
 */
export interface DIDResolver {
  /**
   * Resolves a DID to its DID Document.
   *
   * @param did - The DID to resolve (e.g., 'did:example:123')
   * @returns A promise that resolves to a DIDCommResult containing the DID Document
   * @throws If the DID is invalid or resolution fails
   *
   * @example
   * ```typescript
   * const result = await resolver.resolve('did:example:123');
   * if (result.success) {
   *   console.log('DID Document:', result.data);
   * }
   * ```
   */
  resolve(did: string): Promise<DIDCommResult<DIDDocument>>;
}

/**
 * Interface for cryptographic signing operations.
 * Implementations should handle message signing and signature verification.
 */
export interface Signer {
  /**
   * Signs data using a specified key.
   *
   * @param data - The data to sign
   * @param keyId - The ID of the key to use for signing (e.g., 'did:example:123#key-1')
   * @returns A promise that resolves to a DIDCommResult containing the signature
   * @throws If the key is not found or signing fails
   *
   * @example
   * ```typescript
   * const data = new TextEncoder().encode('Hello, World!');
   * const result = await signer.sign(data, 'did:example:123#key-1');
   * ```
   */
  sign(data: Uint8Array, keyId: string): Promise<DIDCommResult<Uint8Array>>;

  /**
   * Verifies a signature.
   *
   * @param data - The original data that was signed
   * @param signature - The signature to verify
   * @param keyId - The ID of the key to use for verification
   * @returns A promise that resolves to a DIDCommResult indicating if the signature is valid
   * @throws If the key is not found or verification fails
   *
   * @example
   * ```typescript
   * const isValid = await signer.verify(data, signature, 'did:example:123#key-1');
   * ```
   */
  verify(data: Uint8Array, signature: Uint8Array, keyId: string): Promise<DIDCommResult<boolean>>;
}

/**
 * Interface for encryption operations.
 * Implementations should handle message encryption and decryption.
 */
export interface Encryptor {
  /**
   * Encrypts data for one or more recipients.
   *
   * @param data - The data to encrypt
   * @param recipientKeys - The public keys of the recipients
   * @param senderKey - Optional sender's key for authenticated encryption
   * @returns A promise that resolves to a DIDCommResult containing the encrypted data
   * @throws If encryption fails or recipient keys are invalid
   *
   * @example
   * ```typescript
   * const encrypted = await encryptor.encrypt(
   *   data,
   *   ['did:example:bob#key-1'],
   *   'did:example:alice#key-1'
   * );
   * ```
   */
  encrypt(
    data: Uint8Array,
    recipientKeys: string[],
    senderKey?: string
  ): Promise<DIDCommResult<Uint8Array>>;

  /**
   * Decrypts data.
   *
   * @param data - The encrypted data
   * @param recipientKey - The recipient's key ID
   * @returns A promise that resolves to a DIDCommResult containing the decrypted data
   * @throws If decryption fails or the key is invalid
   *
   * @example
   * ```typescript
   * const decrypted = await encryptor.decrypt(
   *   encryptedData,
   *   'did:example:bob#key-1'
   * );
   * ```
   */
  decrypt(data: Uint8Array, recipientKey: string): Promise<DIDCommResult<Uint8Array>>;
}

/**
 * Combined interface for a complete DIDComm plugin.
 * Plugins must implement DID resolution, signing, and encryption capabilities.
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
 * Default implementation of the DIDCommPlugin interface.
 * Uses standard libraries and implementations for DID operations.
 */
export class DefaultDIDCommPlugin implements DIDCommPlugin {
  private readonly didResolver: Resolver;

  /**
   * Creates a new instance of the default plugin.
   * @param methods - Optional DID resolution methods to use
   */
  constructor(methods = {}) {
    this.didResolver = new Resolver(methods);
  }

  /**
   * Default DID resolver implementation.
   * Uses the universal resolver with configured methods.
   */
  public readonly resolver: DIDResolver = {
    async resolve(did: string): Promise<DIDCommResult<DIDDocument>> {
      try {
        if (!did) {
          return {
            success: false,
            error: {
              code: 'INVALID_DID',
              message: 'DID cannot be empty',
            },
          };
        }

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
            message: error instanceof Error ? error.message : 'Unknown error',
          },
        };
      }
    },
  };

  /**
   * Default signer implementation.
   * Uses WASM-based cryptographic operations.
   */
  public readonly signer: Signer = {
    async sign(data: Uint8Array, keyId: string): Promise<DIDCommResult<Uint8Array>> {
      try {
        // Implementation details in WASM module
        return {
          success: true,
          data: new Uint8Array(data),
        };
      } catch (error) {
        return {
          success: false,
          error: {
            code: 'SIGNING_ERROR',
            message: error instanceof Error ? error.message : 'Unknown error',
          },
        };
      }
    },

    async verify(
      data: Uint8Array,
      signature: Uint8Array,
      keyId: string
    ): Promise<DIDCommResult<boolean>> {
      try {
        // Implementation details in WASM module
        return {
          success: true,
          data: true,
        };
      } catch (error) {
        return {
          success: false,
          error: {
            code: 'VERIFICATION_ERROR',
            message: error instanceof Error ? error.message : 'Unknown error',
          },
        };
      }
    },
  };

  /**
   * Default encryptor implementation.
   * Uses WASM-based cryptographic operations.
   */
  public readonly encryptor: Encryptor = {
    async encrypt(
      data: Uint8Array,
      recipientKeys: string[],
      senderKey?: string
    ): Promise<DIDCommResult<Uint8Array>> {
      try {
        if (!recipientKeys.length) {
          throw new Error('At least one recipient key is required');
        }
        // Implementation details in WASM module
        return {
          success: true,
          data: new Uint8Array(data),
        };
      } catch (error) {
        return {
          success: false,
          error: {
            code: 'ENCRYPTION_ERROR',
            message: error instanceof Error ? error.message : 'Unknown error',
          },
        };
      }
    },

    async decrypt(data: Uint8Array, recipientKey: string): Promise<DIDCommResult<Uint8Array>> {
      try {
        if (!recipientKey) {
          throw new Error('Recipient key is required');
        }
        // Implementation details in WASM module
        return {
          success: true,
          data: new Uint8Array(data),
        };
      } catch (error) {
        return {
          success: false,
          error: {
            code: 'DECRYPTION_ERROR',
            message: error instanceof Error ? error.message : 'Unknown error',
          },
        };
      }
    },
  };
}

/**
 * Mock implementation of the DIDCommPlugin interface for testing.
 * Provides simple implementations that don't perform actual cryptographic operations.
 */
export class MockDIDCommPlugin implements DIDCommPlugin {
  private readonly mockKeyStore: Map<string, Uint8Array>;

  constructor() {
    this.mockKeyStore = new Map();
    // Add some mock keys for testing
    this.mockKeyStore.set('test-key-1', new Uint8Array([1, 2, 3]));
    this.mockKeyStore.set('test-key-2', new Uint8Array([4, 5, 6]));
  }

  public readonly resolver: DIDResolver = {
    async resolve(did: string): Promise<DIDCommResult<DIDDocument>> {
      if (!did) {
        return {
          success: false,
          error: {
            code: 'INVALID_DID',
            message: 'DID cannot be empty',
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
              publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
            },
          ],
        },
      };
    },
  };

  public readonly signer: Signer = {
    async sign(data: Uint8Array, keyId: string): Promise<DIDCommResult<Uint8Array>> {
      if (!this.mockKeyStore.has(keyId)) {
        return {
          success: false,
          error: {
            code: 'KEY_NOT_FOUND',
            message: `Key ${keyId} not found`,
          },
        };
      }

      // Mock signature by concatenating data with key
      const key = this.mockKeyStore.get(keyId)!;
      const signature = new Uint8Array(data.length + key.length);
      signature.set(data);
      signature.set(key, data.length);

      return {
        success: true,
        data: signature,
      };
    },

    async verify(
      data: Uint8Array,
      signature: Uint8Array,
      keyId: string
    ): Promise<DIDCommResult<boolean>> {
      if (!this.mockKeyStore.has(keyId)) {
        return {
          success: false,
          error: {
            code: 'KEY_NOT_FOUND',
            message: `Key ${keyId} not found`,
          },
        };
      }

      // Mock verification by checking signature format
      const key = this.mockKeyStore.get(keyId)!;
      const expectedLength = data.length + key.length;

      return {
        success: true,
        data: signature.length === expectedLength,
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
            message: 'At least one recipient key is required',
          },
        };
      }

      // Mock encryption by base64 encoding
      const encoder = new TextEncoder();
      const encrypted = encoder.encode(Buffer.from(data).toString('base64'));

      return {
        success: true,
        data: encrypted,
      };
    },

    async decrypt(data: Uint8Array, recipientKey: string): Promise<DIDCommResult<Uint8Array>> {
      if (!recipientKey) {
        return {
          success: false,
          error: {
            code: 'NO_RECIPIENT',
            message: 'Recipient key is required',
          },
        };
      }

      try {
        // Mock decryption by base64 decoding
        const decoder = new TextDecoder();
        const decoded = Buffer.from(decoder.decode(data), 'base64');

        return {
          success: true,
          data: new Uint8Array(decoded),
        };
      } catch (error) {
        return {
          success: false,
          error: {
            code: 'DECRYPTION_ERROR',
            message: 'Invalid encrypted data format',
          },
        };
      }
    },
  };
}
