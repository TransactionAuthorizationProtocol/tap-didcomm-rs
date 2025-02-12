/**
 * Plugin interfaces for DIDComm operations.
 * @module
 */

import { Resolver } from "did-resolver";
import type { DIDDocument, DIDCommResult } from "./types";

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
  verify(
    data: Uint8Array,
    signature: Uint8Array,
    keyId: string,
  ): Promise<DIDCommResult<boolean>>;
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
    senderKey?: string,
  ): Promise<DIDCommResult<Uint8Array>>;

  /**
   * Decrypt data.
   *
   * @param data - The encrypted data
   * @param recipientKey - The recipient's key ID
   * @returns A promise that resolves to the decrypted data
   */
  decrypt(
    data: Uint8Array,
    recipientKey: string,
  ): Promise<DIDCommResult<Uint8Array>>;
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
            code: "RESOLUTION_ERROR",
            message:
              error instanceof Error
                ? error.message
                : "Unknown error during DID resolution",
          },
        };
      }
    },
  };

  public readonly signer: Signer = {
    async sign(
      data: Uint8Array,
      keyId: string,
    ): Promise<DIDCommResult<Uint8Array>> {
      // Implementation will be provided by WASM module
      return {
        success: false,
        error: {
          code: "NOT_IMPLEMENTED",
          message: "Signing not implemented in default plugin",
        },
      };
    },

    async verify(
      data: Uint8Array,
      signature: Uint8Array,
      keyId: string,
    ): Promise<DIDCommResult<boolean>> {
      // Implementation will be provided by WASM module
      return {
        success: false,
        error: {
          code: "NOT_IMPLEMENTED",
          message: "Verification not implemented in default plugin",
        },
      };
    },
  };

  public readonly encryptor: Encryptor = {
    async encrypt(
      data: Uint8Array,
      recipientKeys: string[],
      senderKey?: string,
    ): Promise<DIDCommResult<Uint8Array>> {
      // Implementation will be provided by WASM module
      return {
        success: false,
        error: {
          code: "NOT_IMPLEMENTED",
          message: "Encryption not implemented in default plugin",
        },
      };
    },

    async decrypt(
      data: Uint8Array,
      recipientKey: string,
    ): Promise<DIDCommResult<Uint8Array>> {
      // Implementation will be provided by WASM module
      return {
        success: false,
        error: {
          code: "NOT_IMPLEMENTED",
          message: "Decryption not implemented in default plugin",
        },
      };
    },
  };
}
