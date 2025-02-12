import { PackingType } from "./types";
import type {
  DIDCommConfig,
  DIDCommResult,
  Message,
  EncryptOptions,
  SignOptions,
  DecryptOptions,
  DIDDocument,
} from "./types";
import type { DIDCommPlugin } from "./plugins";

/**
 * Main client for DIDComm operations.
 * Handles message encryption, decryption, signing, and verification.
 */
export class DIDCommClient {
  private readonly config: DIDCommConfig;
  private readonly plugin: DIDCommPlugin;
  private initialized = false;

  /**
   * Create a new DIDComm client.
   *
   * @param config - Configuration options
   * @param plugin - Plugin implementation for cryptographic operations
   */
  constructor(config: DIDCommConfig, plugin: DIDCommPlugin) {
    this.config = {
      maxMessageSize: 1024 * 1024, // 1MB default
      useHttps: true,
      ...config,
    };
    this.plugin = plugin;
  }

  /**
   * Initialize the client.
   * This must be called before using any other methods.
   */
  public async initialize(): Promise<DIDCommResult<void>> {
    try {
      // Verify plugin functionality
      const testDid = "did:example:test";
      const resolveResult = await this.plugin.resolver.resolve(testDid);

      if (!resolveResult.success) {
        return {
          success: false,
          error: {
            code: "PLUGIN_ERROR",
            message: "DID resolver plugin failed initialization check",
          },
        };
      }

      this.initialized = true;
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: {
          code: "INITIALIZATION_ERROR",
          message:
            error instanceof Error
              ? error.message
              : "Unknown error during initialization",
        },
      };
    }
  }

  /**
   * Resolve a DID to its DID Document.
   *
   * @param did - The DID to resolve
   * @returns A promise that resolves to the DID Document
   */
  public async resolve(did: string): Promise<DIDCommResult<DIDDocument>> {
    if (!this.initialized) {
      return {
        success: false,
        error: {
          code: "NOT_INITIALIZED",
          message: "Client must be initialized before use",
        },
      };
    }

    try {
      return await this.plugin.resolver.resolve(did);
    } catch (error) {
      return {
        success: false,
        error: {
          code: "RESOLUTION_ERROR",
          message:
            error instanceof Error ? error.message : "Unknown resolution error",
        },
      };
    }
  }

  /**
   * Encrypt a message for one or more recipients.
   *
   * @param message - The message to encrypt
   * @param options - Encryption options
   */
  public async encrypt(
    message: Message,
    options: EncryptOptions,
  ): Promise<DIDCommResult<Uint8Array>> {
    if (!this.initialized) {
      return {
        success: false,
        error: {
          code: "NOT_INITIALIZED",
          message: "Client must be initialized before use",
        },
      };
    }

    try {
      // Resolve recipient DIDs
      const recipientDocs = await Promise.all(
        options.to.map((did) => this.plugin.resolver.resolve(did)),
      );

      const recipientKeys = recipientDocs.flatMap((result) => {
        if (!result.success || !result.data) return [];
        return result.data.keyAgreement ?? [];
      });

      if (recipientKeys.length === 0) {
        return {
          success: false,
          error: {
            code: "NO_RECIPIENT_KEYS",
            message: "No valid recipient keys found",
          },
        };
      }

      // If authcrypt, resolve sender DID
      let senderKey: string | undefined;
      if (options.packing === PackingType.AUTHCRYPT && options.from) {
        const senderDoc = await this.plugin.resolver.resolve(options.from);
        if (!senderDoc.success || !senderDoc.data?.keyAgreement?.[0]) {
          return {
            success: false,
            error: {
              code: "NO_SENDER_KEY",
              message: "No valid sender key found for authenticated encryption",
            },
          };
        }
        senderKey = senderDoc.data.keyAgreement[0];
      }

      // Serialize message
      const messageBytes = new TextEncoder().encode(JSON.stringify(message));

      // Sign if requested
      let dataToEncrypt = messageBytes;
      if (options.sign && options.from) {
        const signResult = await this.sign(message, { from: options.from });
        if (!signResult.success) {
          return signResult;
        }
        dataToEncrypt = signResult.data!;
      }

      // Encrypt
      return await this.plugin.encryptor.encrypt(
        dataToEncrypt,
        recipientKeys,
        senderKey,
      );
    } catch (error) {
      return {
        success: false,
        error: {
          code: "ENCRYPTION_ERROR",
          message:
            error instanceof Error ? error.message : "Unknown encryption error",
        },
      };
    }
  }

  /**
   * Decrypt an encrypted message.
   *
   * @param data - The encrypted data
   * @param options - Decryption options
   */
  public async decrypt(
    data: Uint8Array,
    options: DecryptOptions,
  ): Promise<DIDCommResult<Message>> {
    if (!this.initialized) {
      return {
        success: false,
        error: {
          code: "NOT_INITIALIZED",
          message: "Client must be initialized before use",
        },
      };
    }

    try {
      // Decrypt the message
      const decrypted = await this.plugin.encryptor.decrypt(
        data,
        options.recipient ?? "",
      );

      if (!decrypted.success || !decrypted.data) {
        return {
          success: false,
          error: {
            code: "DECRYPTION_ERROR",
            message: "Failed to decrypt message",
          },
        };
      }

      // Parse the decrypted message
      const messageStr = new TextDecoder().decode(decrypted.data);
      const message = JSON.parse(messageStr) as Message;

      return { success: true, data: message };
    } catch (error) {
      return {
        success: false,
        error: {
          code: "DECRYPTION_ERROR",
          message:
            error instanceof Error ? error.message : "Unknown decryption error",
        },
      };
    }
  }

  /**
   * Sign a message.
   *
   * @param message - The message to sign
   * @param options - Signing options
   */
  public async sign(
    message: Message,
    options: SignOptions,
  ): Promise<DIDCommResult<Uint8Array>> {
    if (!this.initialized) {
      return {
        success: false,
        error: {
          code: "NOT_INITIALIZED",
          message: "Client must be initialized before use",
        },
      };
    }

    try {
      // Resolve signer DID
      const signerDoc = await this.plugin.resolver.resolve(options.from);
      if (!signerDoc.success || !signerDoc.data?.verificationMethod?.[0]) {
        return {
          success: false,
          error: {
            code: "NO_SIGNING_KEY",
            message: "No valid signing key found",
          },
        };
      }

      const signingKeyId = signerDoc.data.verificationMethod[0].id;
      const messageBytes = new TextEncoder().encode(JSON.stringify(message));

      return await this.plugin.signer.sign(messageBytes, signingKeyId);
    } catch (error) {
      return {
        success: false,
        error: {
          code: "SIGNING_ERROR",
          message:
            error instanceof Error ? error.message : "Unknown signing error",
        },
      };
    }
  }

  /**
   * Verify a signature.
   *
   * @param data - The original data that was signed
   * @param signature - The signature to verify
   * @param keyId - The ID of the key to use for verification
   */
  public async verify(
    data: Uint8Array,
    signature: Uint8Array,
    keyId: string,
  ): Promise<DIDCommResult<boolean>> {
    if (!this.initialized) {
      return {
        success: false,
        error: {
          code: "NOT_INITIALIZED",
          message: "Client must be initialized before use",
        },
      };
    }

    try {
      return await this.plugin.signer.verify(data, signature, keyId);
    } catch (error) {
      return {
        success: false,
        error: {
          code: "VERIFICATION_ERROR",
          message:
            error instanceof Error
              ? error.message
              : "Unknown verification error",
        },
      };
    }
  }
}
