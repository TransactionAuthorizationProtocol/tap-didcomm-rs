import type { Signer, Encryptor, DIDCommResult } from '../../src';

interface SignedMessage {
  signature: string;
  keyId: string;
  [key: string]: unknown;
}

interface EncryptedMessage {
  ciphertext: string;
  recipients: string[];
}

/**
 * Example custom signer that uses a simple key-value store for private keys
 */
export class CustomSigner implements Signer {
  private keys: Map<string, Uint8Array>;

  constructor() {
    this.keys = new Map();
    // Initialize with some example keys (in a real implementation, these would be secure private keys)
    this.keys.set('did:example:sender#key-1', new Uint8Array([1, 2, 3, 4]));
    this.keys.set('did:example:recipient#key-1', new Uint8Array([5, 6, 7, 8]));
  }

  /**
   * Signs a message using the private key associated with the given key ID
   */
  async sign(data: Uint8Array, keyId: string): Promise<DIDCommResult<Uint8Array>> {
    try {
      const privateKey = this.keys.get(keyId);
      if (!privateKey) {
        return {
          success: false,
          error: {
            code: 'KEY_NOT_FOUND',
            message: `Key not found: ${keyId}`,
          },
        };
      }

      // Mock signature by concatenating data with key
      const signature = new Uint8Array(data.length + privateKey.length);
      signature.set(data);
      signature.set(privateKey, data.length);

      return {
        success: true,
        data: signature,
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'SIGNING_ERROR',
          message: error instanceof Error ? error.message : 'Unknown error occurred',
        },
      };
    }
  }

  /**
   * Verifies a signed message
   */
  async verify(
    data: Uint8Array,
    signature: Uint8Array,
    keyId: string
  ): Promise<DIDCommResult<boolean>> {
    try {
      const privateKey = this.keys.get(keyId);
      if (!privateKey) {
        return {
          success: false,
          error: {
            code: 'KEY_NOT_FOUND',
            message: `Key not found: ${keyId}`,
          },
        };
      }

      // Mock verification by checking if signature ends with key
      const expectedSignature = new Uint8Array(data.length + privateKey.length);
      expectedSignature.set(data);
      expectedSignature.set(privateKey, data.length);

      return {
        success: true,
        data: signature.every((byte, i) => byte === expectedSignature[i]),
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'VERIFICATION_ERROR',
          message: error instanceof Error ? error.message : 'Unknown error occurred',
        },
      };
    }
  }

  /**
   * Checks if this signer supports the given key ID
   */
  supports(keyId: string): boolean {
    return this.keys.has(keyId);
  }
}

/**
 * Example custom encryptor that uses a simple mock encryption scheme
 */
export class CustomEncryptor implements Encryptor {
  private keys: Map<string, Uint8Array>;

  constructor() {
    this.keys = new Map();
    // Initialize with some example keys (in a real implementation, these would be secure encryption keys)
    this.keys.set('did:example:sender#key-2', new Uint8Array([9, 10, 11, 12]));
    this.keys.set('did:example:recipient#key-2', new Uint8Array([13, 14, 15, 16]));
  }

  /**
   * Encrypts a message for the specified recipients
   */
  async encrypt(
    data: Uint8Array,
    recipientKeys: string[],
    senderKey?: string
  ): Promise<DIDCommResult<Uint8Array>> {
    try {
      // Verify we have all recipient keys
      for (const keyId of recipientKeys) {
        if (!this.keys.has(keyId)) {
          return {
            success: false,
            error: {
              code: 'KEY_NOT_FOUND',
              message: `Key not found: ${keyId}`,
            },
          };
        }
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
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'ENCRYPTION_ERROR',
          message: error instanceof Error ? error.message : 'Unknown error occurred',
        },
      };
    }
  }

  /**
   * Decrypts a message using the specified recipient key
   */
  async decrypt(data: Uint8Array, recipientKey: string): Promise<DIDCommResult<Uint8Array>> {
    try {
      if (!this.keys.has(recipientKey)) {
        return {
          success: false,
          error: {
            code: 'KEY_NOT_FOUND',
            message: `Key not found: ${recipientKey}`,
          },
        };
      }

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
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'DECRYPTION_ERROR',
          message: error instanceof Error ? error.message : 'Unknown error occurred',
        },
      };
    }
  }

  /**
   * Checks if this encryptor supports the given key ID
   */
  supports(keyId: string): boolean {
    return this.keys.has(keyId);
  }
}

/**
 * Example usage of the custom plugins
 */
async function example() {
  const signer = new CustomSigner();
  const encryptor = new CustomEncryptor();

  // Test message
  const message = new TextEncoder().encode('Hello from custom plugins!');

  // Test signing
  console.log('Testing signing...');
  const signResult = await signer.sign(message, 'did:example:sender#key-1');
  if (signResult.success && signResult.data) {
    console.log('Successfully signed message:');
    console.log('Signature:', Buffer.from(signResult.data).toString('base64'));

    // Test verification
    console.log('\nVerifying signature...');
    const verifyResult = await signer.verify(message, signResult.data, 'did:example:sender#key-1');
    if (verifyResult.success) {
      console.log('Signature verification:', verifyResult.data ? 'Valid' : 'Invalid');
    }
  }

  // Test encryption
  console.log('\nTesting encryption...');
  const encryptResult = await encryptor.encrypt(message, ['did:example:recipient#key-2']);
  if (encryptResult.success && encryptResult.data) {
    console.log('Successfully encrypted message:');
    console.log('Encrypted:', Buffer.from(encryptResult.data).toString('base64'));

    // Test decryption
    console.log('\nDecrypting message...');
    const decryptResult = await encryptor.decrypt(
      encryptResult.data,
      'did:example:recipient#key-2'
    );
    if (decryptResult.success && decryptResult.data) {
      console.log('Successfully decrypted message:');
      console.log('Decrypted:', new TextDecoder().decode(decryptResult.data));
    }
  }
}

// Run the example if this file is executed directly
if (require.main === module) {
  example().catch(console.error);
}
