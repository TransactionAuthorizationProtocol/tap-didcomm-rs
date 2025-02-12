import { Signer, Encryptor, Result, SignedMessage, EncryptedMessage } from '../../dist';

/**
 * Example custom signer that uses a simple key-value store for private keys
 */
export class CustomSigner implements Signer {
  private keys: Map<string, string>;

  constructor() {
    this.keys = new Map();
    // Initialize with some example keys (in a real implementation, these would be secure private keys)
    this.keys.set('did:example:sender#key-1', 'mock-private-key-1');
    this.keys.set('did:example:recipient#key-1', 'mock-private-key-2');
  }

  /**
   * Signs a message using the private key associated with the given key ID
   */
  async sign(message: any, keyId: string): Promise<Result<SignedMessage>> {
    try {
      const privateKey = this.keys.get(keyId);
      if (!privateKey) {
        return {
          success: false,
          error: new Error(`Key not found: ${keyId}`)
        };
      }

      // In a real implementation, this would use actual cryptographic signing
      const mockSignature = Buffer.from(`${privateKey}-${JSON.stringify(message)}`).toString('base64');

      return {
        success: true,
        data: {
          ...message,
          signature: mockSignature,
          keyId
        }
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error : new Error('Unknown error occurred')
      };
    }
  }

  /**
   * Verifies a signed message
   */
  async verify(signedMessage: SignedMessage): Promise<Result<boolean>> {
    try {
      const { signature, keyId, ...message } = signedMessage;
      const privateKey = this.keys.get(keyId);

      if (!privateKey) {
        return {
          success: false,
          error: new Error(`Key not found: ${keyId}`)
        };
      }

      // In a real implementation, this would verify the cryptographic signature
      const expectedSignature = Buffer.from(`${privateKey}-${JSON.stringify(message)}`).toString('base64');
      const isValid = signature === expectedSignature;

      return {
        success: true,
        data: isValid
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error : new Error('Unknown error occurred')
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
  private keys: Map<string, string>;

  constructor() {
    this.keys = new Map();
    // Initialize with some example keys (in a real implementation, these would be secure encryption keys)
    this.keys.set('did:example:sender#key-2', 'mock-encryption-key-1');
    this.keys.set('did:example:recipient#key-2', 'mock-encryption-key-2');
  }

  /**
   * Encrypts a message for the specified recipients
   */
  async encrypt(message: any, recipientKeys: string[]): Promise<Result<EncryptedMessage>> {
    try {
      // Verify we have all recipient keys
      for (const keyId of recipientKeys) {
        if (!this.keys.has(keyId)) {
          return {
            success: false,
            error: new Error(`Key not found: ${keyId}`)
          };
        }
      }

      // In a real implementation, this would use proper encryption
      const mockCiphertext = Buffer.from(JSON.stringify({
        message,
        recipients: recipientKeys
      })).toString('base64');

      return {
        success: true,
        data: {
          ciphertext: mockCiphertext,
          recipients: recipientKeys
        }
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error : new Error('Unknown error occurred')
      };
    }
  }

  /**
   * Decrypts a message using the specified recipient key
   */
  async decrypt(encryptedMessage: EncryptedMessage, recipientKey: string): Promise<Result<any>> {
    try {
      if (!this.keys.has(recipientKey)) {
        return {
          success: false,
          error: new Error(`Key not found: ${recipientKey}`)
        };
      }

      if (!encryptedMessage.recipients.includes(recipientKey)) {
        return {
          success: false,
          error: new Error(`Message not encrypted for key: ${recipientKey}`)
        };
      }

      // In a real implementation, this would use proper decryption
      const decoded = JSON.parse(Buffer.from(encryptedMessage.ciphertext, 'base64').toString());
      return {
        success: true,
        data: decoded.message
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error : new Error('Unknown error occurred')
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
  const message = {
    id: `test-${Date.now()}`,
    type: 'example/1.0',
    body: {
      text: 'Hello from custom plugins!',
      timestamp: Date.now()
    }
  };

  // Test signing
  console.log('Testing signing...');
  const signResult = await signer.sign(message, 'did:example:sender#key-1');
  if (signResult.success) {
    console.log('Successfully signed message:');
    console.log(JSON.stringify(signResult.data, null, 2));

    // Test verification
    console.log('\nVerifying signature...');
    const verifyResult = await signer.verify(signResult.data);
    if (verifyResult.success) {
      console.log('Signature verification:', verifyResult.data ? 'Valid' : 'Invalid');
    }
  }

  // Test encryption
  console.log('\nTesting encryption...');
  const encryptResult = await encryptor.encrypt(message, [
    'did:example:recipient#key-2'
  ]);
  if (encryptResult.success) {
    console.log('Successfully encrypted message:');
    console.log(JSON.stringify(encryptResult.data, null, 2));

    // Test decryption
    console.log('\nDecrypting message...');
    const decryptResult = await encryptor.decrypt(
      encryptResult.data,
      'did:example:recipient#key-2'
    );
    if (decryptResult.success) {
      console.log('Successfully decrypted message:');
      console.log(JSON.stringify(decryptResult.data, null, 2));
    }
  }
}

// Run the example if this file is executed directly
if (require.main === module) {
  example().catch(console.error); 