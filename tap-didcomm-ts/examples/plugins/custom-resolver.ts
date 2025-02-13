import type { DIDResolver, DIDDocument, DIDCommResult } from '../../src';

/**
 * Example custom DID resolver that resolves DIDs from an in-memory map
 */
export class CustomDIDResolver implements DIDResolver {
  private didDocuments: Map<string, DIDDocument>;

  constructor() {
    this.didDocuments = new Map();

    // Initialize with some example DID documents
    this.didDocuments.set('did:example:sender', {
      id: 'did:example:sender',
      verificationMethod: [
        {
          id: 'did:example:sender#key-1',
          type: 'Ed25519VerificationKey2020',
          controller: 'did:example:sender',
          publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        },
      ],
      authentication: ['did:example:sender#key-1'],
      assertionMethod: ['did:example:sender#key-1'],
      keyAgreement: ['did:example:sender#key-2'],
    });

    this.didDocuments.set('did:example:recipient', {
      id: 'did:example:recipient',
      verificationMethod: [
        {
          id: 'did:example:recipient#key-1',
          type: 'Ed25519VerificationKey2020',
          controller: 'did:example:recipient',
          publicKeyMultibase: 'z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V',
        },
      ],
      authentication: ['did:example:recipient#key-1'],
      assertionMethod: ['did:example:recipient#key-1'],
      keyAgreement: ['did:example:recipient#key-2'],
    });
  }

  /**
   * Resolves a DID to its DID Document
   * @param did The DID to resolve
   * @returns A Result containing the resolved DID Document or an error
   */
  async resolve(did: string): Promise<DIDCommResult<DIDDocument>> {
    try {
      const document = this.didDocuments.get(did);
      if (!document) {
        return {
          success: false,
          error: {
            code: 'DID_NOT_FOUND',
            message: `DID not found: ${did}`,
          },
        };
      }

      return {
        success: true,
        data: document,
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'RESOLUTION_ERROR',
          message: error instanceof Error ? error.message : 'Unknown error occurred',
        },
      };
    }
  }

  /**
   * Checks if this resolver supports resolving a given DID
   * @param did The DID to check
   * @returns True if this resolver supports the DID method
   */
  supports(did: string): boolean {
    return did.startsWith('did:example:');
  }
}

/**
 * Example usage of the custom resolver
 */
async function example() {
  const resolver = new CustomDIDResolver();

  // Test resolving an existing DID
  console.log('Resolving did:example:sender...');
  const result = await resolver.resolve('did:example:sender');
  if (result.success && result.data) {
    console.log('Successfully resolved DID document:');
    console.log(JSON.stringify(result.data, null, 2));
  } else {
    console.error('Failed to resolve DID:', result.error?.message ?? 'Unknown error');
  }

  // Test resolving a non-existent DID
  console.log('\nResolving non-existent DID...');
  const notFoundResult = await resolver.resolve('did:example:nonexistent');
  if (!notFoundResult.success) {
    console.log('Expected error:', notFoundResult.error?.message ?? 'Unknown error');
  }

  // Test method support
  console.log('\nTesting method support:');
  console.log('Supports did:example:test -', resolver.supports('did:example:test'));
  console.log('Supports did:key:test -', resolver.supports('did:key:test'));
}

// Run the example if this file is executed directly
if (require.main === module) {
  example().catch(console.error);
}
