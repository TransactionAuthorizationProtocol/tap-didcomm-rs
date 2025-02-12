import { describe, it, expect } from "vitest";
import { DIDCommClient, DefaultDIDCommPlugin, PackingType } from "../../src";
import {
  createTestMessage,
  createTestMessages,
  createMessageStream,
  measureMemoryUsage,
  isMemoryUsageAcceptable,
} from "./utils";

// Create a mock plugin that simulates successful operations
class MockNodePlugin extends DefaultDIDCommPlugin {
  private maxMessageSize: number;

  constructor(maxMessageSize: number = 1024 * 1024) {
    super();
    this.maxMessageSize = maxMessageSize;
  }

  public readonly resolver = {
    resolve: async (did: string) => {
      return {
        success: true,
        data: {
          id: did,
          verificationMethod: [
            {
              id: `${did}#key-1`,
              type: "Ed25519VerificationKey2020",
              controller: did,
              publicKeyMultibase: "test",
            },
          ],
          keyAgreement: [`${did}#key-1`],
        },
      };
    },
  };

  public readonly signer = {
    sign: async (data: Uint8Array) => {
      if (data.length > this.maxMessageSize) {
        return {
          success: false,
          error: {
            code: "MEMORY_ERROR",
            message: "Message too large",
          },
        };
      }
      return {
        success: true,
        data: new Uint8Array([...data, 0xff]), // Mock signature
      };
    },

    verify: async () => {
      return {
        success: true,
        data: true,
      };
    },
  };

  public readonly encryptor = {
    encrypt: async (data: Uint8Array) => {
      if (data.length > this.maxMessageSize) {
        return {
          success: false,
          error: {
            code: "MEMORY_ERROR",
            message: "Message too large",
          },
        };
      }
      return {
        success: true,
        data: new Uint8Array([...data, 0xff]), // Mock encryption
      };
    },

    decrypt: async (data: Uint8Array) => {
      if (data.length > this.maxMessageSize) {
        return {
          success: false,
          error: {
            code: "MEMORY_ERROR",
            message: "Message too large",
          },
        };
      }
      return {
        success: true,
        data: data.slice(0, -1), // Remove mock encryption byte
      };
    },
  };
}

describe("DIDComm Node.js Integration", () => {
  describe("WASM Loading", () => {
    it("should load WASM module successfully", async () => {
      const client = new DIDCommClient(
        {
          defaultPacking: PackingType.ANONCRYPT,
          maxMessageSize: 1024 * 1024, // 1MB
        },
        new MockNodePlugin(1024 * 1024),
      );
      const result = await client.initialize();
      expect(result.success).toBe(true);
    });

    it("should handle memory limits correctly", async () => {
      const client = new DIDCommClient(
        {
          defaultPacking: PackingType.ANONCRYPT,
          maxMessageSize: 512 * 1024, // 512KB
        },
        new MockNodePlugin(512 * 1024),
      );
      await client.initialize();

      const message = createTestMessage(256 * 1024); // 256KB message
      const result = await client.encrypt(message, {
        to: ["did:example:bob"],
      });
      expect(result.success).toBe(true);
    });
  });

  describe("Message Processing", () => {
    it("should handle concurrent message processing", async () => {
      const client = new DIDCommClient(
        {
          defaultPacking: PackingType.ANONCRYPT,
          maxMessageSize: 1024 * 1024, // 1MB
        },
        new MockNodePlugin(),
      );
      await client.initialize();

      const messages = Array.from({ length: 5 }, (_, i) => ({
        id: `msg-${i}`,
        type: "test",
        body: { data: `test-${i}` },
      }));

      const results = await Promise.all(
        messages.map((msg) =>
          client.encrypt(msg, {
            to: ["did:example:bob"],
          }),
        ),
      );

      expect(results.every((r) => r.success)).toBe(true);
    });

    it("should handle message streaming", async () => {
      const client = new DIDCommClient(
        {
          defaultPacking: PackingType.ANONCRYPT,
          maxMessageSize: 1024 * 1024, // 1MB
        },
        new MockNodePlugin(),
      );
      await client.initialize();

      const messages = Array.from({ length: 3 }, (_, i) => ({
        id: `msg-${i}`,
        type: "test",
        body: { data: "x".repeat(256 * 1024) }, // 256KB data
      }));

      for (const message of messages) {
        const result = await client.encrypt(message, {
          to: ["did:example:bob"],
        });
        expect(result.success).toBe(true);
      }
    });
  });

  describe("Error Handling", () => {
    it("should handle WASM errors gracefully", async () => {
      const client = new DIDCommClient(
        {
          defaultPacking: PackingType.ANONCRYPT,
          maxMessageSize: 1024 * 1024, // 1MB
        },
        new DefaultDIDCommPlugin(), // Use default plugin that returns errors
      );
      await client.initialize();

      const invalidMessage = {
        id: "invalid",
        type: "test",
        body: undefined as any,
      };

      const result = await client.encrypt(invalidMessage, {
        to: ["did:example:bob"],
      });
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("should handle memory allocation errors", async () => {
      const maxSize = 512 * 1024; // 512KB limit
      const client = new DIDCommClient(
        {
          defaultPacking: PackingType.ANONCRYPT,
          maxMessageSize: maxSize,
        },
        new MockNodePlugin(maxSize),
      );
      await client.initialize();

      const hugeMessage = createTestMessage(maxSize * 2); // Double the limit
      const result = await client.encrypt(hugeMessage, {
        to: ["did:example:bob"],
      });
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe("MEMORY_ERROR");
    });
  });

  describe("Plugin System", () => {
    it("should work with custom Node.js plugins", async () => {
      class NodePlugin extends MockNodePlugin {
        public readonly resolver = {
          async resolve(did: string) {
            if (did.startsWith("did:file:")) {
              return {
                success: true,
                data: {
                  id: did,
                  verificationMethod: [
                    {
                      id: `${did}#key-1`,
                      type: "JsonWebKey2020",
                      controller: did,
                      publicKeyJwk: {
                        kty: "OKP",
                        crv: "Ed25519",
                        x: "test",
                      },
                    },
                  ],
                },
              };
            }
            return super.resolver.resolve(did);
          },
        };
      }

      const client = new DIDCommClient(
        {
          defaultPacking: PackingType.ANONCRYPT,
          maxMessageSize: 1024 * 1024, // 1MB
        },
        new NodePlugin(),
      );
      await client.initialize();

      const result = await client.resolve("did:file:test");
      expect(result.success).toBe(true);
      expect(result.data?.id).toBe("did:file:test");
    });
  });
});
