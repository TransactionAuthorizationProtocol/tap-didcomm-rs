import { describe, it, expect, beforeEach } from "vitest";
import {
  DIDCommClient,
  PackingType,
  type DIDCommPlugin,
  type Message,
  type DIDDocument,
} from "../src";

describe("DIDCommClient", () => {
  // Mock plugin implementation
  class MockPlugin implements DIDCommPlugin {
    public readonly resolver = {
      async resolve(did: string) {
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
      async sign(data: Uint8Array) {
        return {
          success: true,
          data: new Uint8Array([...data, 0xff]), // Mock signature
        };
      },

      async verify() {
        return {
          success: true,
          data: true,
        };
      },
    };

    public readonly encryptor = {
      async encrypt(data: Uint8Array) {
        return {
          success: true,
          data: new Uint8Array([...data, 0xff]), // Mock encryption
        };
      },

      async decrypt(data: Uint8Array) {
        return {
          success: true,
          data: data.slice(0, -1), // Remove mock encryption byte
        };
      },
    };
  }

  let client: DIDCommClient;
  let plugin: DIDCommPlugin;

  beforeEach(async () => {
    plugin = new MockPlugin();
    client = new DIDCommClient(
      {
        defaultPacking: PackingType.ANONCRYPT,
      },
      plugin,
    );
    await client.initialize();
  });

  describe("initialization", () => {
    it("should initialize successfully", async () => {
      const result = await client.initialize();
      expect(result.success).toBe(true);
    });
  });

  describe("encryption", () => {
    it("should encrypt a message successfully", async () => {
      const message: Message = {
        id: "123",
        type: "test",
        body: { hello: "world" },
      };

      const result = await client.encrypt(message, {
        to: ["did:example:bob"],
      });

      expect(result.success).toBe(true);
      expect(result.data).toBeInstanceOf(Uint8Array);
    });

    it("should handle encryption with sender authentication", async () => {
      const message: Message = {
        id: "123",
        type: "test",
        body: { hello: "world" },
      };

      const result = await client.encrypt(message, {
        to: ["did:example:bob"],
        from: "did:example:alice",
        packing: PackingType.AUTHCRYPT,
      });

      expect(result.success).toBe(true);
      expect(result.data).toBeInstanceOf(Uint8Array);
    });
  });

  describe("decryption", () => {
    it("should decrypt a message successfully", async () => {
      const original: Message = {
        id: "123",
        type: "test",
        body: { hello: "world" },
      };

      // First encrypt the message
      const encrypted = await client.encrypt(original, {
        to: ["did:example:bob"],
      });
      expect(encrypted.success).toBe(true);

      // Then decrypt it
      const decrypted = await client.decrypt(encrypted.data!, {
        recipient: "did:example:bob",
      });

      expect(decrypted.success).toBe(true);
      expect(decrypted.data).toHaveProperty("id", original.id);
      expect(decrypted.data).toHaveProperty("type", original.type);
      expect(decrypted.data?.body).toEqual(original.body);
    });
  });

  describe("signing", () => {
    it("should sign a message successfully", async () => {
      const message: Message = {
        id: "123",
        type: "test",
        body: { hello: "world" },
      };

      const result = await client.sign(message, {
        from: "did:example:alice",
      });

      expect(result.success).toBe(true);
      expect(result.data).toBeInstanceOf(Uint8Array);
    });
  });

  describe("verification", () => {
    it("should verify a signature successfully", async () => {
      const message: Message = {
        id: "123",
        type: "test",
        body: { hello: "world" },
      };

      // First sign the message
      const signed = await client.sign(message, {
        from: "did:example:alice",
      });
      expect(signed.success).toBe(true);

      // Then verify it
      const verified = await client.verify(
        new TextEncoder().encode(JSON.stringify(message)),
        signed.data!,
        "did:example:alice#key-1",
      );

      expect(verified.success).toBe(true);
      expect(verified.data).toBe(true);
    });
  });
});
