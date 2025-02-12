import { describe, it, expect, beforeEach } from "vitest";
import { DefaultDIDCommPlugin, type DIDCommPlugin } from "../src";

describe("DIDComm Plugins", () => {
  describe("DefaultDIDCommPlugin", () => {
    let plugin: DIDCommPlugin;

    beforeEach(() => {
      plugin = new DefaultDIDCommPlugin();
    });

    describe("DID Resolver", () => {
      it("should return an error when resolving a DID", async () => {
        const result = await plugin.resolver.resolve("did:example:123");
        expect(result.success).toBe(false);
        expect(result.error?.code).toBe("NO_RESOLVER");
      });
    });

    describe("Signer", () => {
      it("should return an error when signing data", async () => {
        const data = new Uint8Array([1, 2, 3]);
        const result = await plugin.signer.sign(data, "key-1");
        expect(result.success).toBe(false);
        expect(result.error?.code).toBe("NO_SIGNER");
      });

      it("should return an error when verifying a signature", async () => {
        const data = new Uint8Array([1, 2, 3]);
        const signature = new Uint8Array([4, 5, 6]);
        const result = await plugin.signer.verify(data, signature, "key-1");
        expect(result.success).toBe(false);
        expect(result.error?.code).toBe("NO_SIGNER");
      });
    });

    describe("Encryptor", () => {
      it("should return an error when encrypting data", async () => {
        const data = new Uint8Array([1, 2, 3]);
        const result = await plugin.encryptor.encrypt(data, ["key-1"]);
        expect(result.success).toBe(false);
        expect(result.error?.code).toBe("NO_ENCRYPTOR");
      });

      it("should return an error when decrypting data", async () => {
        const data = new Uint8Array([1, 2, 3]);
        const result = await plugin.encryptor.decrypt(data, "key-1");
        expect(result.success).toBe(false);
        expect(result.error?.code).toBe("NO_ENCRYPTOR");
      });
    });
  });

  // Example of a custom plugin implementation
  describe("Custom Plugin", () => {
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

    let plugin: DIDCommPlugin;

    beforeEach(() => {
      plugin = new MockPlugin();
    });

    it("should successfully resolve a DID", async () => {
      const result = await plugin.resolver.resolve("did:example:123");
      expect(result.success).toBe(true);
      expect(result.data?.id).toBe("did:example:123");
    });

    it("should successfully sign data", async () => {
      const data = new Uint8Array([1, 2, 3]);
      const result = await plugin.signer.sign(data, "key-1");
      expect(result.success).toBe(true);
      expect(result.data).toHaveLength(data.length + 1);
    });

    it("should successfully verify a signature", async () => {
      const data = new Uint8Array([1, 2, 3]);
      const signature = new Uint8Array([4, 5, 6]);
      const result = await plugin.signer.verify(data, signature, "key-1");
      expect(result.success).toBe(true);
      expect(result.data).toBe(true);
    });

    it("should successfully encrypt data", async () => {
      const data = new Uint8Array([1, 2, 3]);
      const result = await plugin.encryptor.encrypt(data, ["key-1"]);
      expect(result.success).toBe(true);
      expect(result.data).toHaveLength(data.length + 1);
    });

    it("should successfully decrypt data", async () => {
      const data = new Uint8Array([1, 2, 3, 0xff]);
      const result = await plugin.encryptor.decrypt(data, "key-1");
      expect(result.success).toBe(true);
      expect(result.data).toHaveLength(data.length - 1);
    });
  });
});
