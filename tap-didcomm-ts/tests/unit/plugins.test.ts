import { describe, it, expect, beforeEach } from "vitest";
import { DefaultDIDCommPlugin, DIDCommPlugin } from "../../src";
import type { DIDCommResult, DIDDocument } from "../../src";

describe("DefaultDIDCommPlugin", () => {
  let plugin: DIDCommPlugin;

  beforeEach(() => {
    plugin = new DefaultDIDCommPlugin();
  });

  describe("DID Resolution", () => {
    it("should resolve a DID", async () => {
      const result = await plugin.resolver.resolve("did:example:123");
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      const doc = result.data as DIDDocument;
      expect(doc.id).toBe("did:example:123");
    });

    it("should handle invalid DIDs", async () => {
      const result = await plugin.resolver.resolve("invalid:did");
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe("Signing", () => {
    const testData = new Uint8Array([1, 2, 3, 4]);
    const testKeyId = "did:example:123#key-1";

    it("should sign data", async () => {
      const result = await plugin.signer.sign(testData, testKeyId);
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data instanceof Uint8Array).toBe(true);
    });

    it("should verify signatures", async () => {
      const signed = await plugin.signer.sign(testData, testKeyId);
      const verified = await plugin.signer.verify(
        testData,
        signed.data!,
        testKeyId,
      );
      expect(verified.success).toBe(true);
      expect(verified.data).toBe(true);
    });
  });

  describe("Encryption", () => {
    const testData = new Uint8Array([1, 2, 3, 4]);
    const testRecipients = ["did:example:123"];

    it("should encrypt data", async () => {
      const result = await plugin.encryptor.encrypt(testData, testRecipients);
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.data instanceof Uint8Array).toBe(true);
    });

    it("should decrypt data", async () => {
      const encrypted = await plugin.encryptor.encrypt(
        testData,
        testRecipients,
      );
      const decrypted = await plugin.encryptor.decrypt(
        encrypted.data!,
        testRecipients[0],
      );
      expect(decrypted.success).toBe(true);
      expect(decrypted.data).toEqual(testData);
    });
  });

  describe("Error Handling", () => {
    it("should handle resolution errors", async () => {
      const result = await plugin.resolver.resolve("");
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("should handle signing errors", async () => {
      const result = await plugin.signer.sign(new Uint8Array(), "invalid-key");
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("should handle encryption errors", async () => {
      const result = await plugin.encryptor.encrypt(new Uint8Array(), []);
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });
});
