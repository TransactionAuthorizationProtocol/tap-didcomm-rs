import { describe, it, expect, beforeEach } from "vitest";
import { DIDCommClient, DefaultDIDCommPlugin, PackingType } from "../../src";

describe("DIDCommClient", () => {
  let client: DIDCommClient;

  beforeEach(() => {
    client = new DIDCommClient(
      {
        defaultPacking: PackingType.ANONCRYPT,
        useHttps: false,
      },
      new DefaultDIDCommPlugin(),
    );
  });

  describe("initialization", () => {
    it("should initialize successfully", async () => {
      const result = await client.initialize();
      expect(result.success).toBe(true);
    });
  });

  describe("message operations", () => {
    const testMessage = {
      id: "test-msg-1",
      type: "test-type",
      body: { test: "data" },
    };

    beforeEach(async () => {
      await client.initialize();
    });

    it("should encrypt and decrypt a message", async () => {
      const encrypted = await client.encrypt(testMessage, {
        to: ["did:example:123"],
      });
      expect(encrypted.success).toBe(true);
      expect(encrypted.data).toBeDefined();

      const decrypted = await client.decrypt(encrypted.data!, {});
      expect(decrypted.success).toBe(true);
      expect(decrypted.data).toMatchObject(testMessage);
    });

    it("should sign and verify a message", async () => {
      const signed = await client.sign(testMessage, {
        from: "did:example:456",
      });
      expect(signed.success).toBe(true);
      expect(signed.data).toBeDefined();

      const verified = await client.verify(
        signed.data!,
        new Uint8Array(),
        "did:example:456",
      );
      expect(verified.success).toBe(true);
      expect(verified.data).toBe(true);
    });
  });

  describe("error handling", () => {
    beforeEach(async () => {
      await client.initialize();
    });

    it("should handle encryption errors gracefully", async () => {
      const result = await client.encrypt({} as any, { to: [] });
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("should handle decryption errors gracefully", async () => {
      const result = await client.decrypt(new Uint8Array(), {});
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });
});
