import { describe, it, expect } from "vitest";
import {
  PackingType,
  type Message,
  type DIDDocument,
  type EncryptOptions,
  type SignOptions,
  type DecryptOptions,
} from "../src";

describe("DIDComm Types", () => {
  describe("PackingType", () => {
    it("should have the correct values", () => {
      expect(PackingType.SIGNED).toBe("signed");
      expect(PackingType.ANONCRYPT).toBe("anoncrypt");
      expect(PackingType.AUTHCRYPT).toBe("authcrypt");
    });
  });

  describe("Message", () => {
    it("should allow creating a valid message", () => {
      const message: Message = {
        id: "1234567890",
        type: "https://example.com/protocols/1.0/test",
        body: { test: "Hello, World!" },
        from: "did:example:alice",
        to: ["did:example:bob"],
        created_time: Date.now(),
      };

      expect(message).toHaveProperty("id");
      expect(message).toHaveProperty("type");
      expect(message).toHaveProperty("body");
      expect(message.body).toHaveProperty("test");
    });
  });

  describe("DIDDocument", () => {
    it("should allow creating a valid DID document", () => {
      const didDocument: DIDDocument = {
        id: "did:example:123",
        verificationMethod: [
          {
            id: "did:example:123#key-1",
            type: "Ed25519VerificationKey2020",
            controller: "did:example:123",
            publicKeyMultibase:
              "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
          },
        ],
        authentication: ["did:example:123#key-1"],
        keyAgreement: ["did:example:123#key-1"],
        service: [
          {
            id: "did:example:123#service-1",
            type: "DIDCommMessaging",
            serviceEndpoint: "https://example.com/endpoint",
          },
        ],
      };

      expect(didDocument).toHaveProperty("id");
      expect(didDocument).toHaveProperty("verificationMethod");
      expect(didDocument.verificationMethod?.[0]).toHaveProperty("type");
    });
  });

  describe("Options Types", () => {
    it("should allow creating valid encrypt options", () => {
      const options: EncryptOptions = {
        to: ["did:example:bob"],
        from: "did:example:alice",
        packing: PackingType.AUTHCRYPT,
        sign: true,
      };

      expect(options).toHaveProperty("to");
      expect(options).toHaveProperty("from");
      expect(options).toHaveProperty("packing");
      expect(options).toHaveProperty("sign");
    });

    it("should allow creating valid sign options", () => {
      const options: SignOptions = {
        from: "did:example:alice",
        protectSenderIdentity: true,
      };

      expect(options).toHaveProperty("from");
      expect(options).toHaveProperty("protectSenderIdentity");
    });

    it("should allow creating valid decrypt options", () => {
      const options: DecryptOptions = {
        recipient: "did:example:bob",
        verifySignature: true,
      };

      expect(options).toHaveProperty("recipient");
      expect(options).toHaveProperty("verifySignature");
    });
  });
});
