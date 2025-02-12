import { describe, it, expect } from "vitest";
import { DIDCommClient, DefaultDIDCommPlugin, PackingType } from "../../src";
import {
  createTestMessage,
  createTestMessages,
  createMessageStream,
  measureMemoryUsage,
  isMemoryUsageAcceptable,
} from "./utils";

describe("DIDComm Node.js Performance", () => {
  describe("Message Processing Performance", () => {
    it("should handle large messages efficiently", async () => {
      const client = new DIDCommClient(
        {
          defaultPacking: PackingType.ANONCRYPT,
          maxMessageSize: 1024 * 1024, // 1MB
        },
        new DefaultDIDCommPlugin(),
      );
      await client.initialize();

      const message = createTestMessage(512 * 1024); // 512KB message
      const memUsage = measureMemoryUsage();

      const result = await client.encrypt(message, {
        to: ["did:example:bob"],
      });

      expect(result.success).toBe(true);
      expect(isMemoryUsageAcceptable(memUsage.before, memUsage.after, 50)).toBe(
        true,
      );
    });

    it("should process message batches efficiently", async () => {
      const client = new DIDCommClient(
        {
          defaultPacking: PackingType.ANONCRYPT,
          maxMessageSize: 1024 * 1024, // 1MB
        },
        new DefaultDIDCommPlugin(),
      );
      await client.initialize();

      const messages = createTestMessages(5, 256 * 1024); // 5 256KB messages
      const memUsage = measureMemoryUsage();

      const results = await Promise.all(
        messages.map((msg) =>
          client.encrypt(msg, {
            to: ["did:example:bob"],
          }),
        ),
      );

      expect(results.every((r) => r.success)).toBe(true);
      expect(isMemoryUsageAcceptable(memUsage.before, memUsage.after, 50)).toBe(
        true,
      );
    });

    it("should handle message streams efficiently", async () => {
      const client = new DIDCommClient(
        {
          defaultPacking: PackingType.ANONCRYPT,
          maxMessageSize: 1024 * 1024, // 1MB
        },
        new DefaultDIDCommPlugin(),
      );
      await client.initialize();

      const memUsage = measureMemoryUsage();
      const messageStream = createMessageStream(3, 256 * 1024); // 3 256KB messages

      for await (const message of messageStream) {
        const result = await client.encrypt(message, {
          to: ["did:example:bob"],
        });
        expect(result.success).toBe(true);
      }

      expect(isMemoryUsageAcceptable(memUsage.before, memUsage.after, 50)).toBe(
        true,
      );
    });
  });

  describe("Memory Management", () => {
    it("should release memory after processing", async () => {
      const client = new DIDCommClient(
        {
          defaultPacking: PackingType.ANONCRYPT,
          maxMessageSize: 1024 * 1024, // 1MB
        },
        new DefaultDIDCommPlugin(),
      );
      await client.initialize();

      const memUsage = measureMemoryUsage();

      // Process several messages
      for (let i = 0; i < 3; i++) {
        const message = createTestMessage(256 * 1024); // 256KB message
        const result = await client.encrypt(message, {
          to: ["did:example:bob"],
        });
        expect(result.success).toBe(true);

        // Force garbage collection if available
        if (global.gc) {
          global.gc();
        }
      }

      expect(isMemoryUsageAcceptable(memUsage.before, memUsage.after, 25)).toBe(
        true,
      );
    });
  });
});
