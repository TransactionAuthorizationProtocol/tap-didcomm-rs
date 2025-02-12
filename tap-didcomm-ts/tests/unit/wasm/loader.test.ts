import { describe, it, expect, vi } from "vitest";
import {
  loadWasmModule,
  initializeMemory,
  detectEnvironment,
} from "../../../src/wasm/loader";

describe("WASM Loader", () => {
  describe("Environment Detection", () => {
    it("should detect Node.js environment", () => {
      const env = detectEnvironment();
      expect(env.isNode).toBe(true);
      expect(env.isBrowser).toBe(false);
      expect(env.isWebWorker).toBe(false);
    });

    it("should detect WebAssembly support", () => {
      const env = detectEnvironment();
      expect(env.hasWasm).toBe(true);
    });

    it("should detect SharedArrayBuffer support", () => {
      const env = detectEnvironment();
      expect(env.hasSharedArrayBuffer).toBe(true);
    });
  });

  describe("Memory Initialization", () => {
    it("should initialize memory with default settings", async () => {
      const result = await initializeMemory();
      expect(result.success).toBe(true);
      expect(result.data).toBeInstanceOf(WebAssembly.Memory);
    });

    it("should initialize memory with custom limits", async () => {
      const result = await initializeMemory({
        initialPages: 2,
        maximumPages: 10,
      });
      expect(result.success).toBe(true);
      expect(result.data).toBeInstanceOf(WebAssembly.Memory);
    });

    it("should handle memory initialization errors", async () => {
      const result = await initializeMemory({
        initialPages: 100000, // Too large
      });
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe("Module Loading", () => {
    it("should load WASM module with default options", async () => {
      const result = await loadWasmModule();
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
    });

    it("should load Node.js optimized module", async () => {
      const result = await loadWasmModule({ useNode: true });
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
    });

    it("should handle loading errors", async () => {
      // Mock WebAssembly.instantiate to fail
      const originalInstantiate = WebAssembly.instantiate;
      WebAssembly.instantiate = vi
        .fn()
        .mockRejectedValue(new Error("Mock error"));

      const result = await loadWasmModule();
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();

      // Restore original
      WebAssembly.instantiate = originalInstantiate;
    });
  });

  describe("Memory Management", () => {
    it("should handle memory growth", async () => {
      const memory = (await initializeMemory()).data!;
      const initialPages = memory.buffer.byteLength / 65536;

      // Grow memory
      memory.grow(1);

      const newPages = memory.buffer.byteLength / 65536;
      expect(newPages).toBe(initialPages + 1);
    });

    it("should enforce memory limits", async () => {
      const memory = (
        await initializeMemory({
          initialPages: 1,
          maximumPages: 2,
        })
      ).data!;

      // Try to grow beyond limit
      expect(() => memory.grow(2)).toThrow();
    });
  });
});
