import { describe, it, expect, vi } from "vitest";
import { loadWasmModule, initializeMemory } from "../../src/wasm/loader";

describe("WASM Loader", () => {
  describe("Environment Detection", () => {
    it("should detect Node.js environment", () => {
      expect(typeof process).toBe("object");
      expect(typeof process.versions.node).toBe("string");
    });

    it("should detect WebAssembly support", () => {
      expect(typeof WebAssembly).toBe("object");
      expect(typeof WebAssembly.compile).toBe("function");
    });

    it("should detect SharedArrayBuffer support", () => {
      expect(typeof SharedArrayBuffer).toBe("function");
    });

    it("should detect Atomics support", () => {
      expect(typeof Atomics).toBe("object");
    });
  });

  describe("WASM Module Loading", () => {
    it("should fail when WASM is not supported", async () => {
      const originalWebAssembly = global.WebAssembly;
      // @ts-ignore
      global.WebAssembly = undefined;

      const result = await loadWasmModule({ useNode: false });
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe("WASM_NOT_SUPPORTED");

      global.WebAssembly = originalWebAssembly;
    });

    it("should attempt to load Node.js module when in Node environment", async () => {
      const mockNodeModule = {};
      vi.mock("../../src/wasm/node", () => ({
        default: mockNodeModule,
      }));

      const result = await loadWasmModule({ useNode: true });
      expect(result.success).toBe(true);
      expect(result.data).toEqual(mockNodeModule);
    });

    it("should fallback to core module if Node.js module fails", async () => {
      const mockCoreModule = {};
      vi.mock("../../src/wasm/core", () => ({
        default: mockCoreModule,
      }));

      const result = await loadWasmModule({ useNode: true });
      expect(result.success).toBe(true);
      expect(result.data).toEqual(mockCoreModule);
    });
  });

  describe("WASM Memory Initialization", () => {
    it("should initialize memory with default settings", async () => {
      const result = await initializeMemory();
      expect(result.success).toBe(true);
      expect(result.data).toBeInstanceOf(WebAssembly.Memory);
    });

    it("should initialize memory with custom limit", async () => {
      const result = await initializeMemory({
        initialPages: 2,
        maximumPages: 4,
      });
      expect(result.success).toBe(true);
      expect(result.data).toBeInstanceOf(WebAssembly.Memory);
    });

    it("should handle memory initialization errors", async () => {
      const result = await initializeMemory({
        initialPages: 100000, // Too large to allocate
        maximumPages: 200000,
      });
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe("MEMORY_ERROR");
    });
  });
});
