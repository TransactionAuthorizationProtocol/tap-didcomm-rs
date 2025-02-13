import { describe, it, expect, vi, beforeEach } from 'vitest';
import { loadWasmModule, initializeMemory, detectEnvironment } from '../../../src/wasm/loader';
import type { CoreWasmModule, NodeWasmModule } from '../../../src/wasm/types';

// Create a memory instance for mocks
const mockMemory = new WebAssembly.Memory({ initial: 1, maximum: 2 });

// Mock WASM modules
vi.mock('@tap-didcomm/core', () => ({
  default: {
    memory: mockMemory,
    initialize: vi.fn().mockResolvedValue(undefined),
    encrypt: vi.fn().mockResolvedValue('encrypted'),
    decrypt: vi.fn().mockResolvedValue('decrypted'),
    sign: vi.fn().mockResolvedValue('signed'),
    verify: vi.fn().mockResolvedValue(true),
  } satisfies CoreWasmModule,
}));

vi.mock('@tap-didcomm/node', () => ({
  default: {
    memory: mockMemory,
    initialize: vi.fn().mockResolvedValue(undefined),
    encrypt: vi.fn().mockResolvedValue('encrypted'),
    decrypt: vi.fn().mockResolvedValue('decrypted'),
    sign: vi.fn().mockResolvedValue('signed'),
    verify: vi.fn().mockResolvedValue(true),
    resolveIdentifier: vi.fn().mockResolvedValue('{}'),
  } satisfies NodeWasmModule,
}));

describe('WASM Loader', () => {
  describe('Environment Detection', () => {
    it('should detect Node.js environment', () => {
      const env = detectEnvironment();
      expect(env.isNode).toBe(true);
      expect(env.isBrowser).toBe(false);
      expect(env.isWebWorker).toBe(false);
    });

    it('should detect WebAssembly support', () => {
      const env = detectEnvironment();
      expect(env.hasWasm).toBe(true);
    });

    it('should detect SharedArrayBuffer support', () => {
      const env = detectEnvironment();
      expect(env.hasSharedArrayBuffer).toBe(true);
    });
  });

  describe('Memory Initialization', () => {
    it('should initialize memory with default settings', async () => {
      const result = await initializeMemory();
      expect(result.success).toBe(true);
      expect(result.data).toBeInstanceOf(WebAssembly.Memory);
    });

    it('should initialize memory with custom limits', async () => {
      const result = await initializeMemory({
        memory: {
          initialPages: 2,
          maximumPages: 10,
        },
      });
      expect(result.success).toBe(true);
      expect(result.data).toBeInstanceOf(WebAssembly.Memory);
    });

    it('should handle memory initialization errors', async () => {
      const result = await initializeMemory({
        memory: {
          initialPages: 100000, // Too large
          maximumPages: 200000,
        },
      });
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error?.code).toBe('MEMORY_ERROR');
    });
  });

  describe('Module Loading', () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });

    it('should load WASM module with default options', async () => {
      const result = await loadWasmModule();
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      if (result.success && result.data) {
        expect(result.data.memory).toBeDefined();
      }
    });

    it('should load Node.js optimized module', async () => {
      const result = await loadWasmModule({ useNode: true });
      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      if (result.success && result.data) {
        expect(result.data.memory).toBeDefined();
        expect('resolveIdentifier' in result.data).toBe(true);
      }
    });

    it('should handle loading errors', async () => {
      // Mock WebAssembly to be undefined
      const originalWebAssembly = global.WebAssembly;
      // @ts-ignore
      global.WebAssembly = undefined;

      const result = await loadWasmModule();
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('WASM_NOT_SUPPORTED');

      global.WebAssembly = originalWebAssembly;
    });
  });

  describe('Memory Management', () => {
    it('should handle memory growth', async () => {
      const result = await initializeMemory({
        memory: {
          initialPages: 1,
          maximumPages: 2,
        },
      });
      expect(result.success).toBe(true);
      if (result.success && result.data) {
        const memory = result.data;
        const initialPages = memory.buffer.byteLength / 65536;
        memory.grow(1);
        const newPages = memory.buffer.byteLength / 65536;
        expect(newPages).toBe(initialPages + 1);
      }
    });

    it('should enforce memory limits', async () => {
      const result = await initializeMemory({
        memory: {
          initialPages: 1,
          maximumPages: 1, // Set maximum to current size
        },
      });
      expect(result.success).toBe(true);
      if (result.success && result.data) {
        const memory = result.data;
        expect(() => memory.grow(1)).toThrow();
      }
    });
  });
});
