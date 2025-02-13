import { describe, it, expect, vi, beforeEach } from 'vitest';
import { loadWasmModule, initializeMemory, detectEnvironment } from '../../../src/wasm/loader';
import type { CoreWasmModule, NodeWasmModule } from '../../../src/wasm/types';

// Create a memory instance for mocks
const mockMemory = new WebAssembly.Memory({ initial: 1, maximum: 2 });

// Mock WASM modules
vi.mock('@tap-didcomm/core', () => {
  return {
    default: {
      memory: new WebAssembly.Memory({ initial: 1 }),
      initialize: vi.fn().mockResolvedValue(undefined),
    },
  };
});

vi.mock('@tap-didcomm/node', () => {
  return {
    default: {
      memory: new WebAssembly.Memory({ initial: 1 }),
      initialize: vi.fn().mockResolvedValue(undefined),
      resolveIdentifier: vi.fn(),
    },
  };
});

describe('WASM Loader', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

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

    it('should handle missing WebAssembly features gracefully', () => {
      const originalWebAssembly = global.WebAssembly;
      // @ts-ignore
      global.WebAssembly = undefined;

      const env = detectEnvironment();
      expect(env.hasWasm).toBe(false);

      global.WebAssembly = originalWebAssembly;
    });
  });

  describe('Memory Management', () => {
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
      expect(result.error?.code).toBe('MEMORY_ERROR');
    });

    it('should enforce memory growth limits', async () => {
      const result = await initializeMemory({
        memory: {
          initialPages: 1,
          maximumPages: 2,
        },
      });
      expect(result.success).toBe(true);
      if (result.success && result.data) {
        const memory = result.data;
        memory.grow(1); // Should succeed
        expect(() => memory.grow(1)).toThrow(); // Should fail
      }
    });

    it('should handle invalid memory configuration', async () => {
      const result = await initializeMemory({
        memory: {
          initialPages: -1, // Invalid
          maximumPages: 1,
        },
      });
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('MEMORY_ERROR');
    });
  });

  describe('Module Loading', () => {
    beforeEach(() => {
      vi.resetModules();
      vi.clearAllMocks();
      vi.doMock('@tap-didcomm/core', () => ({
        default: {
          memory: new WebAssembly.Memory({ initial: 1 }),
          initialize: vi.fn().mockResolvedValue(undefined),
        },
      }));
      vi.doMock('@tap-didcomm/node', () => ({
        default: {
          memory: new WebAssembly.Memory({ initial: 1 }),
          initialize: vi.fn().mockResolvedValue(undefined),
          resolveIdentifier: vi.fn(),
        },
      }));
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

    it('should handle module import failures', async () => {
      vi.doMock('@tap-didcomm/core', () => {
        throw new Error('Module not found');
      });

      const result = await loadWasmModule();
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('MODULE_LOAD_ERROR');
    });

    it('should handle memory initialization failures during module load', async () => {
      vi.doMock('@tap-didcomm/core', () => ({
        default: {
          memory: null,
          initialize: () => {
            throw new Error('Memory initialization failed');
          },
        },
      }));

      const result = await loadWasmModule();
      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INITIALIZATION_ERROR');
    });
  });

  describe('Error Recovery', () => {
    beforeEach(() => {
      vi.resetModules();
      vi.clearAllMocks();
    });

    it('should allow module reload after failure', async () => {
      // First load fails
      vi.doMock('@tap-didcomm/core', () => {
        throw new Error('Module not found');
      });
      let result = await loadWasmModule();
      expect(result.success).toBe(false);

      // Second load succeeds
      vi.doMock('@tap-didcomm/core', () => ({
        default: {
          memory: new WebAssembly.Memory({ initial: 1 }),
          initialize: vi.fn().mockResolvedValue(undefined),
        },
      }));
      result = await loadWasmModule();
      expect(result.success).toBe(true);
    });

    it('should recover from memory allocation failures', async () => {
      // First allocation fails
      let result = await initializeMemory({
        memory: {
          initialPages: 100000,
          maximumPages: 200000,
        },
      });
      expect(result.success).toBe(false);

      // Second allocation succeeds
      result = await initializeMemory({
        memory: {
          initialPages: 1,
          maximumPages: 2,
        },
      });
      expect(result.success).toBe(true);
    });
  });
});
