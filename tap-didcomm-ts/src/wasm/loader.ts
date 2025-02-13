/**
 * WASM module loading utilities for DIDComm.
 * Handles dynamic loading of WASM modules in both Node.js and browser environments.
 */

import type { CoreWasmModule, NodeWasmModule } from './types';
import type { DIDCommResult } from '../types';

// Default paths for WASM modules
const DEFAULT_CORE_WASM_PATH = '@tap-didcomm/core';
const DEFAULT_NODE_WASM_PATH = '@tap-didcomm/node';

/**
 * Configuration for WASM loading
 */
export interface WasmLoadOptions {
  /** Whether to use Node.js-specific optimizations */
  useNode?: boolean;
  /** Memory configuration */
  memory?: {
    /** Initial memory pages (64KB each) */
    initialPages?: number;
    /** Maximum memory pages (64KB each) */
    maximumPages?: number;
  };
}

/**
 * Environment detection result
 */
export interface Environment {
  /** Whether running in Node.js */
  isNode: boolean;
  /** Whether running in a browser */
  isBrowser: boolean;
  /** Whether running in a Web Worker */
  isWebWorker: boolean;
  /** Whether WASM is supported */
  hasWasm: boolean;
  /** Whether SharedArrayBuffer is supported */
  hasSharedArrayBuffer: boolean;
}

/**
 * Detects the current runtime environment
 */
export function detectEnvironment(): Environment {
  const isNode =
    typeof process !== 'undefined' &&
    process.versions != null &&
    typeof process.versions.node === 'string';
  const isWebWorker =
    typeof self === 'object' &&
    self.constructor &&
    self.constructor.name === 'DedicatedWorkerGlobalScope';
  const isBrowser = !isNode && !isWebWorker && typeof window !== 'undefined';

  return {
    isNode,
    isBrowser,
    isWebWorker,
    hasWasm: typeof WebAssembly === 'object',
    hasSharedArrayBuffer: typeof SharedArrayBuffer === 'function',
  };
}

/**
 * Initializes WebAssembly memory
 */
export async function initializeMemory(
  options: WasmLoadOptions = {}
): Promise<DIDCommResult<WebAssembly.Memory>> {
  try {
    const { initialPages = 16, maximumPages = 100 } = options.memory || {};
    const env = detectEnvironment();

    // Validate memory parameters
    if (initialPages <= 0 || initialPages > 65536) {
      return {
        success: false,
        error: {
          code: 'MEMORY_ERROR',
          message: 'Initial memory pages must be between 1 and 65536',
        },
      };
    }

    if (maximumPages < initialPages || maximumPages > 65536) {
      return {
        success: false,
        error: {
          code: 'MEMORY_ERROR',
          message: 'Maximum memory pages must be between initial pages and 65536',
        },
      };
    }

    try {
      const memory = new WebAssembly.Memory({
        initial: initialPages,
        maximum: maximumPages,
        shared: env.hasSharedArrayBuffer,
      });

      // Test memory growth within limits
      const currentPages = memory.buffer.byteLength / 65536;
      if (currentPages !== initialPages) {
        throw new Error('Memory initialization failed');
      }

      return { success: true, data: memory };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'MEMORY_ERROR',
          message:
            error instanceof Error ? error.message : 'Failed to initialize WebAssembly memory',
        },
      };
    }
  } catch (error) {
    return {
      success: false,
      error: {
        code: 'MEMORY_ERROR',
        message: error instanceof Error ? error.message : 'Failed to initialize WebAssembly memory',
      },
    };
  }
}

/**
 * Loads the appropriate WASM module based on environment and options
 */
export async function loadWasmModule(
  options: WasmLoadOptions = {}
): Promise<DIDCommResult<CoreWasmModule | NodeWasmModule>> {
  try {
    const env = detectEnvironment();

    if (!env.hasWasm) {
      return {
        success: false,
        error: {
          code: 'WASM_NOT_SUPPORTED',
          message: 'WebAssembly is not supported in this environment',
        },
      };
    }

    // Initialize memory first
    const memoryResult = await initializeMemory(options);
    if (!memoryResult.success || !memoryResult.data) {
      return {
        success: false,
        error: memoryResult.error || {
          code: 'MEMORY_ERROR',
          message: 'Failed to initialize memory',
        },
      };
    }

    // Try Node.js module first if requested
    if (options.useNode && env.isNode) {
      try {
        const nodeModule = (await import(DEFAULT_NODE_WASM_PATH)) as { default: NodeWasmModule };
        if (nodeModule.default && typeof nodeModule.default.initialize === 'function') {
          await nodeModule.default.initialize(memoryResult.data);
          return { success: true, data: nodeModule.default };
        }
      } catch (error) {
        console.warn('Failed to load Node.js WASM module, falling back to core:', error);
      }
    }

    // Load core module
    try {
      const coreModule = (await import(DEFAULT_CORE_WASM_PATH)) as { default: CoreWasmModule };
      if (coreModule.default && typeof coreModule.default.initialize === 'function') {
        await coreModule.default.initialize(memoryResult.data);
        return { success: true, data: coreModule.default };
      }
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'WASM_LOAD_ERROR',
          message: error instanceof Error ? error.message : 'Failed to load WASM module',
        },
      };
    }

    return {
      success: false,
      error: {
        code: 'WASM_INIT_ERROR',
        message: 'Failed to initialize WASM module',
      },
    };
  } catch (error) {
    return {
      success: false,
      error: {
        code: 'WASM_ERROR',
        message: error instanceof Error ? error.message : 'Unknown error loading WASM module',
      },
    };
  }
}
