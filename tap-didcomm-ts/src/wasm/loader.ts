/**
 * WASM module loader and initialization utilities.
 * This module handles loading and initializing WebAssembly modules for DIDComm operations.
 * @module wasm/loader
 */

import type { CoreWasmModule, NodeWasmModule } from './types';
import type { DIDCommResult } from '../types';

/**
 * Options for loading and initializing WASM modules.
 */
export interface WasmLoadOptions {
  /** Whether to use Node.js-specific optimizations */
  useNode?: boolean;
  /** Memory configuration for the WASM module */
  memory?: {
    /** Initial memory pages (64KB each) */
    initialPages?: number;
    /** Maximum memory pages (64KB each) */
    maximumPages?: number;
  };
}

/**
 * Information about the execution environment.
 * Used to determine the appropriate WASM loading strategy.
 */
export interface Environment {
  /** Whether running in Node.js */
  isNode: boolean;
  /** Whether running in a browser */
  isBrowser: boolean;
  /** Whether running in a Web Worker */
  isWebWorker: boolean;
  /** Whether WebAssembly is supported */
  hasWasm: boolean;
  /** Whether SharedArrayBuffer is supported (needed for threading) */
  hasSharedArrayBuffer: boolean;
}

/**
 * Detects the current execution environment.
 * This helps determine which WASM loading strategy to use.
 *
 * @returns Information about the current environment
 *
 * @example
 * ```typescript
 * const env = detectEnvironment();
 * if (env.hasWasm && env.hasSharedArrayBuffer) {
 *   console.log('Environment supports threaded WASM');
 * }
 * ```
 */
export function detectEnvironment(): Environment {
  const isNode =
    typeof process !== 'undefined' && process.versions != null && process.versions.node != null;

  const isBrowser = typeof window !== 'undefined' && typeof window.document !== 'undefined';

  const isWebWorker =
    typeof self === 'object' &&
    self.constructor &&
    self.constructor.name === 'DedicatedWorkerGlobalScope';

  const hasWasm = typeof WebAssembly !== 'undefined' && WebAssembly.validate != null;

  const hasSharedArrayBuffer =
    typeof SharedArrayBuffer !== 'undefined' && typeof Atomics !== 'undefined';

  return {
    isNode,
    isBrowser,
    isWebWorker,
    hasWasm,
    hasSharedArrayBuffer,
  };
}

/**
 * Initializes WebAssembly memory with the specified configuration.
 * This creates a new WebAssembly.Memory instance that can be used by WASM modules.
 *
 * @param options - Memory configuration options
 * @returns A promise that resolves to the initialized memory
 * @throws If memory initialization fails or limits are invalid
 *
 * @example
 * ```typescript
 * const memory = await initializeMemory({
 *   initialPages: 16,
 *   maximumPages: 256
 * });
 * ```
 */
export async function initializeMemory(
  options: WasmLoadOptions = {}
): Promise<DIDCommResult<WebAssembly.Memory>> {
  try {
    const { memory = {} } = options;
    const { initialPages = 16, maximumPages = 100 } = memory;

    if (initialPages < 0 || maximumPages < 0) {
      throw new Error('Memory pages cannot be negative');
    }

    if (initialPages > maximumPages) {
      throw new Error('Initial pages cannot exceed maximum pages');
    }

    const wasmMemory = new WebAssembly.Memory({
      initial: initialPages,
      maximum: maximumPages,
      shared: detectEnvironment().hasSharedArrayBuffer,
    });

    return {
      success: true,
      data: wasmMemory,
    };
  } catch (error) {
    return {
      success: false,
      error: {
        code: 'MEMORY_ERROR',
        message: error instanceof Error ? error.message : 'Memory initialization failed',
      },
    };
  }
}

/**
 * Loads and initializes the appropriate WASM module based on the environment.
 * This will attempt to load the Node.js optimized module if specified, falling back
 * to the core module if needed.
 *
 * @param options - Module loading options
 * @returns A promise that resolves to the loaded WASM module
 * @throws If module loading fails or WASM is not supported
 *
 * @example
 * ```typescript
 * const module = await loadWasmModule({
 *   useNode: process.env.NODE_ENV === 'production',
 *   memory: { initialPages: 16 }
 * });
 * ```
 */
export async function loadWasmModule(
  options: WasmLoadOptions = {}
): Promise<DIDCommResult<CoreWasmModule | NodeWasmModule>> {
  try {
    const env = detectEnvironment();
    if (!env.hasWasm) {
      throw new Error('WebAssembly is not supported in this environment');
    }

    // Initialize memory first
    const memoryResult = await initializeMemory(options);
    if (!memoryResult.success) {
      throw new Error(memoryResult.error?.message);
    }

    // Try loading Node.js optimized module if requested
    if (options.useNode && env.isNode) {
      try {
        const nodeModule = await import('@tap-didcomm/node');
        await nodeModule.default.initialize(memoryResult.data);
        return {
          success: true,
          data: nodeModule.default,
        };
      } catch (error) {
        console.warn('Failed to load Node.js module, falling back to core:', error);
      }
    }

    // Load core module
    const coreModule = await import('@tap-didcomm/core');
    await coreModule.default.initialize(memoryResult.data);
    return {
      success: true,
      data: coreModule.default,
    };
  } catch (error) {
    return {
      success: false,
      error: {
        code: 'MODULE_LOAD_ERROR',
        message: error instanceof Error ? error.message : 'Failed to load WASM module',
      },
    };
  }
}
