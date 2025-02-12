/**
 * WASM module loading utilities for DIDComm.
 * Handles dynamic loading of WASM modules in both Node.js and browser environments.
 */

import type { DIDCommResult } from '../types';
import type { CoreWasmModule, NodeWasmModule, WasmModuleImport } from './types';

// Default paths for WASM modules
const DEFAULT_CORE_WASM_PATH = '../pkg/core/tap_didcomm_core_bg.wasm';
const DEFAULT_NODE_WASM_PATH = '../pkg/node/tap_didcomm_node_bg.wasm';

/**
 * Configuration for WASM loading
 */
export interface WasmLoadConfig {
  /** Custom URL for the WASM file (browser only) */
  wasmUrl?: string;
  /** Whether to use Node.js optimized version */
  useNode?: boolean;
  /** Memory limit for WASM in pages (64KB each) */
  memoryLimit?: number;
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
 * Detects the current JavaScript environment
 */
export function detectEnvironment(): Environment {
  const isNode =
    typeof process !== 'undefined' && process.versions != null && process.versions.node != null;

  const isBrowser = typeof window !== 'undefined';
  const isWebWorker = typeof self !== 'undefined' && typeof self.WorkerGlobalScope !== 'undefined';
  const hasWasm = typeof WebAssembly !== 'undefined';
  const hasSharedArrayBuffer = typeof SharedArrayBuffer !== 'undefined';

  return {
    isNode,
    isBrowser,
    isWebWorker,
    hasWasm,
    hasSharedArrayBuffer,
  };
}

/**
 * Options for loading WASM modules
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
  /** Custom WASM URL (browser only) */
  wasmUrl?: string;
}

/**
 * Memory configuration options
 */
export interface MemoryOptions {
  /** Initial memory pages (64KB each) */
  initialPages?: number;
  /** Maximum memory pages (64KB each) */
  maximumPages?: number;
}

/**
 * Loads the appropriate WASM module based on environment
 */
export async function loadWasmModule(
  options: WasmLoadOptions = {}
): Promise<DIDCommResult<CoreWasmModule | NodeWasmModule>> {
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

  try {
    // Initialize memory first
    const memoryResult = await initializeMemory(options.memory);
    if (!memoryResult.success || !memoryResult.data) {
      return {
        success: false,
        error: {
          code: 'MEMORY_ERROR',
          message: memoryResult.error?.message || 'Failed to initialize memory',
        },
      };
    }

    // Try Node.js module first if requested
    if (options.useNode && env.isNode) {
      try {
        const nodeModule = (await import('../pkg/node/tap_didcomm_node')) as WasmModuleImport;
        await nodeModule.default.initialize(memoryResult.data);
        return { success: true, data: nodeModule.default };
      } catch (error) {
        console.warn('Failed to load Node.js WASM module, falling back to core:', error);
      }
    }

    // Load core module
    const coreModule = (await import('../pkg/core/tap_didcomm_core')) as WasmModuleImport;
    await coreModule.default.initialize(memoryResult.data);
    return { success: true, data: coreModule.default };
  } catch (error) {
    return {
      success: false,
      error: {
        code: 'WASM_LOAD_ERROR',
        message: `Failed to load WASM module: ${error instanceof Error ? error.message : String(error)}`,
      },
    };
  }
}

/**
 * Initializes WebAssembly memory
 */
export async function initializeMemory(
  options: MemoryOptions = {}
): Promise<DIDCommResult<WebAssembly.Memory>> {
  const {
    initialPages = 16, // 1MB default
    maximumPages = 256, // 16MB max
  } = options;

  try {
    const memory = new WebAssembly.Memory({
      initial: initialPages,
      maximum: maximumPages,
      shared: false,
    });

    return { success: true, data: memory };
  } catch (error) {
    return {
      success: false,
      error: {
        code: 'MEMORY_ERROR',
        message: `Failed to initialize WebAssembly memory: ${error instanceof Error ? error.message : String(error)}`,
      },
    };
  }
}
