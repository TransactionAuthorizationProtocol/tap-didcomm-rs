/**
 * Type definitions for WASM modules
 */

/**
 * Core WASM module interface
 */
export interface CoreWasmModule {
  /** WebAssembly memory instance */
  memory: WebAssembly.Memory;
  /** Initialize the module */
  initialize(memory: WebAssembly.Memory): Promise<void>;
  /** Encrypt a message */
  encrypt(message: string, recipients: string[]): Promise<string>;
  /** Decrypt a message */
  decrypt(message: string, key: string): Promise<string>;
  /** Sign a message */
  sign(message: string, key: string): Promise<string>;
  /** Verify a message signature */
  verify(message: string, key: string): Promise<boolean>;
}

/**
 * Node.js WASM module interface
 */
export interface NodeWasmModule extends CoreWasmModule {
  /** Resolve a DID */
  resolveIdentifier(did: string): Promise<string>;
}

/**
 * Type declaration for WorkerGlobalScope
 */
export interface WorkerGlobalScope {
  readonly self: WorkerGlobalScope;
}

/**
 * Type declaration for WASM module imports
 */
export interface WasmModuleImport {
  default: CoreWasmModule | NodeWasmModule;
}
