/**
 * Type declarations for WASM modules
 */

declare module "../pkg/core/tap_didcomm_core" {
  interface CoreWasmModule {
    initSync: (wasmUrl: string) => Promise<void>;
    memory: WebAssembly.Memory | null;
    [key: string]: unknown;
  }
  const module: { default: CoreWasmModule };
  export default module.default;
}

declare module "../pkg/node/tap_didcomm_node" {
  interface NodeWasmModule {
    memory: WebAssembly.Memory | null;
    [key: string]: unknown;
  }
  const module: { default: NodeWasmModule };
  export default module.default;
}

declare interface WorkerGlobalScope {
  readonly self: WorkerGlobalScope;
}
