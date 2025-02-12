declare module "*/tap_didcomm_core" {
  export interface CoreWasmModule {
    memory: WebAssembly.Memory;
    encrypt: (message: string, recipients: string[]) => Promise<string>;
    decrypt: (message: string, key: string) => Promise<string>;
    sign: (message: string, key: string) => Promise<string>;
    verify: (message: string, key: string) => Promise<boolean>;
  }

  export default CoreWasmModule;
}

declare module "*/tap_didcomm_node" {
  export interface NodeWasmModule {
    memory: WebAssembly.Memory;
    encrypt: (message: string, recipients: string[]) => Promise<string>;
    decrypt: (message: string, key: string) => Promise<string>;
    sign: (message: string, key: string) => Promise<string>;
    verify: (message: string, key: string) => Promise<boolean>;
    resolveIdentifier: (did: string) => Promise<string>;
  }

  export default NodeWasmModule;
}

interface WorkerGlobalScope {
  readonly self: WorkerGlobalScope;
}

declare var WorkerGlobalScope: {
  prototype: WorkerGlobalScope;
  new (): WorkerGlobalScope;
};
