import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  minify: true,
  treeshake: true,
  target: 'es2020',
  outDir: 'dist',
  external: ['tap-didcomm-core', 'tap-didcomm-node', /\.wasm$/],
  esbuildOptions(options) {
    options.conditions = ['import', 'module', 'node', 'default'];
    options.mainFields = ['module', 'main'];
    options.loader = {
      '.wasm': 'file',
    };
  },
  onSuccess: 'pnpm run type-check',
});
