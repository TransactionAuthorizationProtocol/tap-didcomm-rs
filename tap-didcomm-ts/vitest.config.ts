import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/unit/**/*.test.ts'],
    exclude: ['tests/browser/**/*'],
  },
  resolve: {
    alias: {
      '@tap-didcomm/core': resolve(__dirname, './pkg/core/tap_didcomm_core.js'),
      '@tap-didcomm/node': resolve(__dirname, './pkg/node/tap_didcomm_node.js'),
    },
  },
});
