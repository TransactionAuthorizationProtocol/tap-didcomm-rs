import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  resolve: {
    alias: {
      '@tap-didcomm/core': resolve(__dirname, './pkg/core/tap_didcomm_core.js'),
      '@tap-didcomm/node': resolve(__dirname, './pkg/node/tap_didcomm_node.js'),
    },
  },
});
