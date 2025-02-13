import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const require = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

import fs from 'fs';

// Create pkg directories
const pkgDir = join(__dirname, '../pkg');
const corePkgDir = join(pkgDir, 'core');
const nodePkgDir = join(pkgDir, 'node');

// Create directories if they don't exist
[pkgDir, corePkgDir, nodePkgDir].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Copy core WASM files
const coreFiles = fs.readdirSync(join(__dirname, '../../tap-didcomm-core/pkg'));
coreFiles.forEach(file => {
  fs.copyFileSync(
    join(__dirname, '../../tap-didcomm-core/pkg', file),
    join(corePkgDir, file)
  );
});

// Copy node WASM files
const nodeFiles = fs.readdirSync(join(__dirname, '../../tap-didcomm-node/pkg'));
nodeFiles.forEach(file => {
  fs.copyFileSync(
    join(__dirname, '../../tap-didcomm-node/pkg', file),
    join(nodePkgDir, file)
  );
});

console.log('WASM files copied successfully!'); 