import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { nodePolyfills } from 'vite-plugin-node-polyfills';
import path from 'path';

const baseVendor = '../airgap-coinflip/vendor';

export default defineConfig({
  plugins: [
    viteSingleFile(),
    nodePolyfills({
      include: ['buffer', 'stream', 'crypto', 'events'],
      globals: { Buffer: true, process: true }
    })
  ],
  resolve: {
    alias: [
      { find: /^@noble\/hashes$/, replacement: path.resolve(baseVendor, 'noble-hashes/src/index.ts') },
      { find: /^@noble\/hashes\/sha256(\.js)?$/, replacement: path.resolve(baseVendor, 'noble-hashes/src/sha2.ts') },
      { find: /^@noble\/hashes\/sha512(\.js)?$/, replacement: path.resolve(baseVendor, 'noble-hashes/src/sha2.ts') },
      { find: /^@noble\/hashes\/ripemd160(\.js)?$/, replacement: path.resolve(baseVendor, 'noble-hashes/src/legacy.ts') },
      { find: /^@noble\/hashes\/sha1(\.js)?$/, replacement: path.resolve(baseVendor, 'noble-hashes/src/legacy.ts') },
      { find: /^@noble\/hashes\/hmac(\.js)?$/, replacement: path.resolve(baseVendor, 'noble-hashes/src/hmac.ts') },
      { find: /^@noble\/hashes\/sha2(\.js)?$/, replacement: path.resolve(baseVendor, 'noble-hashes/src/sha2.ts') },
      { find: /^@noble\/hashes\/(.*)\.js$/, replacement: path.resolve(baseVendor, 'noble-hashes/src/$1.ts') },
      { find: /^@noble\/hashes\/(.*)$/, replacement: path.resolve(baseVendor, 'noble-hashes/src/$1.ts') },

      { find: /^@scure\/bip39$/, replacement: path.resolve(baseVendor, 'scure-bip39/src/index.ts') },
      { find: /^@scure\/bip39\/(.*)\.js$/, replacement: path.resolve(baseVendor, 'scure-bip39/src/$1.ts') },
      { find: /^@scure\/bip39\/(.*)$/, replacement: path.resolve(baseVendor, 'scure-bip39/src/$1.ts') },

      { find: /^bip32$/, replacement: path.resolve(baseVendor, 'bip32/ts-src/index.ts') },
      { find: /^@bitcoinerlab\/secp256k1$/, replacement: path.resolve(baseVendor, 'secp256k1/index.js') },
      
      { find: /^@noble\/curves$/, replacement: path.resolve(baseVendor, 'noble-curves/src/index.ts') },
      { find: /^@noble\/curves\/(.*)\.js$/, replacement: path.resolve(baseVendor, 'noble-curves/src/$1.ts') },
      { find: /^@noble\/curves\/(.*)$/, replacement: path.resolve(baseVendor, 'noble-curves/src/$1.ts') },
    ]
  },
  build: {
    modulePreload: false,
    rollupOptions: {
      output: {
        entryFileNames: 'app.js',
        assetFileNames: 'app.[ext]',
      },
    },
  },
});
