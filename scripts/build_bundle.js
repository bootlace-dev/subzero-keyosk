#!/usr/bin/env node
import { execSync } from 'child_process';
import * as esbuild from 'esbuild';

const now = new Date();
const pad = (n) => String(n).padStart(2, '0');
const yy = String(now.getUTCFullYear()).slice(2);
const mm = pad(now.getUTCMonth() + 1);
const dd = pad(now.getUTCDate());
const hh = pad(now.getUTCHours());
const min = pad(now.getUTCMinutes());
const buildStamp = `${yy}${mm}${dd}${hh}${min}Z`;

let gitSha = 'release';
try {
  gitSha = execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim();
} catch (_) {}

const target = process.argv[2] || 'all';

const configs = {
  tui: {
    entryPoints: ['src/tui.ts'],
    outfile: 'dist/tui.cjs',
    define: {
      '__BUILD_STAMP__': JSON.stringify(buildStamp),
      '__GIT_SHA__': JSON.stringify(gitSha)
    }
  },
  testnet4: {
    entryPoints: ['src/fb_testnet4.ts'],
    outfile: 'dist/tui_testnet4.cjs',
    define: {
      '__BUILD_STAMP__': JSON.stringify(buildStamp),
      '__GIT_SHA__': JSON.stringify(gitSha)
    }
  },
  vault: {
    entryPoints: ['src/fb_vault.ts'],
    outfile: 'dist/fb_vault.cjs',
    define: {
      '__BUILD_STAMP__': JSON.stringify(buildStamp),
      '__GIT_SHA__': JSON.stringify(gitSha)
    }
  }
};

const common = {
  bundle: true,
  platform: 'node',
  target: 'node20'
};

async function run() {
  if (target === 'tui' || target === 'all') {
    await esbuild.build({ ...common, ...configs.tui });
    console.log(`  dist/tui.cjs [${buildStamp}-${gitSha}]`);
  }
  if (target === 'testnet4' || target === 'all') {
    await esbuild.build({ ...common, ...configs.testnet4 });
    console.log(`  dist/tui_testnet4.cjs [${buildStamp}-${gitSha}]`);
  }
  if (target === 'vault' || target === 'all') {
    await esbuild.build({ ...common, ...configs.vault });
    execSync('cp src/templates/decrypt.html dist/decrypt.html');
    console.log(`  dist/fb_vault.cjs [${buildStamp}-${gitSha}]`);
  }
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
