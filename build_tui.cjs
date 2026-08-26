const esbuild = require('esbuild');

esbuild.build({
  entryPoints: ['src/tui.ts'],
  bundle: true,
  platform: 'node',
  outfile: 'dist/tui.cjs'
}).catch((e) => { console.error(e); process.exit(1); });

