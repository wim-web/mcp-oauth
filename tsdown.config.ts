import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/oauth-provider.ts', 'src/next.ts', 'src/oidc/index.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  outDir: 'dist',
  fixedExtension: false,
});
