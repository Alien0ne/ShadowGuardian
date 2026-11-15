import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    clean: true,
    target: 'es2019',
  },
  {
    // Drop-in <script> build. Exposes `window.ShadowGuardian`.
    entry: { shadowguardian: 'src/index.ts' },
    format: ['iife'],
    globalName: 'ShadowGuardian',
    minify: true,
    sourcemap: false,
    target: 'es2019',
    outExtension: () => ({ js: '.global.js' }),
  },
]);
