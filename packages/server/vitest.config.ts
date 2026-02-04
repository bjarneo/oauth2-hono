import { defineConfig } from 'vitest/config';

export default defineConfig({
  css: {
    postcss: {},
  },
  test: {
    globals: false,
    environment: 'node',
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/__tests__/**'],
    },
    testTimeout: 30000,
  },
});
