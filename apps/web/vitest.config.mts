import { defineConfig } from 'vitest/config';

export default defineConfig({
  oxc: {
    jsx: {
      runtime: 'automatic',
    },
  },
  test: {
    environment: 'node',
    exclude: ['**/node_modules/**', '**/.next/**', '**/dist/**'],
  },
});
