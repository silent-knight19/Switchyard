import { defineConfig } from 'vitest/config';

/**
 * Default unit/integration suite. Database migration and privilege tests are excluded here
 * because they require a disposable PostgreSQL cluster; CI runs them through the dedicated
 * `test:db` gate so they can never be silently skipped (review finding DB-11).
 */
export default defineConfig({
  test: {
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.{idea,git,cache,output,temp}/**',
      '**/*.db.test.ts',
    ],
    hookTimeout: 60_000,
    testTimeout: 30_000,
  },
});
