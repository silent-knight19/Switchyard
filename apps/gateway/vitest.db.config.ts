import { defineConfig } from 'vitest/config';

/**
 * Database migration, schema, and privilege suite. Every test file starts its own disposable
 * PostgreSQL 16 container (or uses TEST_POSTGRES_ADMIN_URL when it points at a disposable
 * cluster) and never contacts the persistent development database. A missing Docker daemon or
 * unreachable PostgreSQL fails the run; nothing is skipped.
 */
export default defineConfig({
  test: {
    include: ['src/**/*.db.test.ts'],
    fileParallelism: false,
    hookTimeout: 240_000,
    testTimeout: 120_000,
  },
});
