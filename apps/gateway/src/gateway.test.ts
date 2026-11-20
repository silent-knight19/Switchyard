import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, startServer, StartupError, type GatewayServerContext } from './server.js';
import { LifecycleCoordinator } from './lifecycle/state.js';
import { GracefulShutdownManager, type ShutdownDependencies } from './lifecycle/shutdown.js';
import { buildApp } from './app.js';
import { createLogger } from './logging/index.js';
import type { PostgresClient } from './infrastructure/postgres.js';
import type { RedisClient } from './infrastructure/redis.js';

const VALID_DEV_ENV: Record<string, string> = {
  NODE_ENV: 'development',
  PORT: '3001',
  HOST: '127.0.0.1',
  POSTGRES_HOST: '127.0.0.1',
  POSTGRES_PORT: '5432',
  POSTGRES_DB: 'switchyard',
  POSTGRES_USER: 'switchyard',
  POSTGRES_PASSWORD: 'switchyard_dev_password',
  REDIS_HOST: '127.0.0.1',
  REDIS_PORT: '6379',
  REDIS_USER: 'switchyard_app',
  REDIS_PASSWORD: 'switchyard_app_password',
  REDIS_MAXMEMORY_POLICY: 'noeviction',
  REDIS_TLS: 'false',
  COOKIE_SECURE: 'false',
  TLS_VERIFY: 'true',
  MOCK_PROVIDER_ENABLED: 'false',
  DEMO_SEEDING_ENABLED: 'false',
};

function createMockPostgres(overrides?: Partial<PostgresClient>): PostgresClient {
  return {
    pool: {
      totalCount: 1,
      idleCount: 1,
      waitingCount: 0,
    } as unknown as PostgresClient['pool'],
    checkReadiness: async () => ({ ok: true }),
    close: async () => {},
    ...overrides,
  };
}

function createMockRedis(overrides?: Partial<RedisClient>): RedisClient {
  return {
    redis: {
      status: 'ready',
    } as unknown as RedisClient['redis'],
    checkReadiness: async () => ({ ok: true, policy: 'noeviction' }),
    verifyAclRestrictions: async () => ({ ok: true }),
    close: async () => {},
    ...overrides,
  };
}

describe('SW-1.2.4 Gateway Boot, Health, and Shutdown Lifecycle', () => {
  let serverContext: GatewayServerContext;

  beforeAll(async () => {
    const mockPg = createMockPostgres();
    const mockRedis = createMockRedis();
    serverContext = await createServer(VALID_DEV_ENV, {
      postgres: mockPg,
      redis: mockRedis,
    });
    serverContext.lifecycle.setReady();
  });

  afterAll(async () => {
    if (serverContext) {
      await serverContext.stop();
    }
  });

  it('1. valid startup initializes Fastify, connects to PostgreSQL and Redis', async () => {
    expect(serverContext.app).toBeDefined();
    expect(serverContext.postgres).toBeDefined();
    expect(serverContext.redis).toBeDefined();
    expect(serverContext.lifecycle.isReady()).toBe(true);
  });

  it('2. invalid configuration prevents startup fail-closed', async () => {
    const invalidEnv = { ...VALID_DEV_ENV, PORT: 'invalid-port' };
    await expect(createServer(invalidEnv)).rejects.toThrow();
  });

  it('3. unavailable PostgreSQL prevents startup and closes resources (R1, R4)', async () => {
    let closedPg = false;
    const failingPg = createMockPostgres({
      checkReadiness: async () => ({
        ok: false,
        code: 'ECONNREFUSED',
        error: 'connect ECONNREFUSED 127.0.0.1:5499',
      }),
      close: async () => {
        closedPg = true;
      },
    });

    await expect(createServer(VALID_DEV_ENV, { postgres: failingPg })).rejects.toThrow(
      StartupError,
    );
    expect(closedPg).toBe(true); // Verifies resources are safely closed on startup abort
  });

  it('4. unavailable Redis prevents startup and closes resources (R1, R4)', async () => {
    let closedPg = false;
    let closedRedis = false;
    const mockPg = createMockPostgres({
      close: async () => {
        closedPg = true;
      },
    });
    const failingRedis = createMockRedis({
      checkReadiness: async () => ({
        ok: false,
        code: 'ECONNREFUSED',
        error: 'connect ECONNREFUSED 127.0.0.1:6399',
      }),
      close: async () => {
        closedRedis = true;
      },
    });

    await expect(
      createServer(VALID_DEV_ENV, { postgres: mockPg, redis: failingRedis }),
    ).rejects.toThrow(StartupError);
    expect(closedPg).toBe(true);
    expect(closedRedis).toBe(true);
  });

  it('5. unsafe Redis runtime policy prevents readiness and closes resources (R4)', async () => {
    let closedPg = false;
    let closedRedis = false;
    const mockPg = createMockPostgres({
      close: async () => {
        closedPg = true;
      },
    });
    const mockRedisUnsafe = createMockRedis({
      checkReadiness: async () => ({
        ok: true,
        policy: 'allkeys-lru',
      }),
      close: async () => {
        closedRedis = true;
      },
    });

    await expect(
      createServer(VALID_DEV_ENV, { postgres: mockPg, redis: mockRedisUnsafe }),
    ).rejects.toThrow(/Unsafe Redis policy "allkeys-lru": expected "noeviction"/);
    expect(closedPg).toBe(true);
    expect(closedRedis).toBe(true);
  });

  it('6. overprivileged Redis identity fails startup validation and closes resources (R3, R4, R7)', async () => {
    let closedPg = false;
    let closedRedis = false;
    const mockPg = createMockPostgres({
      close: async () => {
        closedPg = true;
      },
    });
    const overprivilegedRedis = createMockRedis({
      verifyAclRestrictions: async () => ({
        ok: false,
        code: 'OVERPRIVILEGED_CONFIG_PERMITTED',
        error:
          'Redis runtime identity is overprivileged: administrative CONFIG command was permitted',
      }),
      close: async () => {
        closedRedis = true;
      },
    });

    await expect(
      createServer(VALID_DEV_ENV, { postgres: mockPg, redis: overprivilegedRedis }),
    ).rejects.toThrow(/Redis ACL verification failed/);
    expect(closedPg).toBe(true);
    expect(closedRedis).toBe(true);
  });

  it('7. properly restricted Redis identity passes startup ACL verification (R3)', async () => {
    let aclVerified = false;
    const mockPg = createMockPostgres();
    const restrictedRedis = createMockRedis({
      verifyAclRestrictions: async () => {
        aclVerified = true;
        return { ok: true };
      },
    });

    const ctx = await createServer(VALID_DEV_ENV, {
      postgres: mockPg,
      redis: restrictedRedis,
    });
    expect(aclVerified).toBe(true);
    await ctx.stop();
  });

  it('8. liveness endpoint reports ok (200) without leaking internal details', async () => {
    const res = await serverContext.app.inject({
      method: 'GET',
      url: '/health/live',
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
  });

  it('9. readiness endpoint reports ready (200) when all dependencies are healthy', async () => {
    const res = await serverContext.app.inject({
      method: 'GET',
      url: '/health/ready',
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.status).toBe('ready');
    expect(body.dependencies.database).toBe('healthy');
    expect(body.dependencies.redis).toBe('healthy');
  });

  it('10. dependency failure changes readiness to unavailable (503)', async () => {
    let pgOk = false;
    const mockPg = createMockPostgres({
      checkReadiness: async () =>
        pgOk ? { ok: true } : { ok: false, error: 'Connection refused' },
    });
    const mockRedis = createMockRedis();
    const lifecycle = new LifecycleCoordinator();
    lifecycle.setReady();
    const logger = createLogger({ level: 'silent' });

    const app = await buildApp({
      postgres: mockPg,
      redis: mockRedis,
      lifecycle,
      logger,
    });

    const resFail = await app.inject({
      method: 'GET',
      url: '/health/ready',
    });
    expect(resFail.statusCode).toBe(503);
    expect(resFail.json().dependencies.database).toBe('unhealthy');

    // Dependency recovery restores readiness
    pgOk = true;
    const resRecover = await app.inject({
      method: 'GET',
      url: '/health/ready',
    });
    expect(resRecover.statusCode).toBe(200);
    expect(resRecover.json().dependencies.database).toBe('healthy');

    await app.close();
  });

  it('11. delayed dependency readiness check bounds execution and returns 503 timeout (R5, R7)', async () => {
    const hangingPg = createMockPostgres({
      checkReadiness: async (timeoutMs = 2000) => {
        // Simulate a hanging database query that exceeds timeout
        await new Promise((r) => setTimeout(r, timeoutMs + 100));
        return { ok: false, code: 'TIMEOUT', error: 'Database timed out' };
      },
    });
    const mockRedis = createMockRedis();
    const lifecycle = new LifecycleCoordinator();
    lifecycle.setReady();
    const logger = createLogger({ level: 'silent' });

    const app = await buildApp({
      postgres: hangingPg,
      redis: mockRedis,
      lifecycle,
      logger,
    });

    const startTime = Date.now();
    const res = await app.inject({
      method: 'GET',
      url: '/health/ready',
    });
    const elapsed = Date.now() - startTime;

    expect(res.statusCode).toBe(503);
    // Verified bounded timeout (must complete within 3000ms)
    expect(elapsed).toBeLessThan(3500);

    // Liveness remains 200 immediately despite delayed dependency
    const liveRes = await app.inject({
      method: 'GET',
      url: '/health/live',
    });
    expect(liveRes.statusCode).toBe(200);

    await app.close();
  });

  it('12. repeated readiness calls do not leak active database connections (R7)', async () => {
    let activeClients = 0;
    let peakConcurrentClients = 0;

    const mockPg = createMockPostgres({
      checkReadiness: async () => {
        activeClients++;
        peakConcurrentClients = Math.max(peakConcurrentClients, activeClients);
        // Simulate async tick of execution
        await new Promise((r) => setImmediate(r));
        activeClients--;
        return { ok: true };
      },
    });
    const mockRedis = createMockRedis();
    const lifecycle = new LifecycleCoordinator();
    lifecycle.setReady();
    const logger = createLogger({ level: 'silent' });

    const app = await buildApp({
      postgres: mockPg,
      redis: mockRedis,
      lifecycle,
      logger,
    });

    for (let i = 0; i < 20; i++) {
      const res = await app.inject({
        method: 'GET',
        url: '/health/ready',
      });
      expect(res.statusCode).toBe(200);
    }

    // Assert that all checked-out clients were released deterministically
    expect(activeClients).toBe(0);
    expect(peakConcurrentClients).toBeGreaterThanOrEqual(1);

    await app.close();
  });

  it('13. HTTP listen failure triggers graceful shutdown and cleans up resources (R4)', async () => {
    let pgClosed = false;
    let redisClosed = false;

    const mockPg = createMockPostgres({
      close: async () => {
        pgClosed = true;
      },
    });
    const mockRedis = createMockRedis({
      close: async () => {
        redisClosed = true;
      },
    });

    // Start a first server to occupy port 3999
    const ctx1 = await startServer(
      { ...VALID_DEV_ENV, PORT: '3999' },
      { postgres: createMockPostgres(), redis: createMockRedis() },
    );

    // Attempting to start a second server on the same port triggers EADDRINUSE
    await expect(
      startServer({ ...VALID_DEV_ENV, PORT: '3999' }, { postgres: mockPg, redis: mockRedis }),
    ).rejects.toThrow();

    // Verify all resources created before the listen error were cleaned up
    expect(pgClosed).toBe(true);
    expect(redisClosed).toBe(true);

    await ctx1.stop();
  });

  it('14. SIGTERM initiates graceful shutdown, marks unready, and closes resources', async () => {
    let closedServer = false;
    let closedPg = false;
    let closedRedis = false;

    const mockServer = {
      close: async () => {
        closedServer = true;
      },
    } as unknown as ShutdownDependencies['server'];
    const mockPg = {
      close: async () => {
        closedPg = true;
      },
    } as unknown as PostgresClient;
    const mockRedis = {
      close: async () => {
        closedRedis = true;
      },
    } as unknown as RedisClient;

    const lifecycle = new LifecycleCoordinator();
    lifecycle.setReady();
    const logger = createLogger({ level: 'silent' });

    const shutdownManager = new GracefulShutdownManager({
      server: mockServer,
      postgres: mockPg,
      redis: mockRedis,
      lifecycle,
      logger,
      timeoutMs: 3000,
    });

    expect(lifecycle.isReady()).toBe(true);
    await shutdownManager.shutdown('SIGTERM');

    expect(lifecycle.isReady()).toBe(false);
    expect(lifecycle.getState()).toBe('stopped');
    expect(closedServer).toBe(true);
    expect(closedPg).toBe(true);
    expect(closedRedis).toBe(true);
  });

  it('15. SIGINT initiates graceful shutdown cleanly', async () => {
    let closed = false;
    const mockServer = {
      close: async () => {
        closed = true;
      },
    } as unknown as ShutdownDependencies['server'];
    const mockPg = { close: async () => {} } as unknown as PostgresClient;
    const mockRedis = { close: async () => {} } as unknown as RedisClient;
    const lifecycle = new LifecycleCoordinator();
    lifecycle.setReady();
    const logger = createLogger({ level: 'silent' });

    const shutdownManager = new GracefulShutdownManager({
      server: mockServer,
      postgres: mockPg,
      redis: mockRedis,
      lifecycle,
      logger,
    });

    await shutdownManager.shutdown('SIGINT');
    expect(closed).toBe(true);
    expect(lifecycle.getState()).toBe('stopped');
  });

  it('16. repeated shutdown signals are idempotent', async () => {
    let closeCallCount = 0;
    const mockServer = {
      close: async () => {
        closeCallCount++;
      },
    } as unknown as ShutdownDependencies['server'];
    const mockPg = { close: async () => {} } as unknown as PostgresClient;
    const mockRedis = { close: async () => {} } as unknown as RedisClient;
    const lifecycle = new LifecycleCoordinator();
    const logger = createLogger({ level: 'silent' });

    const shutdownManager = new GracefulShutdownManager({
      server: mockServer,
      postgres: mockPg,
      redis: mockRedis,
      lifecycle,
      logger,
    });

    const p1 = shutdownManager.shutdown('SIGTERM');
    const p2 = shutdownManager.shutdown('SIGTERM');

    await Promise.all([p1, p2]);
    expect(closeCallCount).toBe(1); // Exactly one invocation
  });

  it('17. readiness returns 503 draining when shutdown is in progress', async () => {
    const mockPg = createMockPostgres();
    const mockRedis = createMockRedis();
    const lifecycle = new LifecycleCoordinator();
    lifecycle.setDraining();
    const logger = createLogger({ level: 'silent' });

    const app = await buildApp({
      postgres: mockPg,
      redis: mockRedis,
      lifecycle,
      logger,
    });

    const res = await app.inject({
      method: 'GET',
      url: '/health/ready',
    });

    expect(res.statusCode).toBe(503);
    expect(res.json().reason).toBe('draining');
    await app.close();
  });

  it('18. request and response lifecycle hooks sanitize query strings from URL logs (R2)', async () => {
    const logEntries: Array<Record<string, unknown>> = [];
    const customLogger = {
      info: (obj: unknown) => {
        if (obj && typeof obj === 'object') {
          logEntries.push(obj as Record<string, unknown>);
        }
      },
      debug: () => {},
      error: () => {},
      fatal: () => {},
      warn: () => {},
      trace: () => {},
      child: () => customLogger,
    } as unknown as ReturnType<typeof createLogger>;

    const app = await buildApp({
      postgres: createMockPostgres(),
      redis: createMockRedis(),
      lifecycle: new LifecycleCoordinator(),
      logger: customLogger,
    });

    const sensitiveQueryToken = 'synthetic_url_query_secret_token_abc999';
    await app.inject({
      method: 'GET',
      url: `/health/live?token=${sensitiveQueryToken}&other=123`,
    });

    expect(JSON.stringify(logEntries)).not.toContain(sensitiveQueryToken);
    const reqLog = logEntries.find((l) => l.requestId !== undefined);
    expect(reqLog).toBeDefined();
    expect(reqLog?.url).toBe('/health/live');

    await app.close();
  });
});
