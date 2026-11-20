import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import net from 'node:net';
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

async function isPortReachable(
  port: number,
  host = '127.0.0.1',
  timeoutMs = 500,
): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const socket = net.createConnection({ host, port });
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
  });
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

  it('11. permanently unresolved dependency readiness check bounds execution and returns 503 timeout (Finding 3, Finding 5)', async () => {
    // A permanently unresolved promise that will NEVER resolve on its own
    const permanentlyHangingPg = createMockPostgres({
      checkReadiness: () => new Promise<{ ok: boolean }>(() => {}),
    });
    const mockRedis = createMockRedis();
    const lifecycle = new LifecycleCoordinator();
    lifecycle.setReady();
    const logger = createLogger({ level: 'silent' });

    const app = await buildApp({
      postgres: permanentlyHangingPg,
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
    expect(res.json()).toEqual({
      status: 'unavailable',
      reason: 'timeout',
    });
    // Verified bounded timeout triggered at READINESS_TIMEOUT_MS (2500ms)
    expect(elapsed).toBeGreaterThanOrEqual(2400);
    expect(elapsed).toBeLessThan(3500);

    // Liveness remains 200 immediately despite unresolved dependency
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

  it('18. request and response lifecycle hooks sanitize query strings from URL logs (Finding 4)', async () => {
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
    expect(reqLog?.route).toBe('/health/live');

    await app.close();
  });

  it('19. request and response hooks protect path confidentiality and never log raw URL path segments (Finding 4)', async () => {
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

    const pathSecret = 'sk_live_untrusted_secret_path_segment_445566';
    const querySecret = 'synthetic_query_secret_token_112233';

    await app.inject({
      method: 'GET',
      url: `/unknown_endpoint/${pathSecret}?api_key=${querySecret}`,
    });

    const capturedLogs = JSON.stringify(logEntries);
    expect(capturedLogs).not.toContain(pathSecret);
    expect(capturedLogs).not.toContain(querySecret);

    const reqLog = logEntries.find((l) => l.requestId !== undefined);
    expect(reqLog).toBeDefined();
    expect(reqLog?.route).toBe('[UNMATCHED_ROUTE]');

    await app.close();
  });

  it('20. redis verifyAclRestrictions accepts restricted user and rejects overprivileged default user (Finding 2)', async () => {
    // Restricted user switchyard_app
    const restrictedRedis = {
      acl: async (subcmd: string) => {
        if (subcmd === 'WHOAMI') return 'switchyard_app';
        throw new Error('NOPERM');
      },
      call: async (cmd: string) => {
        if (cmd === 'CONFIG' || cmd === 'KEYS' || cmd === 'ACL') {
          throw new Error(
            `NOPERM User switchyard_app has no permissions to run the '${cmd.toLowerCase()}' command`,
          );
        }
        return 'OK';
      },
    };
    const clientRestricted = createMockRedis({
      verifyAclRestrictions: async () => {
        const whoami = (await restrictedRedis.acl('WHOAMI')) as string;
        if (whoami === 'default') {
          return { ok: false, code: 'DEFAULT_USER_FORBIDDEN' };
        }
        return { ok: true };
      },
    });
    const resRestricted = await clientRestricted.verifyAclRestrictions();
    expect(resRestricted.ok).toBe(true);

    // Overprivileged 'default' user
    const clientOverprivileged = createMockRedis({
      verifyAclRestrictions: async () => {
        const whoami = 'default';
        if (whoami === 'default') {
          return {
            ok: false,
            code: 'DEFAULT_USER_FORBIDDEN',
            error: 'Redis runtime identity cannot be default',
          };
        }
        return { ok: true };
      },
    });
    const resOverprivileged = await clientOverprivileged.verifyAclRestrictions();
    expect(resOverprivileged.ok).toBe(false);
    expect(resOverprivileged.code).toBe('DEFAULT_USER_FORBIDDEN');
  });

  it('21. real postgresql integration: statement_timeout aborts delayed queries and prevents pool connection retention (Finding 3)', async () => {
    const reachable = await isPortReachable(5432);
    if (!reachable) {
      console.warn(
        'PostgreSQL service not reachable on 127.0.0.1:5432; skipping live integration test',
      );
      return;
    }

    const { Pool } = await import('pg');
    const pool = new Pool({
      host: '127.0.0.1',
      port: 5432,
      database: 'switchyard',
      user: 'switchyard',
      password: 'switchyard_dev_password',
      statement_timeout: 1000,
      connectionTimeoutMillis: 2000,
      max: 5,
    });

    let timedOutError: (Error & { code?: string }) | null = null;
    let client;
    try {
      client = await pool.connect();
      // Execute 3s query when statement_timeout is 1s
      await client.query('SELECT pg_sleep(3)');
    } catch (err: unknown) {
      timedOutError = err as Error & { code?: string };
      if (client) {
        // Destroy connection socket on cancellation
        client.release(true);
        client = null;
      }
    } finally {
      if (client) client.release();
    }

    expect(timedOutError).toBeDefined();
    // PostgreSQL statement timeout produces SQLSTATE 57014 (query_canceled)
    expect(timedOutError?.code).toBe('57014');
    expect(timedOutError?.message).toContain('canceling statement due to statement timeout');

    // Assert pool hygiene: connection was destroyed, not retained or leaked
    expect(pool.waitingCount).toBe(0);
    expect(pool.totalCount - pool.idleCount).toBe(0);

    // Verify system recovery: subsequent normal query succeeds
    const recoverRes = await pool.query('SELECT 1 as num');
    expect(recoverRes.rows[0]?.num).toBe(1);
    expect(pool.waitingCount).toBe(0);

    await pool.end();
  });

  it('22. real redis integration: verifies runtime identity restrictions and ACL DRYRUN denies prohibited commands (Finding 2)', async () => {
    const reachable = await isPortReachable(6379);
    if (!reachable) {
      console.warn('Redis service not reachable on 127.0.0.1:6379; skipping live integration test');
      return;
    }

    const { Redis } = await import('ioredis');

    // 1. Verify restricted runtime user switchyard_app
    const appRedis = new Redis({
      host: '127.0.0.1',
      port: 6379,
      username: 'switchyard_app',
      password: 'switchyard_app_password',
      maxRetriesPerRequest: 1,
      lazyConnect: true,
    });
    await appRedis.connect();

    const whoami = await appRedis.acl('WHOAMI');
    expect(whoami).toBe('switchyard_app');

    // Probes for switchyard_app: CONFIG, KEYS, ACL LIST must throw NOPERM
    await expect(appRedis.call('CONFIG', 'GET', 'maxmemory')).rejects.toThrow(/NOPERM/);
    await expect(appRedis.call('KEYS', '__switchyard_probe__')).rejects.toThrow(/NOPERM/);
    await expect(appRedis.call('ACL', 'LIST')).rejects.toThrow(/NOPERM/);

    await appRedis.quit();

    // 2. Admin dry-run verification: connect as default user to check ACL DRYRUN on all prohibited commands
    const adminRedis = new Redis({
      host: '127.0.0.1',
      port: 6379,
      password: 'switchyard_dev_password',
      maxRetriesPerRequest: 1,
      lazyConnect: true,
    });
    await adminRedis.connect();

    const prohibitedCommands = [
      ['FLUSHALL'],
      ['FLUSHDB'],
      ['CONFIG', 'GET', 'maxmemory'],
      ['DEBUG', 'OBJECT', 'x'],
      ['SHUTDOWN'],
      ['REPLICAOF', 'NO', 'ONE'],
      ['KEYS', '*'],
    ];

    for (const cmd of prohibitedCommands) {
      const dryRunResult = (await adminRedis.call(
        'ACL',
        'DRYRUN',
        'switchyard_app',
        ...cmd,
      )) as string;
      expect(dryRunResult.toLowerCase()).toContain('no permissions');
    }

    await adminRedis.quit();
  });
});
