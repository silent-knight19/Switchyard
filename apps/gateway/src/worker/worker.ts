import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';
import { Redis } from 'ioredis';
import { parseWorkerConfig, type WorkerConfig } from './config.js';
import { getWorkerLogger } from '../logging/index.js';

export interface DependencyStatus {
  database: 'healthy' | 'unhealthy';
  redis: 'healthy' | 'unhealthy';
}

export interface WorkerReadinessResult {
  ok: boolean;
  status: 'ready' | 'unhealthy' | 'shutting_down';
  dependencies: DependencyStatus;
  error?: string | undefined;
}

export interface WorkerContext {
  config: WorkerConfig;
  pgPool: pg.Pool;
  redis: Redis;
  isReady(): boolean;
  getDependencyStatus(): DependencyStatus;
  checkReadiness(timeoutMs?: number): Promise<WorkerReadinessResult>;
  runHealthProbe(): Promise<WorkerReadinessResult>;
  stop(): Promise<void>;
}

export interface WorkerDependencies {
  pgPool?: pg.Pool;
  redis?: Redis;
}

export class WorkerStartupError extends Error {
  public readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'WorkerStartupError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export async function executeDependencyProbe(
  pgPool: pg.Pool,
  redis: Redis,
  timeoutMs = 2000,
): Promise<{
  ok: boolean;
  dependencies: DependencyStatus;
  error?: string | undefined;
}> {
  const dependencies: DependencyStatus = {
    database: 'unhealthy',
    redis: 'unhealthy',
  };

  const probeAction = async (): Promise<{
    ok: boolean;
    dependencies: DependencyStatus;
    error?: string | undefined;
  }> => {
    // 1. Database connectivity check under restricted worker role
    let pgOk = false;
    let pgClient: pg.PoolClient | null = null;
    try {
      pgClient = await pgPool.connect();
      await pgClient.query('SELECT 1');
      pgOk = true;
      dependencies.database = 'healthy';
    } catch {
      dependencies.database = 'unhealthy';
    } finally {
      if (pgClient) {
        try {
          pgClient.release();
        } catch {
          /* ignore release errors */
        }
      }
    }

    // 2. Redis connectivity check under restricted worker ACL
    let redisOk = false;
    try {
      const pong = await redis.ping();
      if (pong === 'PONG') {
        redisOk = true;
        dependencies.redis = 'healthy';
      } else {
        dependencies.redis = 'unhealthy';
      }
    } catch {
      dependencies.redis = 'unhealthy';
    }

    const ok = pgOk && redisOk;
    return {
      ok,
      dependencies,
      error: ok ? undefined : 'Worker dependency check failed',
    };
  };

  let timer: NodeJS.Timeout | null = null;
  const timeoutPromise = new Promise<{
    ok: boolean;
    dependencies: DependencyStatus;
    error?: string | undefined;
  }>((resolve) => {
    timer = setTimeout(() => {
      resolve({
        ok: false,
        dependencies,
        error: 'Worker readiness check timed out',
      });
    }, timeoutMs);
    timer.unref();
  });

  try {
    return await Promise.race([probeAction(), timeoutPromise]);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}

export async function createWorker(
  envOverride?: Record<string, string | undefined>,
  dependencies?: WorkerDependencies,
): Promise<WorkerContext> {
  // Step 1: Validate worker configuration
  const config = parseWorkerConfig(envOverride);
  const logger = getWorkerLogger();

  logger.info({ env: config.NODE_ENV }, 'Initializing Switchyard Worker runtime foundation');

  let pgPool: pg.Pool | null = dependencies?.pgPool ?? null;
  let redis: Redis | null = dependencies?.redis ?? null;
  let heartbeatTimer: NodeJS.Timeout | null = null;
  let isReadyState = false;
  let isStopping = false;
  let isProbing = false;
  let currentDependencies: DependencyStatus = {
    database: 'unhealthy',
    redis: 'unhealthy',
  };

  const writeHealthFileOrThrow = (
    status: 'ready' | 'unhealthy' | 'shutting_down',
    deps: DependencyStatus,
    reason?: string,
  ): void => {
    const dir = path.dirname(config.WORKER_HEALTH_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const payload = JSON.stringify({
      status,
      pid: process.pid,
      timestamp: Date.now(),
      worker: status === 'ready' ? 'operational' : 'degraded',
      dependencies: deps,
      ...(reason ? { reason } : {}),
    });
    fs.writeFileSync(config.WORKER_HEALTH_FILE, payload, 'utf8');
  };

  const cleanup = async () => {
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = null;
    }
    if (redis) {
      try {
        await redis.quit();
      } catch {
        redis.disconnect();
      }
    }
    if (pgPool) {
      try {
        await pgPool.end();
      } catch {
        /* ignore */
      }
    }
    try {
      if (fs.existsSync(config.WORKER_HEALTH_FILE)) {
        fs.unlinkSync(config.WORKER_HEALTH_FILE);
      }
    } catch {
      /* ignore */
    }
  };

  try {
    // Step 2: Initialize and verify PostgreSQL under gateway_worker identity
    if (!pgPool) {
      pgPool = new pg.Pool({
        host: config.POSTGRES_HOST,
        port: config.POSTGRES_PORT,
        database: config.POSTGRES_DB,
        user: config.POSTGRES_USER,
        password: config.POSTGRES_PASSWORD,
        connectionTimeoutMillis: 3000,
        max: 5,
        min: 1,
      });
      pgPool.on('error', (err) => {
        logger.error({ err }, 'Unexpected error on idle worker PostgreSQL client');
      });
    }

    // Verify database connectivity and role
    const pgClient = await pgPool.connect();
    try {
      const { rows } = await pgClient.query<{
        usename: string;
        usesuper: boolean;
      }>('SELECT current_user AS usename, usesuper FROM pg_user WHERE usename = current_user');

      const userRow = rows[0];
      if (!userRow || userRow.usename !== 'gateway_worker') {
        throw new WorkerStartupError(
          'INVALID_WORKER_ROLE',
          "Worker must connect under 'gateway_worker' role",
        );
      }
      if (userRow.usesuper) {
        throw new WorkerStartupError(
          'WORKER_SUPERUSER_FORBIDDEN',
          'Worker role cannot have superuser privileges',
        );
      }

      // Verify BYPASSRLS is not granted
      const { rows: rlsRows } = await pgClient.query<{ rolbypassrls: boolean }>(
        "SELECT rolbypassrls FROM pg_roles WHERE rolname = 'gateway_worker'",
      );
      if (rlsRows[0]?.rolbypassrls) {
        throw new WorkerStartupError(
          'WORKER_BYPASSRLS_FORBIDDEN',
          'Worker role cannot have BYPASSRLS privilege',
        );
      }

      // Verify worker has no access to gateway_control (Architecture §12.5, §19.4)
      let controlAccessForbidden = false;
      try {
        await pgClient.query('SELECT 1 FROM gateway_control LIMIT 1');
      } catch (err: unknown) {
        const pgErr = err as { code?: string };
        if (pgErr.code === '42501') {
          controlAccessForbidden = true;
        }
      }
      if (!controlAccessForbidden) {
        throw new WorkerStartupError(
          'UNAUTHORIZED_GATEWAY_CONTROL_ACCESS',
          'Worker must not have access to gateway_control table or singleton state',
        );
      }
    } finally {
      pgClient.release();
    }

    currentDependencies.database = 'healthy';

    // Step 3: Initialize and verify Redis connectivity under restricted worker ACL
    if (!redis) {
      redis = new Redis({
        host: config.REDIS_HOST,
        port: config.REDIS_PORT,
        username: config.REDIS_USER,
        password: config.REDIS_PASSWORD,
        tls: config.REDIS_TLS ? {} : undefined,
        lazyConnect: true,
        connectTimeout: 3000,
        maxRetriesPerRequest: 1,
        retryStrategy: (times) => (times > 2 ? null : 200),
      });
      redis.on('error', () => {});
      await redis.connect();
    }

    const pong = await redis.ping();
    if (pong !== 'PONG') {
      throw new WorkerStartupError('REDIS_PING_FAILED', 'Redis ping did not return PONG');
    }

    const memoryInfo = await redis.info('memory');
    const policyMatch = memoryInfo.match(/maxmemory_policy:([^\r\n]+)/);
    const policy = policyMatch ? policyMatch[1]?.trim() : undefined;
    if (policy !== 'noeviction') {
      throw new WorkerStartupError(
        'UNSAFE_REDIS_POLICY',
        'Unsafe Redis policy: expected "noeviction"',
      );
    }

    const persistenceInfo = await redis.info('persistence');
    const aofMatch = persistenceInfo.match(/aof_enabled:([^\r\n]+)/);
    const aofEnabled = aofMatch ? aofMatch[1]?.trim() : undefined;
    if (aofEnabled !== '1') {
      throw new WorkerStartupError(
        'UNSAFE_AOF_PERSISTENCE',
        'Redis AOF persistence is not enabled: expected "aof_enabled:1"',
      );
    }

    // Verify worker Redis identity
    const currentRedisUser = (await redis.acl('WHOAMI')) as string;
    if (currentRedisUser === 'default') {
      throw new WorkerStartupError(
        'DEFAULT_REDIS_USER_FORBIDDEN',
        'Worker cannot use unrestricted "default" Redis identity',
      );
    }
    if (currentRedisUser !== config.REDIS_USER) {
      throw new WorkerStartupError(
        'REDIS_USER_MISMATCH',
        'Redis runtime identity does not match configured user',
      );
    }

    // Verify worker Redis ACL restriction: prohibited commands are denied fail-closed
    const prohibitedProbes = [
      () => redis!.config('GET', 'maxmemory'),
      () => redis!.keys('*'),
      () => (redis as unknown as { acl: (cmd: string) => Promise<unknown> }).acl('LIST'),
    ];

    for (const probe of prohibitedProbes) {
      let rejected = false;
      try {
        await probe();
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes('NOPERM') || msg.toLowerCase().includes('no permissions')) {
          rejected = true;
        }
      }
      if (!rejected) {
        throw new WorkerStartupError(
          'UNSAFE_WORKER_REDIS_ACL',
          'Worker Redis ACL is not properly restricted: prohibited command was not rejected',
        );
      }
    }

    currentDependencies.redis = 'healthy';

    // Step 4: Write initial readiness state file (fails closed if initial file write fails)
    try {
      writeHealthFileOrThrow('ready', currentDependencies);
    } catch {
      throw new WorkerStartupError(
        'HEALTH_FILE_INIT_FAILED',
        'Failed to initialize worker health file',
      );
    }
    isReadyState = true;

    // Health probe execution logic with concurrency protection (WRK-01)
    const runHealthProbe = async (
      timeoutMs: number = config.WORKER_PROBE_TIMEOUT_MS,
    ): Promise<WorkerReadinessResult> => {
      if (isStopping) {
        return {
          ok: false,
          status: 'shutting_down',
          dependencies: currentDependencies,
          error: 'Worker is shutting down',
        };
      }

      if (isProbing) {
        // Prevent overlapping probes: return current state
        return {
          ok: isReadyState,
          status: isReadyState ? 'ready' : 'unhealthy',
          dependencies: currentDependencies,
        };
      }

      isProbing = true;
      try {
        const check = await executeDependencyProbe(pgPool!, redis!, timeoutMs);
        currentDependencies = check.dependencies;

        if (isStopping) {
          return {
            ok: false,
            status: 'shutting_down',
            dependencies: currentDependencies,
          };
        }

        if (check.ok) {
          isReadyState = true;
          try {
            writeHealthFileOrThrow('ready', currentDependencies);
          } catch {
            /* best effort write on periodic heartbeat */
          }
          return {
            ok: true,
            status: 'ready',
            dependencies: currentDependencies,
          };
        } else {
          isReadyState = false;
          try {
            writeHealthFileOrThrow('unhealthy', currentDependencies, check.error);
          } catch {
            /* best effort write on periodic heartbeat */
          }
          return {
            ok: false,
            status: 'unhealthy',
            dependencies: currentDependencies,
            error: check.error,
          };
        }
      } finally {
        isProbing = false;
      }
    };

    // Periodic heartbeat executes bounded dependency probe every WORKER_PROBE_INTERVAL_MS
    heartbeatTimer = setInterval(async () => {
      if (!isStopping) {
        await runHealthProbe();
      }
    }, config.WORKER_PROBE_INTERVAL_MS);
    heartbeatTimer.unref();

    const stop = async () => {
      if (isStopping) return;
      isStopping = true;
      isReadyState = false;
      try {
        writeHealthFileOrThrow('shutting_down', currentDependencies);
      } catch {
        /* best effort */
      }
      await cleanup();
    };

    return {
      config,
      pgPool,
      redis,
      isReady: () => isReadyState && !isStopping,
      getDependencyStatus: () => ({ ...currentDependencies }),
      checkReadiness: async (timeoutMs?: number) => {
        return await runHealthProbe(timeoutMs);
      },
      runHealthProbe: async () => {
        return await runHealthProbe();
      },
      stop,
    };
  } catch (err) {
    await cleanup();
    throw err;
  }
}

export async function startWorker(
  envOverride?: Record<string, string | undefined>,
  dependencies?: WorkerDependencies,
): Promise<WorkerContext> {
  const context = await createWorker(envOverride, dependencies);
  const logger = getWorkerLogger();

  logger.info(
    { pid: process.pid, healthFile: context.config.WORKER_HEALTH_FILE },
    'Switchyard Worker operational and ready',
  );

  const handleSignal = (signal: string) => {
    logger.info({ signal }, 'Worker process signal received; shutting down');
    context.stop().then(
      () => {
        process.exit(0);
      },
      (err) => {
        logger.error({ err }, 'Error during worker graceful shutdown');
        process.exit(1);
      },
    );
  };

  process.once('SIGTERM', () => handleSignal('SIGTERM'));
  process.once('SIGINT', () => handleSignal('SIGINT'));

  return context;
}
