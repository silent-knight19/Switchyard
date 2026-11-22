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
  runHealthProbe(timeoutMs?: number): Promise<WorkerReadinessResult>;
  getActiveOperationsCount(): number;
  getActiveProbeSeq(): number;
  stop(): Promise<void>;
}

export interface WorkerDependencies {
  pgPool?: pg.Pool;
  redis?: Redis;
}

export interface ProbeControlHooks {
  probeId?: number;
  onCleanup?: (cb: () => void) => void;
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
  hooks?: ProbeControlHooks,
): Promise<{
  ok: boolean;
  dependencies: DependencyStatus;
  error?: string | undefined;
}> {
  const dependencies: DependencyStatus = {
    database: 'unhealthy',
    redis: 'unhealthy',
  };

  let isTimedOut = false;
  let isCleanedUp = false;
  let overallTimer: NodeJS.Timeout | null = null;
  let activePgClient: pg.PoolClient | null = null;

  const cancelAndDetach = () => {
    isCleanedUp = true;
    if (overallTimer) {
      clearTimeout(overallTimer);
      overallTimer = null;
    }
    if (activePgClient) {
      try {
        activePgClient.release(true);
      } catch {
        /* ignore */
      }
      activePgClient = null;
    }
  };

  if (hooks?.onCleanup) {
    hooks.onCleanup(cancelAndDetach);
  }

  // 1. Database connectivity check under restricted worker role (bounded I/O; WRK-04)
  const checkPostgres = async (): Promise<boolean> => {
    let connectTimer: NodeJS.Timeout | null = null;
    let queryTimer: NodeJS.Timeout | null = null;
    try {
      const connectPromise = pgPool.connect();

      // Ensure late client arrival after probe timeout/cancel is destroyed immediately
      connectPromise
        .then((client) => {
          if (isTimedOut || isCleanedUp) {
            try {
              client.release(true);
            } catch {
              /* ignore */
            }
          }
        })
        .catch(() => {
          /* ignore connect errors on detached probe */
        });

      const client = await Promise.race([
        connectPromise,
        new Promise<never>((_, reject) => {
          connectTimer = setTimeout(() => {
            reject(new Error('PG_CONNECT_TIMEOUT'));
          }, timeoutMs);
          connectTimer.unref();
        }),
      ]);

      if (connectTimer) {
        clearTimeout(connectTimer);
        connectTimer = null;
      }

      if (isTimedOut || isCleanedUp) {
        try {
          client.release(true);
        } catch {
          /* ignore */
        }
        return false;
      }

      activePgClient = client;

      await Promise.race([
        client.query('SELECT 1'),
        new Promise<never>((_, reject) => {
          queryTimer = setTimeout(() => {
            reject(new Error('PG_QUERY_TIMEOUT'));
          }, timeoutMs);
          queryTimer.unref();
        }),
      ]);

      if (queryTimer) {
        clearTimeout(queryTimer);
        queryTimer = null;
      }

      if (isTimedOut || isCleanedUp) {
        try {
          client.release(true);
        } catch {
          /* ignore */
        }
        activePgClient = null;
        return false;
      }

      dependencies.database = 'healthy';
      return true;
    } catch {
      dependencies.database = 'unhealthy';
      if (activePgClient) {
        try {
          activePgClient.release(true);
        } catch {
          /* ignore */
        }
        activePgClient = null;
      }
      return false;
    } finally {
      if (connectTimer) {
        clearTimeout(connectTimer);
      }
      if (queryTimer) {
        clearTimeout(queryTimer);
      }
      if (activePgClient && !isTimedOut && !isCleanedUp) {
        try {
          activePgClient.release();
        } catch {
          /* ignore */
        }
        activePgClient = null;
      }
    }
  };

  // 2. Redis connectivity check under restricted worker ACL (bounded ping; WRK-04)
  const checkRedis = async (): Promise<boolean> => {
    let pingTimer: NodeJS.Timeout | null = null;
    try {
      const pingPromise = redis.ping();

      const pong = await Promise.race([
        pingPromise,
        new Promise<string>((_, reject) => {
          pingTimer = setTimeout(() => {
            reject(new Error('REDIS_PING_TIMEOUT'));
          }, timeoutMs);
          pingTimer.unref();
        }),
      ]);

      if (pingTimer) {
        clearTimeout(pingTimer);
        pingTimer = null;
      }

      if (isTimedOut || isCleanedUp) {
        return false;
      }

      if (pong === 'PONG') {
        dependencies.redis = 'healthy';
        return true;
      } else {
        dependencies.redis = 'unhealthy';
        return false;
      }
    } catch {
      dependencies.redis = 'unhealthy';
      return false;
    } finally {
      if (pingTimer) {
        clearTimeout(pingTimer);
      }
    }
  };

  const overallTimeoutPromise = new Promise<{
    ok: boolean;
    dependencies: DependencyStatus;
    error?: string;
  }>((resolve) => {
    overallTimer = setTimeout(() => {
      isTimedOut = true;
      cancelAndDetach();
      resolve({
        ok: false,
        dependencies: { ...dependencies },
        error: 'Worker readiness check timed out',
      });
    }, timeoutMs);
    overallTimer.unref();
  });

  const probeAction = async (): Promise<{
    ok: boolean;
    dependencies: DependencyStatus;
    error?: string | undefined;
  }> => {
    const [pgOk, redisOk] = await Promise.all([checkPostgres(), checkRedis()]);
    if (overallTimer) {
      clearTimeout(overallTimer);
      overallTimer = null;
    }

    if (isTimedOut || isCleanedUp) {
      return {
        ok: false,
        dependencies: { ...dependencies },
        error: 'Worker readiness check timed out',
      };
    }

    const ok = pgOk && redisOk;
    return {
      ok,
      dependencies: { ...dependencies },
      error: ok ? undefined : 'Worker dependency check failed',
    };
  };

  try {
    return await Promise.race([probeAction(), overallTimeoutPromise]);
  } finally {
    if (overallTimer) {
      clearTimeout(overallTimer);
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
  const isExternalRedis = Boolean(dependencies?.redis);
  let heartbeatTimer: NodeJS.Timeout | null = null;
  let isReadyState = false;
  let isStopping = false;
  let activeProbeSeq = 0;
  let inFlightProbe: Promise<WorkerReadinessResult> | null = null;
  let inFlightCancel: (() => void) | null = null;
  let activeOpsCount = 0;
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
      probeIntervalMs: config.WORKER_PROBE_INTERVAL_MS,
      probeTimeoutMs: config.WORKER_PROBE_TIMEOUT_MS,
      freshnessThresholdMs: config.FRESHNESS_THRESHOLD_MS,
      dependencies: deps,
      ...(reason ? { reason } : {}),
    });
    fs.writeFileSync(config.WORKER_HEALTH_FILE, payload, 'utf8');
  };

  const createWorkerRedis = (): Redis => {
    const client = new Redis({
      host: config.REDIS_HOST,
      port: config.REDIS_PORT,
      username: config.REDIS_USER,
      password: config.REDIS_PASSWORD,
      tls: config.REDIS_TLS ? {} : undefined,
      lazyConnect: true,
      connectTimeout: Math.min(config.WORKER_PROBE_TIMEOUT_MS, 3000),
      commandTimeout: config.WORKER_PROBE_TIMEOUT_MS,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
      retryStrategy: (times) => Math.min(times * 100, 1000),
    });
    client.on('error', () => {});
    return client;
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
        try {
          redis.disconnect();
        } catch {
          /* ignore */
        }
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
        connectionTimeoutMillis: config.WORKER_PROBE_TIMEOUT_MS,
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
      redis = createWorkerRedis();
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

    // Health probe execution logic with generation fence and bounded I/O (WRK-01, WRK-04)
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

      if (inFlightProbe) {
        // Coalesce concurrent readiness requests into existing in-flight probe
        return inFlightProbe;
      }

      const probeSeq = ++activeProbeSeq;
      activeOpsCount++;

      const probePromise = (async (): Promise<WorkerReadinessResult> => {
        try {
          // If Redis retry budget was exhausted or ended, reconnect if self-managed
          if (
            !isExternalRedis &&
            redis &&
            (redis as unknown as { status?: string }).status === 'end'
          ) {
            try {
              redis.disconnect();
            } catch {
              /* ignore */
            }
            redis = createWorkerRedis();
            try {
              await redis.connect();
            } catch {
              /* ignore */
            }
          }

          const check = await executeDependencyProbe(pgPool!, redis!, timeoutMs, {
            probeId: probeSeq,
            onCleanup: (cb) => {
              inFlightCancel = cb;
            },
          });

          // Generation fence: discard if superseded or shutting down
          if (probeSeq !== activeProbeSeq || isStopping) {
            return {
              ok: isReadyState,
              status: isStopping ? 'shutting_down' : isReadyState ? 'ready' : 'unhealthy',
              dependencies: { ...currentDependencies },
              error: isReadyState ? undefined : 'Stale probe result discarded',
            };
          }

          currentDependencies = { ...check.dependencies };

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
              dependencies: { ...currentDependencies },
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
              dependencies: { ...currentDependencies },
              error: check.error,
            };
          }
        } finally {
          activeOpsCount--;
          if (probeSeq === activeProbeSeq) {
            inFlightProbe = null;
            inFlightCancel = null;
          }
        }
      })();

      inFlightProbe = probePromise;
      return await probePromise;
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

      // Abort in-flight probe immediately
      if (inFlightCancel) {
        try {
          inFlightCancel();
        } catch {
          /* ignore */
        }
        inFlightCancel = null;
      }

      if (heartbeatTimer) {
        clearInterval(heartbeatTimer);
        heartbeatTimer = null;
      }

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
      runHealthProbe: async (timeoutMs?: number) => {
        return await runHealthProbe(timeoutMs);
      },
      getActiveOperationsCount: () => activeOpsCount,
      getActiveProbeSeq: () => activeProbeSeq,
      stop,
    };
  } catch (err) {
    await cleanup();
    throw err;
  }
}

export function checkWorkerHealth(healthFilePath?: string): { ok: boolean; error?: string } {
  const healthFile =
    healthFilePath || process.env.WORKER_HEALTH_FILE || '/tmp/switchyard-worker-health.json';

  try {
    if (!fs.existsSync(healthFile)) {
      return { ok: false, error: `health file ${healthFile} not found` };
    }

    const content = fs.readFileSync(healthFile, 'utf8');
    const data = JSON.parse(content) as {
      status?: string;
      pid?: number;
      timestamp?: number;
      freshnessThresholdMs?: number;
    };

    if (data.status !== 'ready') {
      return { ok: false, error: `worker status is "${data.status}"` };
    }

    const freshnessThreshold =
      typeof data.freshnessThresholdMs === 'number' && data.freshnessThresholdMs > 0
        ? data.freshnessThresholdMs
        : 15000;

    if (!data.timestamp || Date.now() - data.timestamp > freshnessThreshold) {
      return {
        ok: false,
        error: `worker heartbeat is stale (>${freshnessThreshold}ms)`,
      };
    }

    if (typeof data.pid !== 'number') {
      return { ok: false, error: 'invalid PID in health file' };
    }

    try {
      // Signal 0 tests process existence without delivering a signal
      process.kill(data.pid, 0);
    } catch {
      return { ok: false, error: `worker PID ${data.pid} is not running` };
    }

    return { ok: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, error: msg };
  }
}

export function runHealthCheck(healthFilePath?: string): void {
  const result = checkWorkerHealth(healthFilePath);
  if (!result.ok) {
    process.stderr.write(`Health check failed: ${result.error}\n`);
    process.exit(1);
  }
  process.exit(0);
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
