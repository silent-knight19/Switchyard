import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { Writable } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseWorkerConfig, WorkerConfigValidationError } from './config.js';
import { createWorker, executeDependencyProbe, WorkerStartupError } from './worker.js';
import {
  createLogger,
  getLogger,
  getWorkerLogger,
  resetLoggerForTesting,
} from '../logging/index.js';

describe('Worker Runtime Foundation & Review Remediation (SW-P1-B01)', () => {
  let tmpDir: string;
  let tmpHealthFile: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'switchyard-worker-test-'));
    tmpHealthFile = path.join(tmpDir, 'worker-health.json');
    resetLoggerForTesting();
  });

  afterEach(() => {
    resetLoggerForTesting();
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  const validEnv: Record<string, string> = {
    NODE_ENV: 'test',
    POSTGRES_HOST: '127.0.0.1',
    POSTGRES_PORT: '5432',
    POSTGRES_DB: 'switchyard',
    POSTGRES_USER: 'gateway_worker',
    POSTGRES_PASSWORD: 'test_worker_password',
    REDIS_HOST: '127.0.0.1',
    REDIS_PORT: '6379',
    REDIS_USER: 'switchyard_worker',
    REDIS_PASSWORD: 'test_worker_password',
    WORKER_HEALTH_FILE: '', // will be set per test
    WORKER_PROBE_INTERVAL_MS: '100',
    WORKER_PROBE_TIMEOUT_MS: '500',
  };

  function getTestEnv(): Record<string, string> {
    return {
      ...validEnv,
      WORKER_HEALTH_FILE: tmpHealthFile,
    };
  }

  function createMockPg(
    opts: {
      queryImpl?: (sql: string) => Promise<unknown>;
      connectRejection?: Error;
      queryRejection?: Error;
    } = {},
  ) {
    const defaultQuery = (sql: string) => {
      if (sql.includes('current_user')) {
        return Promise.resolve({
          rows: [{ usename: 'gateway_worker', usesuper: false }],
        });
      }
      if (sql.includes('rolbypassrls')) {
        return Promise.resolve({
          rows: [{ rolbypassrls: false }],
        });
      }
      if (sql.includes('gateway_control')) {
        const err = new Error('permission denied for table gateway_control') as Error & {
          code: string;
        };
        err.code = '42501';
        return Promise.reject(err);
      }
      return Promise.resolve({ rows: [{ '?column?': 1 }] });
    };

    const mockPgClient = {
      query: vi.fn().mockImplementation((sql: string) => {
        if (opts.queryRejection) {
          return Promise.reject(opts.queryRejection);
        }
        if (opts.queryImpl) {
          return opts.queryImpl(sql);
        }
        return defaultQuery(sql);
      }),
      release: vi.fn(),
    };

    const mockPgPool = {
      connect: vi.fn().mockImplementation(() => {
        if (opts.connectRejection) {
          return Promise.reject(opts.connectRejection);
        }
        return Promise.resolve(mockPgClient);
      }),
      end: vi.fn().mockResolvedValue(undefined),
      on: vi.fn(),
    } as unknown as import('pg').Pool;

    return { mockPgPool, mockPgClient };
  }

  function createMockRedis(
    opts: {
      pingResult?: string;
      pingRejection?: Error;
    } = {},
  ) {
    const mockRedis = {
      connect: vi.fn().mockResolvedValue(undefined),
      ping: vi.fn().mockImplementation(() => {
        if (opts.pingRejection) {
          return Promise.reject(opts.pingRejection);
        }
        return Promise.resolve(opts.pingResult ?? 'PONG');
      }),
      info: vi.fn().mockImplementation((section: string) => {
        if (section === 'memory') return Promise.resolve('maxmemory_policy:noeviction\r\n');
        if (section === 'persistence') return Promise.resolve('aof_enabled:1\r\n');
        return Promise.resolve('');
      }),
      acl: vi.fn().mockImplementation((cmd: string) => {
        if (cmd === 'WHOAMI') return Promise.resolve('switchyard_worker');
        return Promise.reject(new Error('NOPERM This user has no permissions'));
      }),
      config: vi.fn().mockRejectedValue(new Error('NOPERM This user has no permissions')),
      keys: vi.fn().mockRejectedValue(new Error('NOPERM This user has no permissions')),
      quit: vi.fn().mockResolvedValue('OK'),
      disconnect: vi.fn(),
      on: vi.fn(),
    } as unknown as import('ioredis').Redis;

    return { mockRedis };
  }

  // =========================================================================
  // Section 1: Baseline Configuration & Security Invariants
  // =========================================================================
  describe('Baseline Configuration & Security Invariants', () => {
    it('1. Valid worker configuration parses successfully', () => {
      const config = parseWorkerConfig(getTestEnv());
      expect(config.NODE_ENV).toBe('test');
      expect(config.POSTGRES_USER).toBe('gateway_worker');
      expect(config.REDIS_USER).toBe('switchyard_worker');
      expect(config.REDIS_MAXMEMORY_POLICY).toBe('noeviction');
    });

    it('2. Missing or invalid required credentials cause startup failure', () => {
      expect(() => parseWorkerConfig({ ...getTestEnv(), POSTGRES_PASSWORD: '' })).toThrow(
        WorkerConfigValidationError,
      );
      expect(() => parseWorkerConfig({ ...getTestEnv(), REDIS_PASSWORD: '' })).toThrow(
        WorkerConfigValidationError,
      );
    });

    it('3. Worker fails closed if user attempts to run as gateway_app, gateway_migrator, or superuser', () => {
      expect(() => parseWorkerConfig({ ...getTestEnv(), POSTGRES_USER: 'gateway_app' })).toThrow(
        /Worker must connect under the restricted 'gateway_worker' database role/,
      );
      expect(() => parseWorkerConfig({ ...getTestEnv(), POSTGRES_USER: 'postgres' })).toThrow(
        /Worker must connect under the restricted 'gateway_worker' database role/,
      );
    });

    it('4. Worker fails closed if Redis user is default or gateway_app', () => {
      expect(() => parseWorkerConfig({ ...getTestEnv(), REDIS_USER: 'default' })).toThrow(
        /Worker cannot use default or gateway_app Redis identity/,
      );
      expect(() => parseWorkerConfig({ ...getTestEnv(), REDIS_USER: 'gateway_app' })).toThrow(
        /Worker cannot use default or gateway_app Redis identity/,
      );
    });

    it('5. Worker rejects presence of KEKs or provider key decryption material fail-closed', () => {
      expect(() => parseWorkerConfig({ ...getTestEnv(), MASTER_KEK_V1: 'dummy-kek' })).toThrow(
        /Worker runtime must not have access to provider encryption keys or KEKs/,
      );
      expect(() => parseWorkerConfig({ ...getTestEnv(), ACTIVE_KEK_VERSION: '1' })).toThrow(
        /Worker runtime must not have access to provider encryption keys or KEKs/,
      );
    });

    it('6. Worker rejects forbidden security bypass flags', () => {
      expect(() => parseWorkerConfig({ ...getTestEnv(), BYPASS_RLS: 'true' })).toThrow(
        /Forbidden security flag detected/,
      );
      expect(() => parseWorkerConfig({ ...getTestEnv(), FAIL_OPEN: 'true' })).toThrow(
        /Forbidden security flag detected/,
      );
    });
  });

  // =========================================================================
  // Section 2: WRK-02 — Canary Tests and Environment Value Redaction
  // =========================================================================
  describe('WRK-02: Canary and Credential Redaction in Worker Errors & Logs', () => {
    const CANARY_PG_USER = 'CANARY_PG_USER_SECRET_12345';
    const CANARY_PORT = 'CANARY_PORT_SECRET_99999';
    const CANARY_NODE_ENV = 'CANARY_NODE_ENV_SECRET_DEVPROD';
    const CANARY_FLAG = 'CANARY_FLAG_SECRET_FAIL_OPEN';
    const CANARY_KEK = 'CANARY_KEK_SECRET_KEY_MATERIAL';

    it('rejects invalid configuration and never discloses canaries in error messages', () => {
      const testCases: Array<{ env: Record<string, string>; canary: string; desc: string }> = [
        {
          desc: 'Invalid POSTGRES_USER role',
          env: { ...getTestEnv(), POSTGRES_USER: CANARY_PG_USER },
          canary: CANARY_PG_USER,
        },
        {
          desc: 'Invalid non-numeric POSTGRES_PORT',
          env: { ...getTestEnv(), POSTGRES_PORT: CANARY_PORT },
          canary: CANARY_PORT,
        },
        {
          desc: 'Invalid NODE_ENV enum',
          env: { ...getTestEnv(), NODE_ENV: CANARY_NODE_ENV },
          canary: CANARY_NODE_ENV,
        },
        {
          desc: 'Forbidden security bypass flag',
          env: { ...getTestEnv(), FAIL_OPEN: CANARY_FLAG },
          canary: CANARY_FLAG,
        },
        {
          desc: 'Forbidden KEK environment variable',
          env: { ...getTestEnv(), MASTER_KEK_V1: CANARY_KEK },
          canary: CANARY_KEK,
        },
      ];

      for (const tc of testCases) {
        let thrownError: unknown;
        try {
          parseWorkerConfig(tc.env);
        } catch (err) {
          thrownError = err;
        }

        expect(thrownError).toBeInstanceOf(WorkerConfigValidationError);
        const err = thrownError as WorkerConfigValidationError;
        const fullErrorText = `${err.message} ${(err.issues || []).join(' ')}`;

        // Strict assertion: the canary value must NEVER appear anywhere in the error
        expect(fullErrorText).not.toContain(tc.canary);
      }
    });

    it('ensures structured startup logs redact all canaries in development and production profiles', () => {
      const profiles: Array<'development' | 'production'> = ['development', 'production'];

      for (const profile of profiles) {
        let loggedOutput = '';
        const stream = new Writable({
          write(chunk, _encoding, callback) {
            loggedOutput += chunk.toString();
            callback();
          },
        });

        const testLogger = createLogger({
          serviceName: '@switchyard/worker',
          environment: profile,
          stream,
        });

        // Trigger validation error containing multiple canaries
        let validationError: WorkerConfigValidationError | null = null;
        try {
          parseWorkerConfig({
            ...getTestEnv(),
            NODE_ENV: profile,
            POSTGRES_USER: CANARY_PG_USER,
            POSTGRES_PORT: CANARY_PORT,
            FAIL_OPEN: CANARY_FLAG,
            MASTER_KEK_V1: CANARY_KEK,
          });
        } catch (err) {
          if (err instanceof WorkerConfigValidationError) {
            validationError = err;
          }
        }

        expect(validationError).not.toBeNull();

        // Log the error through the safe logger serializer
        testLogger.fatal({ err: validationError }, 'Worker fatal startup failure');

        // Verify the emitted log line
        expect(loggedOutput.length).toBeGreaterThan(0);
        expect(loggedOutput).not.toContain(CANARY_PG_USER);
        expect(loggedOutput).not.toContain(CANARY_PORT);
        expect(loggedOutput).not.toContain(CANARY_FLAG);
        expect(loggedOutput).not.toContain(CANARY_KEK);

        // Verify log structure preserves safe information
        const parsed = JSON.parse(loggedOutput) as {
          level: number;
          service: string;
          err?: { type: string; code?: string; message: string };
        };
        expect(parsed.service).toBe('@switchyard/worker');
        expect(parsed.err?.code).toBe('CONFIG_VALIDATION_FAILED');
      }
    });
  });

  // =========================================================================
  // Section 2: WRK-03 — Worker Service Attribution
  // =========================================================================
  describe('WRK-03: Structured Log Service Identity', () => {
    it('worker logger attributes logs to @switchyard/worker while gateway logger identifies as @switchyard/gateway', () => {
      let workerLogs = '';
      const workerStream = new Writable({
        write(chunk, _enc, cb) {
          workerLogs += chunk.toString();
          cb();
        },
      });

      let gatewayLogs = '';
      const gatewayStream = new Writable({
        write(chunk, _enc, cb) {
          gatewayLogs += chunk.toString();
          cb();
        },
      });

      const workerLog = createLogger({ serviceName: '@switchyard/worker', stream: workerStream });
      const gatewayLog = createLogger({
        serviceName: '@switchyard/gateway',
        stream: gatewayStream,
      });

      workerLog.info({ task: 'background_check' }, 'Worker status ping');
      gatewayLog.info({ route: '/health/ready' }, 'Gateway status ping');

      const parsedWorker = JSON.parse(workerLogs) as { service: string; name: string };
      const parsedGateway = JSON.parse(gatewayLogs) as { service: string; name: string };

      expect(parsedWorker.service).toBe('@switchyard/worker');
      expect(parsedWorker.name).toBe('@switchyard/worker');

      expect(parsedGateway.service).toBe('@switchyard/gateway');
      expect(parsedGateway.name).toBe('@switchyard/gateway');
    });

    it('getWorkerLogger singleton returns @switchyard/worker attribution', () => {
      const logger = getWorkerLogger();
      expect(logger.bindings().service).toBe('@switchyard/worker');
    });

    it('getLogger singleton returns @switchyard/gateway attribution', () => {
      const logger = getLogger();
      expect(logger.bindings().service).toBe('@switchyard/gateway');
    });
  });

  // =========================================================================
  // Section 3: WRK-01 — Worker Readiness Semantics & Negative Recovery Tests
  // =========================================================================
  describe('WRK-01: Worker Readiness State & Dependency Recovery', () => {
    it('1. Worker starts with both dependencies healthy and writes ready health file', async () => {
      const { mockPgPool } = createMockPg();
      const { mockRedis } = createMockRedis();

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      try {
        expect(worker.isReady()).toBe(true);
        expect(worker.getDependencyStatus()).toEqual({
          database: 'healthy',
          redis: 'healthy',
        });

        expect(fs.existsSync(tmpHealthFile)).toBe(true);
        const health = JSON.parse(fs.readFileSync(tmpHealthFile, 'utf8')) as {
          status: string;
          worker: string;
          dependencies: { database: string; redis: string };
        };
        expect(health.status).toBe('ready');
        expect(health.worker).toBe('operational');
        expect(health.dependencies.database).toBe('healthy');
        expect(health.dependencies.redis).toBe('healthy');
      } finally {
        await worker.stop();
      }
    });

    it('2 & 3. PostgreSQL becomes unavailable after startup: health becomes unhealthy within bounded interval', async () => {
      let pgHealthy = true;
      const { mockPgPool } = createMockPg({
        queryImpl: (sql: string) => {
          if (!pgHealthy && sql.includes('SELECT 1')) {
            return Promise.reject(new Error('PostgreSQL connection terminated'));
          }
          if (sql.includes('current_user')) {
            return Promise.resolve({ rows: [{ usename: 'gateway_worker', usesuper: false }] });
          }
          if (sql.includes('rolbypassrls')) {
            return Promise.resolve({ rows: [{ rolbypassrls: false }] });
          }
          if (sql.includes('gateway_control')) {
            const err = new Error('permission denied') as Error & { code: string };
            err.code = '42501';
            return Promise.reject(err);
          }
          return Promise.resolve({ rows: [{ '?column?': 1 }] });
        },
      });
      const { mockRedis } = createMockRedis();

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      try {
        expect(worker.isReady()).toBe(true);

        // Simulate PostgreSQL becoming unavailable
        pgHealthy = false;

        // Run health probe
        const check = await worker.runHealthProbe();
        expect(check.ok).toBe(false);
        expect(check.status).toBe('unhealthy');
        expect(check.dependencies.database).toBe('unhealthy');
        expect(check.dependencies.redis).toBe('healthy');
        expect(worker.isReady()).toBe(false);

        // Verify health file reflects unhealthy state
        const health = JSON.parse(fs.readFileSync(tmpHealthFile, 'utf8')) as {
          status: string;
          dependencies: { database: string; redis: string };
        };
        expect(health.status).toBe('unhealthy');
        expect(health.dependencies.database).toBe('unhealthy');
      } finally {
        await worker.stop();
      }
    });

    it('4. PostgreSQL recovers and worker becomes healthy again', async () => {
      let pgHealthy = false;
      let startupDone = false;

      const { mockPgPool } = createMockPg({
        queryImpl: (sql: string) => {
          if (!startupDone) {
            if (sql.includes('current_user')) {
              return Promise.resolve({ rows: [{ usename: 'gateway_worker', usesuper: false }] });
            }
            if (sql.includes('rolbypassrls')) {
              return Promise.resolve({ rows: [{ rolbypassrls: false }] });
            }
            if (sql.includes('gateway_control')) {
              const err = new Error('permission denied') as Error & { code: string };
              err.code = '42501';
              return Promise.reject(err);
            }
          }
          if (!pgHealthy) {
            return Promise.reject(new Error('Connection reset by peer'));
          }
          return Promise.resolve({ rows: [{ '?column?': 1 }] });
        },
      });
      const { mockRedis } = createMockRedis();

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });
      startupDone = true;

      try {
        // Probe while PostgreSQL is unhealthy
        const unhealthyCheck = await worker.runHealthProbe();
        expect(unhealthyCheck.ok).toBe(false);
        expect(worker.isReady()).toBe(false);

        // PostgreSQL recovers
        pgHealthy = true;

        // Probe again
        const recoveredCheck = await worker.runHealthProbe();
        expect(recoveredCheck.ok).toBe(true);
        expect(recoveredCheck.status).toBe('ready');
        expect(recoveredCheck.dependencies.database).toBe('healthy');
        expect(worker.isReady()).toBe(true);

        // Health file is updated to ready
        const health = JSON.parse(fs.readFileSync(tmpHealthFile, 'utf8')) as {
          status: string;
          dependencies: { database: string };
        };
        expect(health.status).toBe('ready');
        expect(health.dependencies.database).toBe('healthy');
      } finally {
        await worker.stop();
      }
    });

    it('5 & 6. Redis becomes unavailable after startup: health becomes unhealthy', async () => {
      let redisHealthy = true;
      const { mockPgPool } = createMockPg();
      const mockRedis = {
        connect: vi.fn().mockResolvedValue(undefined),
        ping: vi.fn().mockImplementation(() => {
          if (!redisHealthy) {
            return Promise.reject(new Error('ECONNREFUSED'));
          }
          return Promise.resolve('PONG');
        }),
        info: vi.fn().mockImplementation((section: string) => {
          if (section === 'memory') return Promise.resolve('maxmemory_policy:noeviction\r\n');
          if (section === 'persistence') return Promise.resolve('aof_enabled:1\r\n');
          return Promise.resolve('');
        }),
        acl: vi.fn().mockImplementation((cmd: string) => {
          if (cmd === 'WHOAMI') return Promise.resolve('switchyard_worker');
          return Promise.reject(new Error('NOPERM'));
        }),
        config: vi.fn().mockRejectedValue(new Error('NOPERM')),
        keys: vi.fn().mockRejectedValue(new Error('NOPERM')),
        quit: vi.fn().mockResolvedValue('OK'),
        disconnect: vi.fn(),
        on: vi.fn(),
      } as unknown as import('ioredis').Redis;

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      try {
        expect(worker.isReady()).toBe(true);

        // Redis goes down
        redisHealthy = false;

        const check = await worker.runHealthProbe();
        expect(check.ok).toBe(false);
        expect(check.status).toBe('unhealthy');
        expect(check.dependencies.redis).toBe('unhealthy');
        expect(check.dependencies.database).toBe('healthy');
        expect(worker.isReady()).toBe(false);

        const health = JSON.parse(fs.readFileSync(tmpHealthFile, 'utf8')) as {
          status: string;
          dependencies: { redis: string };
        };
        expect(health.status).toBe('unhealthy');
        expect(health.dependencies.redis).toBe('unhealthy');
      } finally {
        await worker.stop();
      }
    });

    it('7. Redis recovers and worker becomes healthy again', async () => {
      let redisHealthy = false;
      const { mockPgPool } = createMockPg();
      let startupDone = false;

      const mockRedis = {
        connect: vi.fn().mockResolvedValue(undefined),
        ping: vi.fn().mockImplementation(() => {
          if (!startupDone || redisHealthy) {
            return Promise.resolve('PONG');
          }
          return Promise.reject(new Error('ECONNRESET'));
        }),
        info: vi.fn().mockImplementation((section: string) => {
          if (section === 'memory') return Promise.resolve('maxmemory_policy:noeviction\r\n');
          if (section === 'persistence') return Promise.resolve('aof_enabled:1\r\n');
          return Promise.resolve('');
        }),
        acl: vi.fn().mockImplementation((cmd: string) => {
          if (cmd === 'WHOAMI') return Promise.resolve('switchyard_worker');
          return Promise.reject(new Error('NOPERM'));
        }),
        config: vi.fn().mockRejectedValue(new Error('NOPERM')),
        keys: vi.fn().mockRejectedValue(new Error('NOPERM')),
        quit: vi.fn().mockResolvedValue('OK'),
        disconnect: vi.fn(),
        on: vi.fn(),
      } as unknown as import('ioredis').Redis;

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });
      startupDone = true;

      try {
        // Probe when Redis is down
        const unhealthyCheck = await worker.runHealthProbe();
        expect(unhealthyCheck.ok).toBe(false);
        expect(worker.isReady()).toBe(false);

        // Redis recovers
        redisHealthy = true;

        const recoveredCheck = await worker.runHealthProbe();
        expect(recoveredCheck.ok).toBe(true);
        expect(recoveredCheck.status).toBe('ready');
        expect(recoveredCheck.dependencies.redis).toBe('healthy');
        expect(worker.isReady()).toBe(true);
      } finally {
        await worker.stop();
      }
    });

    it('8. Failed health-file creation does not produce false readiness', async () => {
      const { mockPgPool } = createMockPg();
      const { mockRedis } = createMockRedis();

      // Configure an impossible/forbidden health file path
      const invalidHealthFile = '/proc/sys/fs/protected/cannot-write-here.json';

      await expect(
        createWorker(
          { ...getTestEnv(), WORKER_HEALTH_FILE: invalidHealthFile },
          { pgPool: mockPgPool, redis: mockRedis },
        ),
      ).rejects.toThrow(WorkerStartupError);
    });

    it('9. Concurrent / slow probes do not overlap or accumulate', async () => {
      const { mockPgPool } = createMockPg();
      let pingCallCount = 0;

      const mockRedis = {
        connect: vi.fn().mockResolvedValue(undefined),
        ping: vi.fn().mockImplementation(async () => {
          pingCallCount += 1;
          // Simulate slow 50ms probe
          await new Promise((r) => setTimeout(r, 50));
          return 'PONG';
        }),
        info: vi.fn().mockImplementation((section: string) => {
          if (section === 'memory') return Promise.resolve('maxmemory_policy:noeviction\r\n');
          if (section === 'persistence') return Promise.resolve('aof_enabled:1\r\n');
          return Promise.resolve('');
        }),
        acl: vi.fn().mockImplementation((cmd: string) => {
          if (cmd === 'WHOAMI') return Promise.resolve('switchyard_worker');
          return Promise.reject(new Error('NOPERM'));
        }),
        config: vi.fn().mockRejectedValue(new Error('NOPERM')),
        keys: vi.fn().mockRejectedValue(new Error('NOPERM')),
        quit: vi.fn().mockResolvedValue('OK'),
        disconnect: vi.fn(),
        on: vi.fn(),
      } as unknown as import('ioredis').Redis;

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      try {
        const pingCallsBefore = pingCallCount;

        // Launch 5 probes simultaneously
        const promises = [
          worker.runHealthProbe(),
          worker.runHealthProbe(),
          worker.runHealthProbe(),
          worker.runHealthProbe(),
          worker.runHealthProbe(),
        ];

        const results = await Promise.all(promises);
        for (const res of results) {
          expect(res.ok).toBe(true);
        }

        // Probes must not overlap: exactly 1 actual Redis ping occurred for the concurrent burst
        const pingCallsAfter = pingCallCount;
        expect(pingCallsAfter - pingCallsBefore).toBe(1);
      } finally {
        await worker.stop();
      }
    });

    it('10. Shutdown clears pending timers and connections', async () => {
      const { mockPgPool } = createMockPg();
      const { mockRedis } = createMockRedis();

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      expect(worker.isReady()).toBe(true);

      await worker.stop();

      expect(worker.isReady()).toBe(false);
      expect(mockRedis.quit).toHaveBeenCalled();
      expect(mockPgPool.end).toHaveBeenCalled();

      // Subsequent health probe after stop returns shutting_down and not ok
      const probeAfterStop = await worker.runHealthProbe();
      expect(probeAfterStop.ok).toBe(false);
      expect(probeAfterStop.status).toBe('shutting_down');
    });

    it('11. Direct dependency probe helper respects bounded timeout', async () => {
      const { mockPgPool } = createMockPg({
        queryImpl: () => new Promise((resolve) => setTimeout(resolve, 2000)), // Hangs for 2s
      });
      const { mockRedis } = createMockRedis();

      // Execute probe with tight 100ms timeout
      const probe = await executeDependencyProbe(mockPgPool, mockRedis, 100);

      expect(probe.ok).toBe(false);
      expect(probe.error).toBe('Worker readiness check timed out');
      expect(probe.dependencies.database).toBe('unhealthy');
    });
  });
});
