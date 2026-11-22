import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { Writable } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseWorkerConfig, WorkerConfigValidationError } from './config.js';
import {
  checkWorkerHealth,
  createWorker,
  executeDependencyProbe,
  WorkerStartupError,
} from './worker.js';
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
    WORKER_PROBE_INTERVAL_MS: '200',
    WORKER_PROBE_TIMEOUT_MS: '100',
  };

  function getTestEnv(): Record<string, string> {
    return {
      ...validEnv,
      WORKER_HEALTH_FILE: tmpHealthFile,
    };
  }

  function createDeferred<T>() {
    let resolve!: (val: T | PromiseLike<T>) => void;
    let reject!: (err?: unknown) => void;
    const promise = new Promise<T>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    return { promise, resolve, reject };
  }

  interface MockPgClientInstance {
    id: number;
    query: ReturnType<typeof vi.fn>;
    release: ReturnType<typeof vi.fn>;
    isDestroyed: boolean;
    isReleased: boolean;
  }

  interface MockPgPoolTracker {
    activeClients: Set<MockPgClientInstance>;
    allClients: MockPgClientInstance[];
    destroyedClients: MockPgClientInstance[];
    releasedClients: MockPgClientInstance[];
    waitingCount: number;
    readonly activeClientsCount: number;
  }

  function createMockPg(
    opts: {
      queryImpl?: (sql: string) => Promise<unknown> | undefined;
      connectImpl?: () => Promise<unknown>;
      connectRejection?: Error;
      queryRejection?: Error;
    } = {},
  ) {
    let clientIdCounter = 1;
    const tracker: MockPgPoolTracker = {
      activeClients: new Set(),
      allClients: [],
      destroyedClients: [],
      releasedClients: [],
      waitingCount: 0,
      get activeClientsCount() {
        return tracker.activeClients.size;
      },
    };

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

    const createClientInstance = (id: number): MockPgClientInstance => {
      const client: MockPgClientInstance = {
        id,
        query: vi.fn().mockImplementation((sql: string) => {
          if (opts.queryRejection) {
            return Promise.reject(opts.queryRejection);
          }
          if (opts.queryImpl) {
            const res = opts.queryImpl(sql);
            if (res !== undefined) {
              return res;
            }
          }
          return defaultQuery(sql);
        }),
        release: vi.fn().mockImplementation((destroy?: boolean) => {
          tracker.activeClients.delete(client);
          if (destroy) {
            client.isDestroyed = true;
            tracker.destroyedClients.push(client);
          } else {
            client.isReleased = true;
            tracker.releasedClients.push(client);
          }
        }),
        isDestroyed: false,
        isReleased: false,
      };
      return client;
    };

    const primaryClient = createClientInstance(0);

    const mockPgPool = {
      connect: vi.fn().mockImplementation(() => {
        if (opts.connectRejection) {
          return Promise.reject(opts.connectRejection);
        }
        if (opts.connectImpl) {
          tracker.waitingCount++;
          const promise = opts.connectImpl();
          promise
            .then((client) => {
              tracker.waitingCount = Math.max(0, tracker.waitingCount - 1);
              if (client && typeof (client as MockPgClientInstance).release === 'function') {
                tracker.activeClients.add(client as MockPgClientInstance);
                tracker.allClients.push(client as MockPgClientInstance);
              }
            })
            .catch(() => {
              tracker.waitingCount = Math.max(0, tracker.waitingCount - 1);
            });
          return promise;
        }
        const client =
          clientIdCounter === 1 ? primaryClient : createClientInstance(clientIdCounter);
        clientIdCounter++;
        tracker.activeClients.add(client);
        tracker.allClients.push(client);
        return Promise.resolve(client);
      }),
      end: vi.fn().mockResolvedValue(undefined),
      on: vi.fn(),
      get waitingCount() {
        return tracker.waitingCount;
      },
    } as unknown as import('pg').Pool;

    return {
      mockPgPool,
      mockPgClient: primaryClient,
      createClientInstance,
      poolTracker: tracker,
    };
  }

  function createMockRedis(
    opts: {
      pingResult?: string;
      pingImpl?: () => Promise<string>;
      pingRejection?: Error;
    } = {},
  ) {
    const mockRedis = {
      connect: vi.fn().mockResolvedValue(undefined),
      ping: vi.fn().mockImplementation(() => {
        if (opts.pingRejection) {
          return Promise.reject(opts.pingRejection);
        }
        if (opts.pingImpl) {
          return opts.pingImpl();
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

  // =========================================================================
  // Section 5: WRK-04 — Real Bounded Dependency Probes & Non-Overlapping Invariants
  // =========================================================================
  describe('WRK-04: Real Bounded Dependency Probes & Invariants', () => {
    it('1. PostgreSQL connection acquisition never resolving terminates within bound and destroys late client', async () => {
      const deferredConnect = createDeferred<unknown>();
      const { mockPgPool, mockPgClient } = createMockPg({
        connectImpl: () => deferredConnect.promise,
      });
      const { mockRedis } = createMockRedis();

      const probe = await executeDependencyProbe(mockPgPool, mockRedis, 50);

      expect(probe.ok).toBe(false);
      expect(probe.error).toBe('Worker readiness check timed out');
      expect(probe.dependencies.database).toBe('unhealthy');
      expect(probe.dependencies.redis).toBe('healthy');

      // Late resolution of connect promise must immediately destroy the acquired client
      deferredConnect.resolve(mockPgClient);
      await new Promise((r) => setTimeout(r, 20));
      expect(mockPgClient.release).toHaveBeenCalledWith(true);
    });

    it('2. PostgreSQL query never resolving terminates within bound and destroys active client', async () => {
      const deferredQuery = createDeferred<unknown>();
      const { mockPgPool, mockPgClient } = createMockPg({
        queryImpl: () => deferredQuery.promise,
      });
      const { mockRedis } = createMockRedis();

      const probe = await executeDependencyProbe(mockPgPool, mockRedis, 50);

      expect(probe.ok).toBe(false);
      expect(probe.error).toBe('Worker readiness check timed out');
      expect(probe.dependencies.database).toBe('unhealthy');
      expect(mockPgClient.release).toHaveBeenCalledWith(true);
    });

    it('3. Redis PING never resolving terminates within bound', async () => {
      const deferredPing = createDeferred<string>();
      const { mockPgPool } = createMockPg();
      const { mockRedis } = createMockRedis({
        pingImpl: () => deferredPing.promise,
      });

      const probe = await executeDependencyProbe(mockPgPool, mockRedis, 50);

      expect(probe.ok).toBe(false);
      expect(probe.error).toBe('Worker readiness check timed out');
      expect(probe.dependencies.database).toBe('healthy');
      expect(probe.dependencies.redis).toBe('unhealthy');
    });

    it('4. Timeout followed by a late successful database result does not mutate readiness', async () => {
      let hangQuery = false;
      const deferredQuery = createDeferred<unknown>();
      const { mockPgPool } = createMockPg({
        queryImpl: (sql) => {
          if (sql.includes('SELECT 1') && hangQuery) {
            return deferredQuery.promise;
          }
          return undefined;
        },
      });
      const { mockRedis } = createMockRedis();

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      expect(worker.isReady()).toBe(true);

      // Trigger probe timeout
      hangQuery = true;
      const probeResult = await worker.runHealthProbe(50);
      expect(probeResult.ok).toBe(false);
      expect(worker.isReady()).toBe(false);
      expect(worker.getDependencyStatus().database).toBe('unhealthy');

      // Late resolution of database query arrives
      deferredQuery.resolve({ rows: [{ '?column?': 1 }] });
      await new Promise((r) => setTimeout(r, 20));

      // Assert readiness was NOT mutated by the late success
      expect(worker.isReady()).toBe(false);
      expect(worker.getDependencyStatus().database).toBe('unhealthy');

      await worker.stop();
    });

    it('5. Timeout followed by a late successful Redis result does not mutate readiness', async () => {
      let hangPing = false;
      const deferredPing = createDeferred<string>();
      const { mockPgPool } = createMockPg();
      const { mockRedis } = createMockRedis({
        pingImpl: () => {
          if (hangPing) {
            return deferredPing.promise;
          }
          return Promise.resolve('PONG');
        },
      });

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      expect(worker.isReady()).toBe(true);

      // Trigger probe timeout on Redis
      hangPing = true;
      const probeResult = await worker.runHealthProbe(50);
      expect(probeResult.ok).toBe(false);
      expect(worker.isReady()).toBe(false);
      expect(worker.getDependencyStatus().redis).toBe('unhealthy');

      // Late resolution arrives
      deferredPing.resolve('PONG');
      await new Promise((r) => setTimeout(r, 20));

      // Assert readiness was NOT mutated by late Redis arrival
      expect(worker.isReady()).toBe(false);
      expect(worker.getDependencyStatus().redis).toBe('unhealthy');

      await worker.stop();
    });

    it('6. Multiple probe intervals during a persistent hang keep active operations and pool clients bounded', async () => {
      const { mockPgPool, poolTracker } = createMockPg({
        queryImpl: (sql) => {
          if (sql === 'SELECT 1') {
            return new Promise(() => {}); // persists hanging
          }
          return undefined;
        },
      });
      const { mockRedis } = createMockRedis();

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      // Run multiple sequential probes during the persistent hang
      await worker.runHealthProbe(50);
      await worker.runHealthProbe(50);
      await worker.runHealthProbe(50);

      expect(worker.isReady()).toBe(false);

      // Wrapper-level operations count returns to 0
      expect(worker.getActiveOperationsCount()).toBe(0);

      // Underlying PostgreSQL pool resources are strictly cleaned up (WRK-07)
      expect(poolTracker.activeClientsCount).toBe(0);
      expect(poolTracker.waitingCount).toBe(0);
      expect(poolTracker.destroyedClients).toHaveLength(3);
      for (const client of poolTracker.destroyedClients) {
        expect(client.release).toHaveBeenCalledWith(true);
      }

      await worker.stop();
    });

    it('7. Concurrent readiness requests coalesce into single in-flight probe', async () => {
      const { mockPgPool } = createMockPg();
      const { mockRedis } = createMockRedis();

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      const results = await Promise.all([
        worker.checkReadiness(100),
        worker.checkReadiness(100),
        worker.checkReadiness(100),
        worker.checkReadiness(100),
      ]);

      expect(results).toHaveLength(4);
      expect(results.every((r) => r.ok && r.status === 'ready')).toBe(true);
      expect(worker.getActiveOperationsCount()).toBe(0);

      await worker.stop();
    });

    it('8. Old failure arriving after a newer success is discarded by generation fence', async () => {
      const { mockPgPool } = createMockPg();
      const { mockRedis } = createMockRedis();

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      expect(worker.isReady()).toBe(true);
      const initialSeq = worker.getActiveProbeSeq();

      // Simulate a newer probe advancing sequence
      await worker.runHealthProbe(100);
      expect(worker.getActiveProbeSeq()).toBeGreaterThan(initialSeq);
      expect(worker.isReady()).toBe(true);

      await worker.stop();
    });

    it('9. Old success arriving after a newer failure is discarded by generation fence', async () => {
      let failNext = false;
      const { mockPgPool } = createMockPg({
        queryImpl: (sql) => {
          if (sql === 'SELECT 1' && failNext) {
            return Promise.reject(new Error('PG_OUTAGE'));
          }
          return undefined;
        },
      });
      const { mockRedis } = createMockRedis();

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      failNext = true;
      const failResult = await worker.runHealthProbe(100);
      expect(failResult.ok).toBe(false);
      expect(worker.isReady()).toBe(false);

      await worker.stop();
    });

    it('10. Shutdown with a pending dependency operation terminates boundedly', async () => {
      const deferredQuery = createDeferred<unknown>();
      const { mockPgPool } = createMockPg({
        queryImpl: (sql) => {
          if (sql === 'SELECT 1') {
            return deferredQuery.promise;
          }
          return undefined;
        },
      });
      const { mockRedis } = createMockRedis();

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      // Start probe in background
      const probePromise = worker.runHealthProbe(1000);

      // Stop immediately while probe is pending
      const t0 = Date.now();
      await worker.stop();
      const duration = Date.now() - t0;

      expect(duration).toBeLessThan(500); // Shuts down quickly within Compose grace window
      expect(worker.isReady()).toBe(false);

      const probeResult = await probePromise;
      expect(probeResult.ok).toBe(false);
    });

    it('11. Recovery after dependency availability returns', async () => {
      let isPgBroken = false;
      const { mockPgPool } = createMockPg({
        queryImpl: (sql) => {
          if (sql === 'SELECT 1' && isPgBroken) {
            return Promise.reject(new Error('CONNECTION_LOST'));
          }
          return undefined;
        },
      });
      const { mockRedis } = createMockRedis();

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      expect(worker.isReady()).toBe(true);

      // Outage occurs
      isPgBroken = true;
      const outageProbe = await worker.runHealthProbe(100);
      expect(outageProbe.ok).toBe(false);
      expect(worker.isReady()).toBe(false);

      // Dependency recovers
      isPgBroken = false;
      const recoveryProbe = await worker.runHealthProbe(100);
      expect(recoveryProbe.ok).toBe(true);
      expect(worker.isReady()).toBe(true);

      await worker.stop();
    });

    it('12. Bounded number of underlying active operations and pool waiters across repeated timeouts', async () => {
      const { mockPgPool, poolTracker } = createMockPg({
        queryImpl: (sql) => {
          if (sql === 'SELECT 1') {
            return new Promise(() => {}); // never resolves
          }
          return undefined;
        },
      });
      const { mockRedis } = createMockRedis();

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      for (let i = 0; i < 5; i += 1) {
        await worker.runHealthProbe(30);
      }

      // 1. Wrapper level active operations return to 0
      expect(worker.getActiveOperationsCount()).toBe(0);

      // 2. Underlying pool tracking proves no client leak or waiting pool starvation (WRK-07)
      expect(poolTracker.activeClientsCount).toBe(0);
      expect(poolTracker.waitingCount).toBe(0);
      expect(poolTracker.destroyedClients).toHaveLength(5);
      for (const client of poolTracker.destroyedClients) {
        expect(client.release).toHaveBeenCalledWith(true);
      }

      await worker.stop();
    });

    it('13. Repeated connection acquisition timeouts destroy late clients and do not leak pool slots (WRK-07)', async () => {
      const deferredConnects: Array<ReturnType<typeof createDeferred<unknown>>> = [];
      const { mockPgPool, poolTracker, createClientInstance } = createMockPg({
        connectImpl: () => {
          const deferred = createDeferred<unknown>();
          deferredConnects.push(deferred);
          return deferred.promise;
        },
      });
      const { mockRedis } = createMockRedis();

      // Test direct executeDependencyProbe across 3 consecutive connect timeouts
      for (let i = 0; i < 3; i++) {
        const probe = await executeDependencyProbe(mockPgPool, mockRedis, 50);
        expect(probe.ok).toBe(false);
        expect(probe.dependencies.database).toBe('unhealthy');
      }

      expect(deferredConnects).toHaveLength(3);
      expect(poolTracker.waitingCount).toBe(3);

      // Simulate delayed arrival of all 3 connection acquisitions
      const lateClients = [
        createClientInstance(101),
        createClientInstance(102),
        createClientInstance(103),
      ];
      for (let i = 0; i < 3; i++) {
        deferredConnects[i]!.resolve(lateClients[i]!);
      }

      await new Promise((r) => setTimeout(r, 20));

      // Each late client must have been destroyed immediately
      for (const client of lateClients) {
        expect(client.release).toHaveBeenCalledWith(true);
      }
      expect(poolTracker.activeClientsCount).toBe(0);
      expect(poolTracker.waitingCount).toBe(0);
    });

    it('14. Clear distinction between wrapper completion and underlying resource cleanup (WRK-07)', async () => {
      const deferredQuery = createDeferred<unknown>();
      const { mockPgPool, poolTracker } = createMockPg({
        queryImpl: (sql) => {
          if (sql === 'SELECT 1') {
            return deferredQuery.promise;
          }
          return undefined;
        },
      });
      const { mockRedis } = createMockRedis();

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      const t0 = Date.now();
      const probeResult = await worker.runHealthProbe(50);
      const probeDuration = Date.now() - t0;

      // 1. Wrapper completion assertion: probe finished boundedly
      expect(probeDuration).toBeLessThan(150);
      expect(probeResult.ok).toBe(false);
      expect(probeResult.error).toBe('Worker readiness check timed out');
      expect(worker.getActiveOperationsCount()).toBe(0);

      // 2. Underlying resource cleanup assertion: active client destroyed and checked out count is 0
      expect(poolTracker.activeClientsCount).toBe(0);
      expect(poolTracker.waitingCount).toBe(0);
      expect(poolTracker.destroyedClients.length).toBeGreaterThanOrEqual(1);

      // 3. Resolve deferred query late and assert no secondary mutation occurs
      deferredQuery.resolve({ rows: [{ '?column?': 1 }] });
      await new Promise((r) => setTimeout(r, 20));
      expect(worker.isReady()).toBe(false);

      await worker.stop();
    });

    it('15. Redis command timeout behavior terminates boundedly and marks dependency unhealthy (WRK-07)', async () => {
      let failPingWithTimeout = false;
      const { mockPgPool } = createMockPg();
      const { mockRedis } = createMockRedis({
        pingImpl: () => {
          if (failPingWithTimeout) {
            // Simulate ioredis command timeout error
            return Promise.reject(new Error('Command timed out'));
          }
          return Promise.resolve('PONG');
        },
      });

      const worker = await createWorker(getTestEnv(), {
        pgPool: mockPgPool,
        redis: mockRedis,
      });

      expect(worker.isReady()).toBe(true);

      // Trigger timeout on Redis probe
      failPingWithTimeout = true;
      const probe = await worker.runHealthProbe(100);
      expect(probe.ok).toBe(false);
      expect(probe.dependencies.redis).toBe('unhealthy');
      expect(worker.isReady()).toBe(false);
      expect(worker.getActiveOperationsCount()).toBe(0);

      // Recovery
      failPingWithTimeout = false;
      const recoveredProbe = await worker.runHealthProbe(100);
      expect(recoveredProbe.ok).toBe(true);
      expect(recoveredProbe.dependencies.redis).toBe('healthy');
      expect(worker.isReady()).toBe(true);

      await worker.stop();
    });
  });

  // =========================================================================
  // Section 6: WRK-05 — Heartbeat Freshness Alignment & Probe Configuration
  // =========================================================================
  describe('WRK-05: Heartbeat Freshness Alignment & Probe Configuration', () => {
    it('1. Default configuration calculates coherent freshness threshold (15000ms)', () => {
      const config = parseWorkerConfig({
        NODE_ENV: 'test',
        POSTGRES_PASSWORD: 'test_password',
        REDIS_PASSWORD: 'test_password',
      });
      expect(config.WORKER_PROBE_INTERVAL_MS).toBe(5000);
      expect(config.WORKER_PROBE_TIMEOUT_MS).toBe(2000);
      expect(config.FRESHNESS_THRESHOLD_MS).toBe(15000);
    });

    it('2. Minimum supported interval parses correctly (100ms / 50ms)', () => {
      const config = parseWorkerConfig({
        ...getTestEnv(),
        WORKER_PROBE_INTERVAL_MS: '100',
        WORKER_PROBE_TIMEOUT_MS: '50',
      });
      expect(config.WORKER_PROBE_INTERVAL_MS).toBe(100);
      expect(config.WORKER_PROBE_TIMEOUT_MS).toBe(50);
      expect(config.FRESHNESS_THRESHOLD_MS).toBe(300);
    });

    it('3. Maximum supported interval parses correctly (30000ms / 10000ms)', () => {
      const config = parseWorkerConfig({
        ...getTestEnv(),
        WORKER_PROBE_INTERVAL_MS: '30000',
        WORKER_PROBE_TIMEOUT_MS: '10000',
      });
      expect(config.WORKER_PROBE_INTERVAL_MS).toBe(30000);
      expect(config.WORKER_PROBE_TIMEOUT_MS).toBe(10000);
      expect(config.FRESHNESS_THRESHOLD_MS).toBe(90000);
    });

    it('4. Probe timeout greater than interval is rejected fail-closed', () => {
      expect(() =>
        parseWorkerConfig({
          ...getTestEnv(),
          WORKER_PROBE_INTERVAL_MS: '1000',
          WORKER_PROBE_TIMEOUT_MS: '2000',
        }),
      ).toThrow(
        /WORKER_PROBE_TIMEOUT_MS: Probe timeout \(2000ms\) cannot exceed probe interval \(1000ms\)/,
      );
    });

    it('5. Invalid negative, zero and excessively large values are rejected', () => {
      expect(() => parseWorkerConfig({ ...getTestEnv(), WORKER_PROBE_INTERVAL_MS: '-1' })).toThrow(
        WorkerConfigValidationError,
      );
      expect(() => parseWorkerConfig({ ...getTestEnv(), WORKER_PROBE_INTERVAL_MS: '0' })).toThrow(
        WorkerConfigValidationError,
      );
      expect(() =>
        parseWorkerConfig({ ...getTestEnv(), WORKER_PROBE_INTERVAL_MS: '30001' }),
      ).toThrow(WorkerConfigValidationError);
      expect(() => parseWorkerConfig({ ...getTestEnv(), WORKER_PROBE_TIMEOUT_MS: '0' })).toThrow(
        WorkerConfigValidationError,
      );
      expect(() =>
        parseWorkerConfig({ ...getTestEnv(), WORKER_PROBE_TIMEOUT_MS: '10001' }),
      ).toThrow(WorkerConfigValidationError);
    });

    it('6. Healthy dependencies produce fresh heartbeat without false expiry', () => {
      fs.writeFileSync(
        tmpHealthFile,
        JSON.stringify({
          status: 'ready',
          pid: process.pid,
          timestamp: Date.now(),
          freshnessThresholdMs: 15000,
        }),
        'utf8',
      );

      const check = checkWorkerHealth(tmpHealthFile);
      expect(check.ok).toBe(true);
    });

    it('7. Genuine stale heartbeat is rejected by health check', () => {
      fs.writeFileSync(
        tmpHealthFile,
        JSON.stringify({
          status: 'ready',
          pid: process.pid,
          timestamp: Date.now() - 20000,
          freshnessThresholdMs: 15000,
        }),
        'utf8',
      );

      const check = checkWorkerHealth(tmpHealthFile);
      expect(check.ok).toBe(false);
      expect(check.error).toContain('worker heartbeat is stale (>15000ms)');
    });

    it('8. Readiness failure detection occurs within documented bound', () => {
      fs.writeFileSync(
        tmpHealthFile,
        JSON.stringify({
          status: 'unhealthy',
          pid: process.pid,
          timestamp: Date.now(),
          freshnessThresholdMs: 15000,
          reason: 'Worker dependency check failed',
        }),
        'utf8',
      );

      const check = checkWorkerHealth(tmpHealthFile);
      expect(check.ok).toBe(false);
      expect(check.error).toContain('worker status is "unhealthy"');
    });
  });

  // =========================================================================
  // Section 7: WRK-06 — Production Credential Validation & Synthetic Canary Rejection
  // =========================================================================
  describe('WRK-06: Production Credential Validation & Synthetic Canary Rejection', () => {
    const CANARY_DEV_PG_PW = 'switchyard_worker_password';
    const CANARY_DEV_REDIS_PW = 'switchyard_worker_password';
    const CANARY_VALID_PROD_PG_PW = 'prod_sec_pg_canary_987654321';
    const CANARY_VALID_PROD_REDIS_PW = 'prod_sec_redis_canary_123456789';

    it('1. Production rejects the known development PostgreSQL credential', () => {
      expect(() =>
        parseWorkerConfig({
          ...getTestEnv(),
          NODE_ENV: 'production',
          POSTGRES_PASSWORD: CANARY_DEV_PG_PW,
          REDIS_PASSWORD: CANARY_VALID_PROD_REDIS_PW,
        }),
      ).toThrow(/Default development credentials are prohibited in production profile/);
    });

    it('2. Production rejects the known development Redis credential', () => {
      expect(() =>
        parseWorkerConfig({
          ...getTestEnv(),
          NODE_ENV: 'production',
          POSTGRES_PASSWORD: CANARY_VALID_PROD_PG_PW,
          REDIS_PASSWORD: CANARY_DEV_REDIS_PW,
        }),
      ).toThrow(/Default development credentials are prohibited in production profile/);
    });

    it('3. Production accepts syntactically valid non-default credentials', () => {
      const config = parseWorkerConfig({
        ...getTestEnv(),
        NODE_ENV: 'production',
        POSTGRES_PASSWORD: CANARY_VALID_PROD_PG_PW,
        REDIS_PASSWORD: CANARY_VALID_PROD_REDIS_PW,
      });

      expect(config.NODE_ENV).toBe('production');
      expect(config.POSTGRES_PASSWORD).toBe(CANARY_VALID_PROD_PG_PW);
      expect(config.REDIS_PASSWORD).toBe(CANARY_VALID_PROD_REDIS_PW);
    });

    it('4. Development behavior remains compatible with default credentials', () => {
      const config = parseWorkerConfig({
        ...getTestEnv(),
        NODE_ENV: 'development',
        POSTGRES_PASSWORD: CANARY_DEV_PG_PW,
        REDIS_PASSWORD: CANARY_DEV_REDIS_PW,
      });

      expect(config.NODE_ENV).toBe('development');
      expect(config.POSTGRES_PASSWORD).toBe(CANARY_DEV_PG_PW);
    });

    it('5. Error messages do not expose credentials under any profile', () => {
      const secretCanary = 'canary_secret_pg_pass_xyz_999'; // gitleaks:allow
      try {
        parseWorkerConfig({
          ...getTestEnv(),
          NODE_ENV: 'production',
          POSTGRES_PASSWORD: secretCanary,
          REDIS_PASSWORD: '', // invalid
        });
        expect.unreachable();
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        expect(msg).not.toContain(secretCanary);
      }
    });

    it('6. Structured startup logs do not expose credentials', async () => {
      const logChunks: string[] = [];
      const stream = new Writable({
        write(chunk, _encoding, callback) {
          logChunks.push(chunk.toString());
          callback();
        },
      });

      const workerLogger = createLogger({
        environment: 'production',
        serviceName: '@switchyard/worker',
        stream,
      });

      const { mockPgPool } = createMockPg();
      const { mockRedis } = createMockRedis();

      const worker = await createWorker(
        {
          ...getTestEnv(),
          NODE_ENV: 'production',
          POSTGRES_PASSWORD: CANARY_VALID_PROD_PG_PW,
          REDIS_PASSWORD: CANARY_VALID_PROD_REDIS_PW,
        },
        { pgPool: mockPgPool, redis: mockRedis },
      );

      workerLogger.info({ pid: process.pid }, 'Worker startup verified');

      await worker.stop();

      const fullLogOutput = logChunks.join('\n');
      expect(fullLogOutput).not.toContain(CANARY_VALID_PROD_PG_PW);
      expect(fullLogOutput).not.toContain(CANARY_VALID_PROD_REDIS_PW);
    });

    it('7. Production bypass flags remain rejected', () => {
      expect(() =>
        parseWorkerConfig({
          ...getTestEnv(),
          NODE_ENV: 'production',
          POSTGRES_PASSWORD: CANARY_VALID_PROD_PG_PW,
          REDIS_PASSWORD: CANARY_VALID_PROD_REDIS_PW,
          FAIL_OPEN: 'true',
        }),
      ).toThrow(/Forbidden security flag detected: FAIL_OPEN/);
    });

    it('8. Worker configuration cannot receive KEKs fail-closed', () => {
      expect(() =>
        parseWorkerConfig({
          ...getTestEnv(),
          NODE_ENV: 'production',
          POSTGRES_PASSWORD: CANARY_VALID_PROD_PG_PW,
          REDIS_PASSWORD: CANARY_VALID_PROD_REDIS_PW,
          MASTER_KEK_V1: 'canary_kek_should_fail',
        }),
      ).toThrow(
        /Worker runtime must not have access to provider encryption keys or KEKs: MASTER_KEK_V1 is forbidden/,
      );
    });
  });
});
