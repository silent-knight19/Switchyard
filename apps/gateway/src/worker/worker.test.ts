import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { describe, expect, it, vi } from 'vitest';
import { parseWorkerConfig, WorkerConfigValidationError } from './config.js';
import { createWorker, WorkerStartupError } from './worker.js';

describe('Worker Runtime Foundation (SW-P1-B01)', () => {
  const tmpHealthFile = path.join(os.tmpdir(), `test-worker-health-${Date.now()}.json`);

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
    WORKER_HEALTH_FILE: tmpHealthFile,
  };

  it('1. Valid worker configuration parses successfully', () => {
    const config = parseWorkerConfig(validEnv);
    expect(config.NODE_ENV).toBe('test');
    expect(config.POSTGRES_USER).toBe('gateway_worker');
    expect(config.REDIS_USER).toBe('switchyard_worker');
    expect(config.REDIS_MAXMEMORY_POLICY).toBe('noeviction');
  });

  it('2. Missing or invalid required credentials cause startup failure', () => {
    // Missing POSTGRES_PASSWORD
    expect(() => parseWorkerConfig({ ...validEnv, POSTGRES_PASSWORD: '' })).toThrow(
      WorkerConfigValidationError,
    );

    // Missing REDIS_PASSWORD
    expect(() => parseWorkerConfig({ ...validEnv, REDIS_PASSWORD: '' })).toThrow(
      WorkerConfigValidationError,
    );
  });

  it('3. Worker fails closed if user attempts to run as gateway_app, gateway_migrator, or superuser', () => {
    expect(() => parseWorkerConfig({ ...validEnv, POSTGRES_USER: 'gateway_app' })).toThrow(
      /Worker must connect under the restricted 'gateway_worker' database role/,
    );

    expect(() => parseWorkerConfig({ ...validEnv, POSTGRES_USER: 'postgres' })).toThrow(
      /Worker must connect under the restricted 'gateway_worker' database role/,
    );
  });

  it('4. Worker fails closed if Redis user is default or gateway_app', () => {
    expect(() => parseWorkerConfig({ ...validEnv, REDIS_USER: 'default' })).toThrow(
      /Worker cannot use 'default' Redis identity/,
    );

    expect(() => parseWorkerConfig({ ...validEnv, REDIS_USER: 'gateway_app' })).toThrow(
      /Worker cannot use 'gateway_app' Redis identity/,
    );
  });

  it('5. Worker rejects presence of KEKs or provider key decryption material fail-closed', () => {
    expect(() => parseWorkerConfig({ ...validEnv, MASTER_KEK_V1: 'dummy-kek' })).toThrow(
      /Worker runtime must not have access to provider encryption keys or KEKs/,
    );

    expect(() => parseWorkerConfig({ ...validEnv, ACTIVE_KEK_VERSION: '1' })).toThrow(
      /Worker runtime must not have access to provider encryption keys or KEKs/,
    );
  });

  it('6. Worker rejects forbidden security bypass flags', () => {
    expect(() => parseWorkerConfig({ ...validEnv, BYPASS_RLS: 'true' })).toThrow(
      /Forbidden security flag detected/,
    );

    expect(() => parseWorkerConfig({ ...validEnv, FAIL_OPEN: 'true' })).toThrow(
      /Forbidden security flag detected/,
    );
  });

  it('7. Mock dependency initialization: proves successful startup, health file, and clean shutdown', async () => {
    // Mock Postgres client
    const mockPgClient = {
      query: vi.fn().mockImplementation((sql: string) => {
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
      }),
      release: vi.fn(),
    };

    const mockPgPool = {
      connect: vi.fn().mockResolvedValue(mockPgClient),
      end: vi.fn().mockResolvedValue(undefined),
      on: vi.fn(),
    } as unknown as import('pg').Pool;

    // Mock Redis client
    const mockRedis = {
      connect: vi.fn().mockResolvedValue(undefined),
      ping: vi.fn().mockResolvedValue('PONG'),
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

    const worker = await createWorker(validEnv, {
      pgPool: mockPgPool,
      redis: mockRedis,
    });

    expect(worker.isReady()).toBe(true);

    // Verify health file written
    expect(fs.existsSync(tmpHealthFile)).toBe(true);
    const healthContent = JSON.parse(fs.readFileSync(tmpHealthFile, 'utf8')) as {
      status: string;
      pid: number;
    };
    expect(healthContent.status).toBe('ready');
    expect(healthContent.pid).toBe(process.pid);

    // Verify readiness check
    const readiness = await worker.checkReadiness();
    expect(readiness.ok).toBe(true);

    // Verify worker does not start HTTP server or expose fastify
    expect('app' in worker).toBe(false);
    expect('server' in worker).toBe(false);

    // Verify clean shutdown
    await worker.stop();
    expect(worker.isReady()).toBe(false);
    expect(mockRedis.quit).toHaveBeenCalled();
    expect(mockPgPool.end).toHaveBeenCalled();
  });

  it('8. Database failure prevents worker readiness', async () => {
    const mockPgPool = {
      connect: vi.fn().mockRejectedValue(new Error('connection refused')),
      end: vi.fn().mockResolvedValue(undefined),
      on: vi.fn(),
    } as unknown as import('pg').Pool;

    await expect(
      createWorker(validEnv, {
        pgPool: mockPgPool,
      }),
    ).rejects.toThrow('connection refused');
  });

  it('9. Unsafe Redis policy fails closed during startup', async () => {
    const mockPgClient = {
      query: vi.fn().mockImplementation((sql: string) => {
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
          const err = new Error('permission denied') as Error & { code: string };
          err.code = '42501';
          return Promise.reject(err);
        }
        return Promise.resolve({ rows: [] });
      }),
      release: vi.fn(),
    };

    const mockPgPool = {
      connect: vi.fn().mockResolvedValue(mockPgClient),
      end: vi.fn().mockResolvedValue(undefined),
      on: vi.fn(),
    } as unknown as import('pg').Pool;

    const mockRedis = {
      connect: vi.fn().mockResolvedValue(undefined),
      ping: vi.fn().mockResolvedValue('PONG'),
      info: vi.fn().mockResolvedValue('maxmemory_policy:allkeys-lru\r\n'),
      quit: vi.fn().mockResolvedValue('OK'),
      disconnect: vi.fn(),
      on: vi.fn(),
    } as unknown as import('ioredis').Redis;

    await expect(
      createWorker(validEnv, {
        pgPool: mockPgPool,
        redis: mockRedis,
      }),
    ).rejects.toThrow(WorkerStartupError);
  });
});
