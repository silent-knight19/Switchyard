import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import { Redis } from 'ioredis';

const DEFAULT_REDIS_IMAGE = 'redis:7.4.2-alpine';

export const REDIS_CLUSTER_LABEL_KEY = 'switchyard.test';
export const REDIS_CLUSTER_LABEL_VALUE = 'redis';
export const REDIS_CLUSTER_ID_ENV = 'SWITCHYARD_TEST_REDIS_ID';

export interface DisposableRedisCluster {
  host: string;
  port: number;
  appUsername: string;
  appPassword: string;
  adminPassword: string;
  containerName: string;
  token: string;
  stop(): Promise<void>;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function docker(args: string[]): string {
  try {
    return execFileSync('docker', args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    const stderr =
      typeof error === 'object' && error !== null && 'stderr' in error
        ? String((error as { stderr?: unknown }).stderr ?? '')
        : '';
    throw new Error(
      `Docker command failed: docker ${args.join(' ')}${stderr === '' ? '' : `: ${stderr.trim()}`}. ` +
        'The disposable Redis test suite requires Docker with a reachable daemon.',
    );
  }
}

async function waitForRedis(
  host: string,
  port: number,
  password: string,
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    const client = new Redis({
      host,
      port,
      password,
      connectTimeout: 1000,
      maxRetriesPerRequest: 1,
      lazyConnect: true,
    });
    try {
      await client.connect();
      const pong = await client.ping();
      await client.quit();
      if (pong === 'PONG') {
        return;
      }
    } catch (error) {
      lastError = error;
      await client.quit().catch(() => undefined);
      await delay(250);
    }
  }
  throw new Error(
    `Redis did not become ready within ${timeoutMs}ms: ${
      lastError instanceof Error ? lastError.message : String(lastError)
    }`,
  );
}

/**
 * Starts a disposable, isolated Redis 7 container with the production-aligned ACL contract.
 * Container is automatically destroyed when stop() is called.
 */
export async function startDisposableRedis(): Promise<DisposableRedisCluster> {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Refusing to start disposable Redis container with NODE_ENV=production');
  }

  const containerName = `switchyard-test-redis-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  const token = crypto.randomBytes(32).toString('hex');
  const adminPassword = crypto.randomBytes(18).toString('hex');
  const appUsername = 'switchyard_app';
  const appPassword = 'switchyard_app_password';

  // Config string matching docker-compose.yml ACL and safety invariants
  const redisConfig = [
    'appendonly yes',
    'appendfsync everysec',
    'maxmemory 64mb',
    'maxmemory-policy noeviction',
    `requirepass ${adminPassword}`,
    `user default on >${adminPassword} ~* &* +@all`,
    `user ${appUsername} on >${appPassword} ~* &* +@all -@admin -@dangerous +info -FLUSHALL -FLUSHDB -CONFIG -DEBUG -SHUTDOWN -REPLICAOF -KEYS`,
  ].join('\n');

  docker([
    'run',
    '-d',
    '--rm',
    '--name',
    containerName,
    '--label',
    `${REDIS_CLUSTER_LABEL_KEY}=${REDIS_CLUSTER_LABEL_VALUE}`,
    '-e',
    `${REDIS_CLUSTER_ID_ENV}=${token}`,
    '-p',
    '127.0.0.1::6379',
    process.env.TEST_REDIS_IMAGE ?? DEFAULT_REDIS_IMAGE,
    '/bin/sh',
    '-c',
    `printf "${redisConfig.replace(/\n/g, '\\n')}\\n" | exec redis-server -`,
  ]);

  const stop = async (): Promise<void> => {
    try {
      docker(['rm', '-f', containerName]);
    } catch {
      // Container cleanup is best-effort but idempotent.
    }
  };

  try {
    const portOutput = docker(['port', containerName, '6379']).trim();
    const portStr = portOutput.slice(portOutput.lastIndexOf(':') + 1);
    const port = Number(portStr);
    if (!Number.isInteger(port) || port <= 0) {
      throw new Error(`Could not determine the mapped Redis port from "${portOutput}"`);
    }

    await waitForRedis('127.0.0.1', port, adminPassword, 30_000);

    return {
      host: '127.0.0.1',
      port,
      appUsername,
      appPassword,
      adminPassword,
      containerName,
      token,
      stop,
    };
  } catch (error) {
    await stop();
    throw error;
  }
}
