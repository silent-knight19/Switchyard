import { Redis } from 'ioredis';
import type { GatewayConfig } from '../config/index.js';

export interface RedisClient {
  redis: Redis;
  checkReadiness(timeoutMs?: number): Promise<{
    ok: boolean;
    policy?: string | undefined;
    code?: string | undefined;
    error?: string | undefined;
  }>;
  verifyAclRestrictions(timeoutMs?: number): Promise<{
    ok: boolean;
    code?: string | undefined;
    error?: string | undefined;
  }>;
  close(): Promise<void>;
}

export function createRedisClient(config: GatewayConfig): RedisClient {
  const redis = new Redis({
    host: config.REDIS_HOST,
    port: config.REDIS_PORT,
    username: config.REDIS_USER,
    password: config.REDIS_PASSWORD,
    tls: config.REDIS_TLS ? {} : undefined,
    lazyConnect: true,
    connectTimeout: 2000,
    maxRetriesPerRequest: 1,
    retryStrategy: (times) => {
      if (times > 2) return null;
      return Math.min(times * 100, 500);
    },
  });

  // Attach silent error listener to prevent unhandled error event noise during connection failures
  redis.on('error', () => {});

  return {
    redis,
    async checkReadiness(timeoutMs = 2000) {
      let timer: NodeJS.Timeout | null = null;
      const timeoutPromise = new Promise<{
        ok: false;
        code: string;
        error: string;
      }>((resolve) => {
        timer = setTimeout(() => {
          resolve({ ok: false, code: 'TIMEOUT', error: 'Redis readiness check timed out' });
        }, timeoutMs);
      });

      const checkPromise = (async () => {
        try {
          const pong = await redis.ping();
          if (pong !== 'PONG') {
            return {
              ok: false,
              code: 'UNEXPECTED_PING_RESPONSE',
              error: 'Unexpected response from Redis ping probe',
            };
          }

          const info = await redis.info('memory');
          const policyMatch = info.match(/maxmemory_policy:([^\r\n]+)/);
          const policy = policyMatch ? policyMatch[1]?.trim() : undefined;

          if (policy !== 'noeviction') {
            return {
              ok: false,
              policy,
              code: 'UNSAFE_POLICY',
              error: `Unsafe Redis policy "${policy}": expected "noeviction"`,
            };
          }

          return { ok: true, policy };
        } catch (err: unknown) {
          const code =
            err && typeof err === 'object' && 'code' in err && typeof err.code === 'string'
              ? err.code
              : 'REDIS_ERROR';
          return { ok: false, code, error: 'Redis readiness check failed' };
        }
      })();

      try {
        return await Promise.race([checkPromise, timeoutPromise]);
      } finally {
        if (timer) clearTimeout(timer);
      }
    },

    async verifyAclRestrictions(timeoutMs = 2000) {
      let timer: NodeJS.Timeout | null = null;
      const timeoutPromise = new Promise<{
        ok: false;
        code: string;
        error: string;
      }>((resolve) => {
        timer = setTimeout(() => {
          resolve({ ok: false, code: 'TIMEOUT', error: 'Redis ACL verification timed out' });
        }, timeoutMs);
      });

      const verifyPromise = (async () => {
        try {
          // Probe 1: Non-destructive administrative probe (CONFIG GET maxmemory)
          // Under least-privilege runtime constraints, CONFIG must be denied with NOPERM.
          let configDenied = false;
          try {
            await redis.call('CONFIG', 'GET', 'maxmemory');
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg.startsWith('NOPERM')) {
              configDenied = true;
            } else {
              throw err;
            }
          }

          if (!configDenied) {
            return {
              ok: false,
              code: 'OVERPRIVILEGED_CONFIG_PERMITTED',
              error:
                'Redis runtime identity is overprivileged: administrative CONFIG command was permitted',
            };
          }

          // Probe 2: Non-destructive key-enumeration probe (KEYS dummy_probe)
          // Unrestricted key enumeration must be denied with NOPERM.
          let keysDenied = false;
          try {
            await redis.call('KEYS', '__switchyard_probe__');
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg.startsWith('NOPERM')) {
              keysDenied = true;
            } else {
              throw err;
            }
          }

          if (!keysDenied) {
            return {
              ok: false,
              code: 'OVERPRIVILEGED_KEYS_PERMITTED',
              error:
                'Redis runtime identity is overprivileged: unrestricted KEYS command was permitted',
            };
          }

          return { ok: true };
        } catch (err: unknown) {
          const code =
            err && typeof err === 'object' && 'code' in err && typeof err.code === 'string'
              ? err.code
              : 'ACL_PROBE_ERROR';
          return { ok: false, code, error: 'Redis ACL verification failed' };
        }
      })();

      try {
        return await Promise.race([verifyPromise, timeoutPromise]);
      } finally {
        if (timer) clearTimeout(timer);
      }
    },

    async close() {
      try {
        if (
          redis.status === 'ready' ||
          redis.status === 'connecting' ||
          redis.status === 'connect'
        ) {
          await redis.quit();
        } else {
          redis.disconnect();
        }
      } catch {
        redis.disconnect();
      }
    },
  };
}
