import { Redis } from 'ioredis';
import type { GatewayConfig } from '../config/index.js';

export interface RedisClient {
  redis: Redis;
  checkReadiness(): Promise<{
    ok: boolean;
    policy?: string | undefined;
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
    connectTimeout: 3000,
    maxRetriesPerRequest: 1,
    retryStrategy: (times) => {
      if (times > 3) return null;
      return Math.min(times * 100, 1000);
    },
  });

  // Attach silent error listener to prevent unhandled error event noise during connection failures
  redis.on('error', () => {});

  return {
    redis,
    async checkReadiness() {
      try {
        const pong = await redis.ping();
        if (pong !== 'PONG') {
          return { ok: false, error: `Unexpected PING response: ${pong}` };
        }

        const info = await redis.info('memory');
        const policyMatch = info.match(/maxmemory_policy:([^\r\n]+)/);
        const policy = policyMatch ? policyMatch[1]?.trim() : undefined;

        if (policy !== 'noeviction') {
          return {
            ok: false,
            policy,
            error: `Unsafe Redis policy "${policy}": expected "noeviction"`,
          };
        }

        return { ok: true, policy };
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown Redis error';
        return { ok: false, error: message };
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
