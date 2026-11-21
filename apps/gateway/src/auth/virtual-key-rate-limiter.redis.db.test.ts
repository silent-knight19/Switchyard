import { Redis } from 'ioredis';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startDisposableRedis, type DisposableRedisCluster } from './test/disposable-redis.js';
import { VirtualKeyAuthError, VirtualKeyRateLimiter } from './virtual-key-rate-limiter.js';

describe('SW-1.6.2: Redis 7 Real Rate Limiter Integration Suite', () => {
  let redisCluster: DisposableRedisCluster;
  let appRedis: Redis;
  let adminRedis: Redis;

  beforeAll(async () => {
    redisCluster = await startDisposableRedis();

    // Restricted runtime client (switchyard_app)
    appRedis = new Redis({
      host: redisCluster.host,
      port: redisCluster.port,
      username: redisCluster.appUsername,
      password: redisCluster.appPassword,
      maxRetriesPerRequest: 1,
      lazyConnect: true,
    });
    await appRedis.connect();

    // Administrative client (default user) for inspecting TTL and raw keys
    adminRedis = new Redis({
      host: redisCluster.host,
      port: redisCluster.port,
      password: redisCluster.adminPassword,
      maxRetriesPerRequest: 1,
      lazyConnect: true,
    });
    await adminRedis.connect();
  }, 60_000);

  afterAll(async () => {
    if (appRedis) await appRedis.quit().catch(() => undefined);
    if (adminRedis) await adminRedis.quit().catch(() => undefined);
    if (redisCluster) await redisCluster.stop().catch(() => undefined);
  });

  describe('1. Runtime ACL Verification', () => {
    it('proves switchyard_app is authenticated and EVAL is permitted', async () => {
      const whoami = await appRedis.acl('WHOAMI');
      expect(whoami).toBe('switchyard_app');

      const evalRes = await appRedis.eval('return 100', 0);
      expect(evalRes).toBe(100);
    });

    it('proves prohibited administrative commands are rejected with NOPERM', async () => {
      await expect(appRedis.call('CONFIG', 'GET', 'maxmemory')).rejects.toThrow(/NOPERM/);
      await expect(appRedis.call('KEYS', '*')).rejects.toThrow(/NOPERM/);
      await expect(appRedis.call('FLUSHALL')).rejects.toThrow(/NOPERM/);
      await expect(appRedis.call('FLUSHDB')).rejects.toThrow(/NOPERM/);
    });
  });

  describe('2. Rate Limiter Key Naming, Privacy & TTL', () => {
    it('uses auth:ratelimit:vk:ip:<ip> and excludes credentials from Redis', async () => {
      const limiter = new VirtualKeyRateLimiter(appRedis, {
        ipLimit: 10,
        ipWindowSeconds: 60,
      });

      const clientIp = '198.51.100.42';
      await limiter.assertNotRateLimited(clientIp);

      const expectedKey = `auth:ratelimit:vk:ip:${clientIp}`;
      const exists = await adminRedis.exists(expectedKey);
      expect(exists).toBe(1);

      const ttl = await adminRedis.ttl(expectedKey);
      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(60);

      // Verify no credential strings in Redis
      const val = await adminRedis.get(expectedKey);
      expect(val).toBe('1');
    });
  });

  describe('3. Atomic Increments & Threshold Enforcement', () => {
    it('permits requests up to threshold and rejects subsequent with RATE_LIMITED', async () => {
      const limit = 5;
      const windowSeconds = 300;
      const limiter = new VirtualKeyRateLimiter(appRedis, {
        ipLimit: limit,
        ipWindowSeconds: windowSeconds,
      });

      const testIp = '198.51.100.99';
      await limiter.reset(testIp);

      // Exactly `limit` attempts must succeed
      for (let i = 0; i < limit; i++) {
        await expect(limiter.assertNotRateLimited(testIp)).resolves.toBeUndefined();
      }

      // Check raw Redis counter via admin connection
      const count = await adminRedis.get(`auth:ratelimit:vk:ip:${testIp}`);
      expect(count).toBe(String(limit));

      // Attempt limit + 1 must fail closed with RATE_LIMITED
      await expect(limiter.assertNotRateLimited(testIp)).rejects.toThrow(VirtualKeyAuthError);
      try {
        await limiter.assertNotRateLimited(testIp);
      } catch (err) {
        expect((err as VirtualKeyAuthError).reason).toBe('RATE_LIMITED');
      }
    });

    it('enforces independent counters across distinct IP addresses', async () => {
      const limiter = new VirtualKeyRateLimiter(appRedis, {
        ipLimit: 3,
        ipWindowSeconds: 300,
      });

      const ipA = '198.51.100.10';
      const ipB = '198.51.100.20';
      await limiter.reset(ipA);
      await limiter.reset(ipB);

      // Exhaust IP A
      for (let i = 0; i < 3; i++) {
        await limiter.assertNotRateLimited(ipA);
      }
      await expect(limiter.assertNotRateLimited(ipA)).rejects.toThrow(VirtualKeyAuthError);

      // IP B must remain unaffected
      await expect(limiter.assertNotRateLimited(ipB)).resolves.toBeUndefined();
      await expect(limiter.assertNotRateLimited(ipB)).resolves.toBeUndefined();
    });

    it('resets counter when window expires', async () => {
      const limiter = new VirtualKeyRateLimiter(appRedis, {
        ipLimit: 2,
        ipWindowSeconds: 1, // 1 second window
      });

      const testIp = '198.51.100.77';
      await limiter.reset(testIp);

      await limiter.assertNotRateLimited(testIp);
      await limiter.assertNotRateLimited(testIp);
      await expect(limiter.assertNotRateLimited(testIp)).rejects.toThrow(VirtualKeyAuthError);

      // Wait for 1-second TTL expiration
      await new Promise((resolve) => setTimeout(resolve, 1100));

      // Next attempt after expiration must succeed
      await expect(limiter.assertNotRateLimited(testIp)).resolves.toBeUndefined();
    });
  });

  describe('4. Redis Downtime & Fail-Closed Behavior', () => {
    it('fails closed with SERVICE_UNAVAILABLE when Redis connection drops', async () => {
      const deadRedis = new Redis({
        host: '127.0.0.1',
        port: 65534, // unreachable port
        connectTimeout: 200,
        maxRetriesPerRequest: 0,
        lazyConnect: true,
      });

      const limiter = new VirtualKeyRateLimiter(deadRedis);

      await expect(limiter.assertNotRateLimited('198.51.100.1')).rejects.toThrow(
        VirtualKeyAuthError,
      );
      try {
        await limiter.assertNotRateLimited('198.51.100.1');
      } catch (err) {
        expect((err as VirtualKeyAuthError).reason).toBe('SERVICE_UNAVAILABLE');
      } finally {
        await deadRedis.quit().catch(() => undefined);
      }
    });
  });
});
