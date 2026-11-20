import { Redis } from 'ioredis';
import type pg from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { hashAccountIdentifier, LoginRateLimiter } from './rate-limiter.js';
import { AuthenticationService } from './service.js';
import { startDisposableRedis, type DisposableRedisCluster } from './test/disposable-redis.js';
import { AuthenticationError } from './types.js';

describe('SW-1.5.1: Redis 7 Real Rate Limiter Integration Suite (AUTH-05)', () => {
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

      // Lua evaluation must succeed under switchyard_app
      const evalRes = await appRedis.eval('return 42', 0);
      expect(evalRes).toBe(42);
    });

    it('proves prohibited administrative commands are rejected with NOPERM', async () => {
      await expect(appRedis.call('CONFIG', 'GET', 'maxmemory')).rejects.toThrow(/NOPERM/);
      await expect(appRedis.call('KEYS', '*')).rejects.toThrow(/NOPERM/);
      await expect(appRedis.call('FLUSHALL')).rejects.toThrow(/NOPERM/);
      await expect(appRedis.call('FLUSHDB')).rejects.toThrow(/NOPERM/);
    });
  });

  describe('2. Rate Limiter Key Naming & Privacy', () => {
    it('excludes plaintext emails from Redis keys and uses SHA-256 tokens', async () => {
      const limiter = new LoginRateLimiter(appRedis, {
        ipLimit: 10,
        ipWindowSeconds: 60,
        accountLimit: 10,
        accountWindowSeconds: 60,
      });

      const clientIp = '198.51.100.5';
      const email = 'supersecretuser@internalcorp.com';
      await limiter.assertNotRateLimited(clientIp, email);

      const expectedAccountHash = hashAccountIdentifier(email);

      // Verify with admin connection that the account key uses hash only
      const exists = await adminRedis.exists(`auth:ratelimit:account:${expectedAccountHash}`);
      expect(exists).toBe(1);

      // Search keys with admin connection to guarantee plaintext email never appears anywhere in Redis
      const keys = await adminRedis.keys('*');
      for (const k of keys) {
        expect(k).not.toContain(email);
        expect(k).not.toContain('supersecretuser');
      }
    });
  });

  describe('3. Separate IP and Account Limits', () => {
    it('enforces IP rate limit independently of account', async () => {
      const limiter = new LoginRateLimiter(appRedis, {
        ipLimit: 3,
        ipWindowSeconds: 60,
        accountLimit: 100,
        accountWindowSeconds: 60,
      });

      const ip = '203.0.113.19';

      // Attempts from same IP for different accounts
      await limiter.assertNotRateLimited(ip, 'user1@example.com');
      await limiter.assertNotRateLimited(ip, 'user2@example.com');
      await limiter.assertNotRateLimited(ip, 'user3@example.com');

      // 4th attempt from same IP must be rejected regardless of account
      await expect(limiter.assertNotRateLimited(ip, 'user4@example.com')).rejects.toThrow(
        AuthenticationError,
      );

      try {
        await limiter.assertNotRateLimited(ip, 'user4@example.com');
      } catch (err) {
        expect(err).toBeInstanceOf(AuthenticationError);
        expect((err as AuthenticationError).reason).toBe('RATE_LIMITED');
        expect((err as AuthenticationError).message).toContain('IP address');
      }
    });

    it('enforces Account rate limit independently of IP', async () => {
      const limiter = new LoginRateLimiter(appRedis, {
        ipLimit: 100,
        ipWindowSeconds: 60,
        accountLimit: 2,
        accountWindowSeconds: 60,
      });

      const targetEmail = 'targeted.executive@corp.com';

      // 2 attempts from different IPs targeting the same account
      await limiter.assertNotRateLimited('192.0.2.1', targetEmail);
      await limiter.assertNotRateLimited('192.0.2.2', targetEmail);

      // 3rd attempt targeting the same account from a 3rd distinct IP must be rejected
      await expect(limiter.assertNotRateLimited('192.0.2.3', targetEmail)).rejects.toThrow(
        AuthenticationError,
      );

      try {
        await limiter.assertNotRateLimited('192.0.2.3', targetEmail);
      } catch (err) {
        expect(err).toBeInstanceOf(AuthenticationError);
        expect((err as AuthenticationError).reason).toBe('RATE_LIMITED');
        expect((err as AuthenticationError).message).toContain('account');
      }
    });
  });

  describe('4. Atomic Increments under Concurrency', () => {
    it('handles high concurrent attempts atomically without lost increments', async () => {
      const limit = 15;
      const limiter = new LoginRateLimiter(appRedis, {
        ipLimit: limit,
        ipWindowSeconds: 60,
        accountLimit: limit,
        accountWindowSeconds: 60,
      });

      const ip = '198.51.100.99';
      const email = 'concurrency.test@switchyard.ai';

      // Fire 30 concurrent attempts against limit of 15
      const promises: Promise<unknown>[] = [];
      for (let i = 0; i < 30; i++) {
        promises.push(
          limiter
            .assertNotRateLimited(ip, email)
            .then(() => ({ status: 'allowed' }))
            .catch((err) => ({ status: 'rejected', reason: err.reason })),
        );
      }

      const results = (await Promise.all(promises)) as Array<{ status: string; reason?: string }>;

      const allowed = results.filter((r) => r.status === 'allowed');
      const rejected = results.filter((r) => r.status === 'rejected');

      // Exactly 15 attempts allowed, exactly 15 rejected
      expect(allowed).toHaveLength(limit);
      expect(rejected).toHaveLength(30 - limit);
      for (const rej of rejected) {
        expect(rej.reason).toBe('RATE_LIMITED');
      }
    });
  });

  describe('5. TTL Creation and Expiration', () => {
    it('sets TTL on initial increment and preserves TTL on subsequent increments', async () => {
      const windowSeconds = 10;
      const limiter = new LoginRateLimiter(appRedis, {
        ipLimit: 5,
        ipWindowSeconds: windowSeconds,
        accountLimit: 5,
        accountWindowSeconds: windowSeconds,
      });

      const ip = '192.0.2.77';
      const email = 'ttl.test@switchyard.ai';
      const ipKey = `auth:ratelimit:ip:${ip}`;

      await limiter.assertNotRateLimited(ip, email);

      // Verify TTL was set between 1 and 10 seconds
      const ttl1 = await adminRedis.ttl(ipKey);
      expect(ttl1).toBeGreaterThan(0);
      expect(ttl1).toBeLessThanOrEqual(windowSeconds);

      // Second increment must not reset or overwrite TTL
      await limiter.assertNotRateLimited(ip, email);
      const ttl2 = await adminRedis.ttl(ipKey);
      expect(ttl2).toBeGreaterThan(0);
      expect(ttl2).toBeLessThanOrEqual(ttl1);
    });

    it('resets counter after window expires without unexpected counter bypass', async () => {
      // 1-second short window
      const limiter = new LoginRateLimiter(appRedis, {
        ipLimit: 1,
        ipWindowSeconds: 1,
        accountLimit: 1,
        accountWindowSeconds: 1,
      });

      const ip = '192.0.2.88';
      const email = 'expiry.test@switchyard.ai';

      // First attempt succeeds
      await limiter.assertNotRateLimited(ip, email);

      // Immediate second attempt rejected
      await expect(limiter.assertNotRateLimited(ip, email)).rejects.toThrow(AuthenticationError);

      // Wait 1.1s for TTL expiry
      await new Promise((resolve) => setTimeout(resolve, 1100));

      // Attempt after expiry succeeds cleanly
      await expect(limiter.assertNotRateLimited(ip, email)).resolves.toBeUndefined();
    });
  });

  describe('6. Fail-Closed on Redis Unavailability', () => {
    it('fails closed with SERVICE_UNAVAILABLE if Redis disconnects or errors', async () => {
      // Create disconnected client
      const brokenRedis = new Redis({
        host: '127.0.0.1',
        port: 1, // Invalid port
        connectTimeout: 50,
        maxRetriesPerRequest: 0,
        lazyConnect: true,
      });

      // Suppress unhandled error noise
      brokenRedis.on('error', () => {});

      const limiter = new LoginRateLimiter(brokenRedis);

      await expect(limiter.assertNotRateLimited('127.0.0.1', 'user@switchyard.ai')).rejects.toThrow(
        AuthenticationError,
      );

      try {
        await limiter.assertNotRateLimited('127.0.0.1', 'user@switchyard.ai');
      } catch (err) {
        expect(err).toBeInstanceOf(AuthenticationError);
        expect((err as AuthenticationError).reason).toBe('SERVICE_UNAVAILABLE');
        expect((err as AuthenticationError).message).toContain(
          'rate limiter backend is unavailable',
        );
      } finally {
        await brokenRedis.quit().catch(() => undefined);
      }
    });
  });

  describe('7. Integration with AuthenticationService', () => {
    it('proves rate-limited attempt never queries PostgreSQL or runs Argon2', async () => {
      const limiter = new LoginRateLimiter(appRedis, {
        ipLimit: 1,
        ipWindowSeconds: 60,
        accountLimit: 1,
        accountWindowSeconds: 60,
      });

      const querySpy = vi.fn();
      const mockPool = { query: querySpy } as unknown as pg.Pool;

      const authService = new AuthenticationService({
        pool: mockPool,
        rateLimiter: limiter,
      });

      const ip = '198.51.100.200';
      const email = 'protection.target@switchyard.ai';

      // First attempt triggers rate limit check and proceeds to database
      await expect(authService.authenticate(email, 'validPassword123', ip)).rejects.toThrow();
      expect(querySpy).toHaveBeenCalledTimes(1);

      // Second attempt is rate limited: must NEVER query database
      querySpy.mockClear();
      await expect(authService.authenticate(email, 'validPassword123', ip)).rejects.toThrow(
        AuthenticationError,
      );

      // Database was NEVER touched on second attempt!
      expect(querySpy).not.toHaveBeenCalled();
    });
  });
});
