import type { Redis } from 'ioredis';
import { describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_VIRTUAL_KEY_RATE_LIMIT_POLICY,
  VirtualKeyAuthError,
  VirtualKeyRateLimiter,
} from './virtual-key-rate-limiter.js';

describe('VirtualKeyRateLimiter Unit Suite (SW-1.6.2)', () => {
  function createMockRedis(evalResult: number = 1): Redis {
    return {
      eval: vi.fn().mockResolvedValue(evalResult),
      del: vi.fn().mockResolvedValue(1),
    } as unknown as Redis;
  }

  describe('Configuration & Instantiation', () => {
    it('throws CONFIGURATION_ERROR if Redis client is missing', () => {
      expect(() => new VirtualKeyRateLimiter(undefined as unknown as Redis)).toThrow(
        VirtualKeyAuthError,
      );
      expect(() => new VirtualKeyRateLimiter(undefined as unknown as Redis)).toThrow(
        /Redis instance is required/,
      );
    });

    it('uses default policy (30 attempts / 900 seconds) when not specified', async () => {
      const mockRedis = createMockRedis(1);
      const limiter = new VirtualKeyRateLimiter(mockRedis);

      await limiter.assertNotRateLimited('192.168.1.1');

      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.any(String),
        1,
        'auth:ratelimit:vk:ip:192.168.1.1',
        DEFAULT_VIRTUAL_KEY_RATE_LIMIT_POLICY.ipWindowSeconds,
        DEFAULT_VIRTUAL_KEY_RATE_LIMIT_POLICY.ipLimit,
      );
    });

    it('applies custom policy when provided', async () => {
      const mockRedis = createMockRedis(1);
      const limiter = new VirtualKeyRateLimiter(mockRedis, {
        ipLimit: 5,
        ipWindowSeconds: 60,
      });

      await limiter.assertNotRateLimited('192.168.1.1');

      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.any(String),
        1,
        'auth:ratelimit:vk:ip:192.168.1.1',
        60,
        5,
      );
    });
  });

  describe('Client IP Sanitization & Validation', () => {
    it('accepts canonical IPv4 and IPv6 addresses', async () => {
      const mockRedis = createMockRedis(1);
      const limiter = new VirtualKeyRateLimiter(mockRedis);

      await expect(limiter.assertNotRateLimited('10.0.0.1')).resolves.toBeUndefined();
      await expect(
        limiter.assertNotRateLimited('2001:0db8:85a3:0000:0000:8a2e:0370:7334'),
      ).resolves.toBeUndefined();
    });

    it('strips port from IPv4 and bracketed IPv6 addresses', async () => {
      const mockRedis = createMockRedis(1);
      const limiter = new VirtualKeyRateLimiter(mockRedis);

      await limiter.assertNotRateLimited('192.168.1.1:8080');
      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.any(String),
        1,
        'auth:ratelimit:vk:ip:192.168.1.1',
        expect.any(Number),
        expect.any(Number),
      );

      await limiter.assertNotRateLimited('[::1]:9000');
      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.any(String),
        1,
        'auth:ratelimit:vk:ip:::1',
        expect.any(Number),
        expect.any(Number),
      );
    });

    it('fails closed on missing, non-string, or invalid client IP', async () => {
      const mockRedis = createMockRedis(1);
      const limiter = new VirtualKeyRateLimiter(mockRedis);

      await expect(limiter.assertNotRateLimited(undefined as unknown as string)).rejects.toThrow(
        VirtualKeyAuthError,
      );
      await expect(limiter.assertNotRateLimited('' as unknown as string)).rejects.toThrow(
        VirtualKeyAuthError,
      );
      await expect(limiter.assertNotRateLimited('   ')).rejects.toThrow(VirtualKeyAuthError);
      await expect(limiter.assertNotRateLimited('not-an-ip')).rejects.toThrow(VirtualKeyAuthError);
      await expect(limiter.assertNotRateLimited('999.999.999.999')).rejects.toThrow(
        VirtualKeyAuthError,
      );
    });
  });

  describe('Rate Limiting & Failure Handling', () => {
    it('resolves normally when counter is within limit (eval returns 1)', async () => {
      const mockRedis = createMockRedis(1);
      const limiter = new VirtualKeyRateLimiter(mockRedis);

      await expect(limiter.assertNotRateLimited('1.2.3.4')).resolves.toBeUndefined();
    });

    it('throws RATE_LIMITED when threshold is exceeded (eval returns 0)', async () => {
      const mockRedis = createMockRedis(0);
      const limiter = new VirtualKeyRateLimiter(mockRedis);

      await expect(limiter.assertNotRateLimited('1.2.3.4')).rejects.toThrow(VirtualKeyAuthError);
      try {
        await limiter.assertNotRateLimited('1.2.3.4');
      } catch (err) {
        expect((err as VirtualKeyAuthError).reason).toBe('RATE_LIMITED');
        expect((err as VirtualKeyAuthError).message).toContain('Too many authentication attempts');
      }
    });

    it('fails closed with SERVICE_UNAVAILABLE when Redis throws an error', async () => {
      const mockRedis = {
        eval: vi.fn().mockRejectedValue(new Error('Connection refused')),
      } as unknown as Redis;
      const limiter = new VirtualKeyRateLimiter(mockRedis);

      await expect(limiter.assertNotRateLimited('1.2.3.4')).rejects.toThrow(VirtualKeyAuthError);
      try {
        await limiter.assertNotRateLimited('1.2.3.4');
      } catch (err) {
        expect((err as VirtualKeyAuthError).reason).toBe('SERVICE_UNAVAILABLE');
        expect((err as VirtualKeyAuthError).message).toContain('backend is unavailable');
      }
    });

    it('reset() deletes the correct Redis key for client IP', async () => {
      const mockRedis = createMockRedis(1);
      const limiter = new VirtualKeyRateLimiter(mockRedis);

      await limiter.reset('192.168.1.5');
      expect(mockRedis.del).toHaveBeenCalledWith('auth:ratelimit:vk:ip:192.168.1.5');
    });
  });
});
