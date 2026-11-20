import type { Redis } from 'ioredis';
import { describe, expect, it } from 'vitest';
import { hashAccountIdentifier, LoginRateLimiter, sanitizeClientIp } from './rate-limiter.js';
import { AuthenticationError } from './types.js';

describe('SW-1.5.1: Login Rate Limiting & Abuse Prevention', () => {
  describe('IP Sanitization and Account Hash', () => {
    it('sanitizes client IP by stripping port if present', () => {
      expect(sanitizeClientIp('192.168.1.100:54321')).toBe('192.168.1.100');
      expect(sanitizeClientIp('10.0.0.1')).toBe('10.0.0.1');
      expect(sanitizeClientIp('2001:db8::1')).toBe('2001:db8::1');
      expect(sanitizeClientIp('')).toBe('127.0.0.1');
      expect(sanitizeClientIp(null)).toBe('127.0.0.1');
    });

    it('creates irreversible SHA-256 hash token for account identifier', () => {
      const email = 'admin@switchyard.ai';
      const token = hashAccountIdentifier(email);
      expect(token).toMatch(/^[0-9a-f]{64}$/);
      expect(token).not.toContain('@');
      expect(token).not.toContain('admin');
      // Case-insensitive normalization
      expect(hashAccountIdentifier('ADMIN@SWITCHYARD.AI')).toBe(token);
    });
  });

  describe('LoginRateLimiter with Mock Redis', () => {
    it('allows requests within policy limits', async () => {
      const mockRedis = {
        eval: async () => 1, // 1 = allowed
      } as unknown as Redis;

      const limiter = new LoginRateLimiter(mockRedis, {
        ipLimit: 5,
        ipWindowSeconds: 60,
        accountLimit: 3,
        accountWindowSeconds: 60,
      });

      await expect(
        limiter.assertNotRateLimited('192.168.1.1', 'user@example.com'),
      ).resolves.toBeUndefined();
    });

    it('rejects with RATE_LIMITED when IP or account exceeds limit', async () => {
      let callCount = 0;
      const mockRedis = {
        eval: async () => {
          callCount++;
          if (callCount === 1) return 0; // IP limit exceeded
          return 1;
        },
      } as unknown as Redis;

      const limiter = new LoginRateLimiter(mockRedis);

      await expect(limiter.assertNotRateLimited('192.168.1.1', 'user@example.com')).rejects.toThrow(
        AuthenticationError,
      );

      try {
        await limiter.assertNotRateLimited('192.168.1.1', 'user@example.com');
      } catch (err) {
        expect(err).toBeInstanceOf(AuthenticationError);
        expect((err as AuthenticationError).reason).toBe('RATE_LIMITED');
      }
    });

    it('fails closed with SERVICE_UNAVAILABLE when Redis throws an error', async () => {
      const mockRedis = {
        eval: async () => {
          throw new Error('Connection lost to Redis cluster');
        },
      } as unknown as Redis;

      const limiter = new LoginRateLimiter(mockRedis);

      await expect(limiter.assertNotRateLimited('192.168.1.1', 'user@example.com')).rejects.toThrow(
        AuthenticationError,
      );

      try {
        await limiter.assertNotRateLimited('192.168.1.1', 'user@example.com');
      } catch (err) {
        expect(err).toBeInstanceOf(AuthenticationError);
        expect((err as AuthenticationError).reason).toBe('SERVICE_UNAVAILABLE');
      }
    });
  });
});
