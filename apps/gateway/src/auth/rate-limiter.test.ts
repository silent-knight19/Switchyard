import type { Redis } from 'ioredis';
import type pg from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { hashAccountIdentifier, LoginRateLimiter, sanitizeClientIp } from './rate-limiter.js';
import { AuthenticationService } from './service.js';
import { AuthenticationError } from './types.js';

describe('SW-1.5.1: Login Rate Limiting & Abuse Prevention', () => {
  describe('Strict IP Sanitization (AUTH-05)', () => {
    it('accepts valid IPv4 addresses and strips port suffix when present', () => {
      expect(sanitizeClientIp('192.168.1.100:54321')).toBe('192.168.1.100');
      expect(sanitizeClientIp('10.0.0.1')).toBe('10.0.0.1');
      expect(sanitizeClientIp('127.0.0.1:8080')).toBe('127.0.0.1');
    });

    it('accepts valid IPv6 addresses and bracketed IPv6 with port', () => {
      expect(sanitizeClientIp('2001:db8::1')).toBe('2001:db8::1');
      expect(sanitizeClientIp('[2001:db8::1]:8080')).toBe('2001:db8::1');
      expect(sanitizeClientIp('::1')).toBe('::1');
      expect(sanitizeClientIp('[::1]:3000')).toBe('::1');
      // Canonicalizes uppercase hex
      expect(sanitizeClientIp('2001:DB8::ABCD')).toBe('2001:db8::abcd');
    });

    it('fails closed and rejects empty, whitespace, and non-string inputs (no loopback fallback)', () => {
      expect(() => sanitizeClientIp('')).toThrow(AuthenticationError);
      expect(() => sanitizeClientIp('   ')).toThrow(AuthenticationError);
      expect(() => sanitizeClientIp(null)).toThrow(AuthenticationError);
      expect(() => sanitizeClientIp(undefined)).toThrow(AuthenticationError);
      expect(() => sanitizeClientIp(12345)).toThrow(AuthenticationError);
    });

    it('fails closed and rejects malformed non-IP strings', () => {
      expect(() => sanitizeClientIp('not-an-ip')).toThrow(AuthenticationError);
      expect(() => sanitizeClientIp('192.168.1.999')).toThrow(AuthenticationError);
      expect(() => sanitizeClientIp('999.999.999.999')).toThrow(AuthenticationError);
      expect(() => sanitizeClientIp('user_header_injection; eval')).toThrow(AuthenticationError);
      expect(() => sanitizeClientIp('../../../etc/passwd')).toThrow(AuthenticationError);
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

  describe('Mandatory Rate Limiter Dependency Invariant (AUTH-01)', () => {
    const dummyPool = {} as unknown as pg.Pool;

    it('fails closed at construction if rateLimiter dependency is missing', () => {
      expect(
        () =>
          new AuthenticationService({
            pool: dummyPool,
          } as unknown as { pool: pg.Pool; rateLimiter: LoginRateLimiter }),
      ).toThrow(AuthenticationError);

      try {
        new AuthenticationService({
          pool: dummyPool,
        } as unknown as { pool: pg.Pool; rateLimiter: LoginRateLimiter });
      } catch (err) {
        expect(err).toBeInstanceOf(AuthenticationError);
        expect((err as AuthenticationError).reason).toBe('CONFIGURATION_ERROR');
        expect((err as AuthenticationError).message).toContain('LoginRateLimiter');
      }
    });

    it('invokes assertNotRateLimited test spy before any authentication work', async () => {
      const mockRedis = {
        eval: vi.fn().mockResolvedValue(1),
      } as unknown as Redis;

      const limiter = new LoginRateLimiter(mockRedis);
      const spy = vi.spyOn(limiter, 'assertNotRateLimited');

      // Mock pool returning 0 rows (unknown account)
      const mockPool = {
        query: vi.fn().mockResolvedValue({ rows: [] }),
      } as unknown as pg.Pool;

      const authService = new AuthenticationService({
        pool: mockPool,
        rateLimiter: limiter,
      });

      // Unknown account authentication attempt
      await expect(
        authService.authenticate('unknown@switchyard.ai', 'password123', '10.0.0.1'),
      ).rejects.toThrow(AuthenticationError);

      // Verify the limiter was invoked with exact IP and canonical email
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy).toHaveBeenCalledWith('10.0.0.1', 'unknown@switchyard.ai');
    });

    it('does not query database when rate limiter throws', async () => {
      const mockRedis = {
        eval: vi.fn().mockResolvedValue(0), // 0 = rate limit exceeded
      } as unknown as Redis;

      const limiter = new LoginRateLimiter(mockRedis);
      const querySpy = vi.fn();
      const mockPool = { query: querySpy } as unknown as pg.Pool;

      const authService = new AuthenticationService({
        pool: mockPool,
        rateLimiter: limiter,
      });

      await expect(
        authService.authenticate('user@switchyard.ai', 'password123', '10.0.0.1'),
      ).rejects.toThrow(AuthenticationError);

      // Database lookup was completely bypassed because rate limiter failed closed
      expect(querySpy).not.toHaveBeenCalled();
    });
  });
});
