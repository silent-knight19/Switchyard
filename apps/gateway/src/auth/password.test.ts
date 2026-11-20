import { describe, expect, it } from 'vitest';
import {
  Argon2ConcurrencyLimiter,
  dummyVerifyPassword,
  hashPassword,
  validatePasswordInput,
  verifyPassword,
} from './password.js';
import { AuthenticationError } from './types.js';

describe('SW-1.5.1: Password Validation, Argon2id Hashing & Bounded Concurrency', () => {
  describe('Password byte-length validation', () => {
    it('accepts passwords within the 128-byte limit', () => {
      expect(validatePasswordInput('a'.repeat(128))).toBe('a'.repeat(128));
      expect(validatePasswordInput('simple-password-123')).toBe('simple-password-123');
    });

    it('measures UTF-8 byte length, not JavaScript character count, for multibyte characters', () => {
      // Euro sign (€) is 3 bytes in UTF-8
      const euroChar = '€';
      expect(Buffer.byteLength(euroChar, 'utf8')).toBe(3);
      expect(euroChar.length).toBe(1);

      // 42 euro signs = 126 bytes (valid)
      const validMultibyte = euroChar.repeat(42);
      expect(Buffer.byteLength(validMultibyte, 'utf8')).toBe(126);
      expect(validatePasswordInput(validMultibyte)).toBe(validMultibyte);

      // 43 euro signs = 129 bytes (exceeds 128 bytes, even though character length is only 43!)
      const invalidMultibyte = euroChar.repeat(43);
      expect(Buffer.byteLength(invalidMultibyte, 'utf8')).toBe(129);
      expect(invalidMultibyte.length).toBe(43);

      expect(() => validatePasswordInput(invalidMultibyte)).toThrow(AuthenticationError);
      try {
        validatePasswordInput(invalidMultibyte);
      } catch (err) {
        expect(err).toBeInstanceOf(AuthenticationError);
        expect((err as AuthenticationError).reason).toBe('INVALID_INPUT');
      }
    });

    it('rejects passwords exceeding 128 bytes', () => {
      const oversized = 'a'.repeat(129);
      expect(() => validatePasswordInput(oversized)).toThrow(AuthenticationError);
    });

    it('rejects empty and non-string passwords', () => {
      expect(() => validatePasswordInput('')).toThrow(AuthenticationError);
      expect(() => validatePasswordInput(null)).toThrow(AuthenticationError);
      expect(() => validatePasswordInput(undefined)).toThrow(AuthenticationError);
      expect(() => validatePasswordInput(12345)).toThrow(AuthenticationError);
    });
  });

  describe('Real Argon2id hashing and verification', () => {
    it('hashes and verifies a password successfully with OWASP baseline parameters', async () => {
      const password = 'CorrectHorseBatteryStaple!2026';
      const hash = await hashPassword(password);

      // Check structure of generated PHC string
      expect(hash).toMatch(
        /^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/=_-]+\$[A-Za-z0-9+/=_-]+$/,
      );

      // Verify correct password
      const isCorrect = await verifyPassword(hash, password);
      expect(isCorrect).toBe(true);

      // Reject incorrect password
      const isWrong = await verifyPassword(hash, 'WrongPassword123');
      expect(isWrong).toBe(false);
    });

    it('dummyVerifyPassword executes without throwing for valid inputs', async () => {
      await expect(dummyVerifyPassword('any-password')).resolves.toBeUndefined();
    });

    it('verifyPassword safely handles malformed verifier strings without throwing internal crypto errors', async () => {
      expect(await verifyPassword('not-a-hash', 'password')).toBe(false);
      expect(await verifyPassword('$bcrypt$invalid', 'password')).toBe(false);
      expect(await verifyPassword('', 'password')).toBe(false);
    });
  });

  describe('Argon2 Concurrency Limiter (bounded semaphore)', () => {
    it('executes tasks within maximum concurrency limit', async () => {
      const limiter = new Argon2ConcurrencyLimiter({ maxConcurrency: 2, queueCapacity: 5 });
      let currentActive = 0;
      let maxActiveObserved = 0;

      const task = async () => {
        return limiter.run(async () => {
          currentActive++;
          maxActiveObserved = Math.max(maxActiveObserved, currentActive);
          await new Promise((r) => setTimeout(r, 20));
          currentActive--;
        });
      };

      await Promise.all([task(), task(), task(), task()]);
      expect(maxActiveObserved).toBeLessThanOrEqual(2);
      expect(limiter.active).toBe(0);
      expect(limiter.queued).toBe(0);
    });

    it('rejects tasks with SERVICE_UNAVAILABLE when queue capacity is exceeded', async () => {
      const limiter = new Argon2ConcurrencyLimiter({ maxConcurrency: 1, queueCapacity: 2 });
      let blocked = true;

      // Occupy the single permit
      const slowTask = limiter.run(async () => {
        while (blocked) {
          await new Promise((r) => setTimeout(r, 10));
        }
      });

      // Queue 2 tasks (reaches queue capacity of 2)
      const q1 = limiter.run(async () => {});
      const q2 = limiter.run(async () => {});

      // 4th task should exceed queue capacity and be rejected immediately
      await expect(limiter.run(async () => {})).rejects.toThrow(AuthenticationError);

      try {
        await limiter.run(async () => {});
      } catch (err) {
        expect(err).toBeInstanceOf(AuthenticationError);
        expect((err as AuthenticationError).reason).toBe('SERVICE_UNAVAILABLE');
      }

      // Cleanup
      blocked = false;
      await Promise.all([slowTask, q1, q2]);
      expect(limiter.active).toBe(0);
      expect(limiter.queued).toBe(0);
    });

    it('releases permit on task error so subsequent requests succeed', async () => {
      const limiter = new Argon2ConcurrencyLimiter({ maxConcurrency: 1, queueCapacity: 2 });

      // Run a failing task
      await expect(
        limiter.run(async () => {
          throw new Error('Hashing computation failed');
        }),
      ).rejects.toThrow('Hashing computation failed');

      expect(limiter.active).toBe(0);

      // Next task should succeed without being blocked
      const result = await limiter.run(async () => 'success');
      expect(result).toBe('success');
      expect(limiter.active).toBe(0);
    });

    it('times out waiting requests when timeoutMs expires', async () => {
      const limiter = new Argon2ConcurrencyLimiter({
        maxConcurrency: 1,
        queueCapacity: 5,
        timeoutMs: 30,
      });

      let blocked = true;
      const slowTask = limiter.run(async () => {
        while (blocked) {
          await new Promise((r) => setTimeout(r, 10));
        }
      });

      // Waiting task should time out after 30ms
      await expect(limiter.run(async () => {})).rejects.toThrow('timed out');

      blocked = false;
      await slowTask;
    });
  });
});
