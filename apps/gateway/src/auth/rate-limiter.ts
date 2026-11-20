import crypto from 'node:crypto';
import type { Redis } from 'ioredis';
import { AuthenticationError } from './types.js';

export interface RateLimiterPolicy {
  readonly ipLimit: number; // e.g. 30 attempts
  readonly ipWindowSeconds: number; // e.g. 900 seconds (15 mins)
  readonly accountLimit: number; // e.g. 5 attempts
  readonly accountWindowSeconds: number; // e.g. 900 seconds (15 mins)
}

export const DEFAULT_LOGIN_RATE_LIMIT_POLICY: RateLimiterPolicy = {
  ipLimit: 30,
  ipWindowSeconds: 900,
  accountLimit: 5,
  accountWindowSeconds: 900,
};

/**
 * Validates and sanitizes a client IP string.
 * Strips port suffix if present and ensures non-empty string.
 */
export function sanitizeClientIp(rawIp: unknown): string {
  if (typeof rawIp !== 'string' || rawIp.trim().length === 0) {
    return '127.0.0.1';
  }

  const trimmed = rawIp.trim();
  // Strip IPv4 port if present (e.g. "192.168.1.1:12345")
  const ipv4WithPort = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$/;
  const match = ipv4WithPort.exec(trimmed);
  if (match && match[1]) {
    return match[1];
  }

  return trimmed;
}

/**
 * Produces an irreversible, bounded key token for an account identifier using SHA-256.
 * Guarantees that raw emails never persist in Redis keys or error messages.
 */
export function hashAccountIdentifier(canonicalEmail: string): string {
  return crypto.createHash('sha256').update(canonicalEmail.toLowerCase().trim()).digest('hex');
}

/**
 * Lua script for atomic sliding/fixed window counter with TTL.
 * ARGV[1]: windowSeconds, ARGV[2]: maxLimit
 * Returns: { allowed: 1 | 0, current: count }
 */
const RATE_LIMIT_LUA = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
end
if count > tonumber(ARGV[2]) then
  return 0
else
  return 1
end
`;

export class LoginRateLimiter {
  private readonly redis: Redis;
  private readonly policy: RateLimiterPolicy;

  constructor(redis: Redis, policy: RateLimiterPolicy = DEFAULT_LOGIN_RATE_LIMIT_POLICY) {
    this.redis = redis;
    this.policy = policy;
  }

  /**
   * Asserts that neither the client IP nor the account identifier has exceeded rate limits.
   * Atomic Redis evaluation. Fails closed with SERVICE_UNAVAILABLE if Redis encounters an error.
   * Throws AuthenticationError with 'RATE_LIMITED' if limit is exceeded.
   */
  public async assertNotRateLimited(clientIp: string, canonicalEmail: string): Promise<void> {
    const ip = sanitizeClientIp(clientIp);
    const accountToken = hashAccountIdentifier(canonicalEmail);

    const ipKey = `auth:ratelimit:ip:${ip}`;
    const accountKey = `auth:ratelimit:account:${accountToken}`;

    try {
      // Check IP rate limit atomically
      const ipResult = (await this.redis.eval(
        RATE_LIMIT_LUA,
        1,
        ipKey,
        this.policy.ipWindowSeconds,
        this.policy.ipLimit,
      )) as number;

      if (ipResult === 0) {
        throw new AuthenticationError(
          'RATE_LIMITED',
          'Too many authentication attempts from this IP address. Please try again later.',
        );
      }

      // Check Account rate limit atomically
      const accountResult = (await this.redis.eval(
        RATE_LIMIT_LUA,
        1,
        accountKey,
        this.policy.accountWindowSeconds,
        this.policy.accountLimit,
      )) as number;

      if (accountResult === 0) {
        throw new AuthenticationError(
          'RATE_LIMITED',
          'Too many authentication attempts for this account. Please try again later.',
        );
      }
    } catch (err) {
      if (err instanceof AuthenticationError) {
        throw err;
      }
      // Fail closed if Redis is down or unavailable
      throw new AuthenticationError(
        'SERVICE_UNAVAILABLE',
        'Authentication rate limiter backend is unavailable',
        { cause: err },
      );
    }
  }

  /**
   * Resets the rate limit counters for a given IP and account (useful for tests or post-login cleanup).
   */
  public async reset(clientIp: string, canonicalEmail: string): Promise<void> {
    const ip = sanitizeClientIp(clientIp);
    const accountToken = hashAccountIdentifier(canonicalEmail);
    await this.redis.del(`auth:ratelimit:ip:${ip}`, `auth:ratelimit:account:${accountToken}`);
  }
}
