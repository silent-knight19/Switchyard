import type { Redis } from 'ioredis';
import { sanitizeClientIp } from './rate-limiter.js';

export type VirtualKeyAuthErrorReason =
  | 'RATE_LIMITED'
  | 'SERVICE_UNAVAILABLE'
  | 'INVALID_INPUT'
  | 'CONFIGURATION_ERROR'
  | 'INTEGRITY_ERROR';

/**
 * Domain error for virtual API key authentication and abuse limiting (SW-1.6.2).
 * Fails closed without interpolating secrets, keys, hashes, SQL parameters, or connection details.
 */
export class VirtualKeyAuthError extends Error {
  public readonly reason: VirtualKeyAuthErrorReason;

  constructor(reason: VirtualKeyAuthErrorReason, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'VirtualKeyAuthError';
    this.reason = reason;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export interface VirtualKeyRateLimiterPolicy {
  readonly ipLimit: number; // e.g. 30 attempts
  readonly ipWindowSeconds: number; // e.g. 900 seconds (15 minutes)
}

/**
 * Default virtual key abuse rate limit policy.
 * Fixed-window threshold of 30 attempts per 15-minute window per IP.
 */
export const DEFAULT_VIRTUAL_KEY_RATE_LIMIT_POLICY: VirtualKeyRateLimiterPolicy = {
  ipLimit: 30,
  ipWindowSeconds: 900,
};

/**
 * Interface contract for virtual key rate limiting.
 */
export interface IVirtualKeyRateLimiter {
  assertNotRateLimited(clientIp: string): Promise<void>;
  reset?(clientIp: string): Promise<void>;
}

/**
 * Lua script for atomic fixed-window counter with TTL.
 * KEYS[1]: rate limit key
 * ARGV[1]: windowSeconds, ARGV[2]: maxLimit
 * Returns: 1 if allowed, 0 if limit exceeded
 */
const VIRTUAL_KEY_RATE_LIMIT_LUA = `
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

/**
 * Redis-backed per-IP abuse rate limiter for virtual API key authentication (SW-1.6.2).
 * Protects PostgreSQL authentication functions from brute-force random key lookups.
 * Enforces atomic fixed-window counter under key namespace 'auth:ratelimit:vk:ip:<ip>'.
 * Fails closed on Redis unavailability.
 */
export class VirtualKeyRateLimiter implements IVirtualKeyRateLimiter {
  private readonly redis: Redis;
  private readonly policy: VirtualKeyRateLimiterPolicy;

  constructor(
    redis: Redis,
    policy: VirtualKeyRateLimiterPolicy = DEFAULT_VIRTUAL_KEY_RATE_LIMIT_POLICY,
  ) {
    if (!redis) {
      throw new VirtualKeyAuthError(
        'CONFIGURATION_ERROR',
        'Redis instance is required for VirtualKeyRateLimiter',
      );
    }
    this.redis = redis;
    this.policy = policy;
  }

  /**
   * Asserts that client IP has not exceeded the abuse rate limit.
   * Atomic Redis evaluation using fixed-window counter.
   * Fails closed with SERVICE_UNAVAILABLE if Redis encounters an error.
   * Throws VirtualKeyAuthError with 'RATE_LIMITED' if limit is exceeded.
   */
  public async assertNotRateLimited(clientIp: string): Promise<void> {
    let ip: string;
    try {
      ip = sanitizeClientIp(clientIp);
    } catch (err) {
      throw new VirtualKeyAuthError(
        'INVALID_INPUT',
        err instanceof Error ? err.message : 'Invalid client IP address',
        { cause: err },
      );
    }

    const key = `auth:ratelimit:vk:ip:${ip}`;

    try {
      const result = (await this.redis.eval(
        VIRTUAL_KEY_RATE_LIMIT_LUA,
        1,
        key,
        this.policy.ipWindowSeconds,
        this.policy.ipLimit,
      )) as number;

      if (result === 0) {
        throw new VirtualKeyAuthError(
          'RATE_LIMITED',
          'Too many authentication attempts from this IP address. Please try again later.',
        );
      }
    } catch (err) {
      if (err instanceof VirtualKeyAuthError) {
        throw err;
      }
      throw new VirtualKeyAuthError(
        'SERVICE_UNAVAILABLE',
        'Authentication rate limiter backend is unavailable',
        { cause: err },
      );
    }
  }

  /**
   * Resets the rate limit counter for a given client IP (useful for test isolation).
   */
  public async reset(clientIp: string): Promise<void> {
    let ip: string;
    try {
      ip = sanitizeClientIp(clientIp);
    } catch (err) {
      throw new VirtualKeyAuthError(
        'INVALID_INPUT',
        err instanceof Error ? err.message : 'Invalid client IP address',
        { cause: err },
      );
    }
    await this.redis.del(`auth:ratelimit:vk:ip:${ip}`);
  }
}
