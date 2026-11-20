import { Algorithm, hash as argon2Hash, verify as argon2Verify, Version } from '@node-rs/argon2';
import { AuthenticationError } from './types.js';

/**
 * Maximum allowed password length in UTF-8 bytes (Architecture §13.4, Directive §4).
 */
export const MAX_PASSWORD_BYTE_LENGTH = 128;

/**
 * Argon2id parameters conforming to OWASP recommendations and Architecture v1.2 §13.4.
 */
export const ARGON2ID_CONFIG = {
  memoryCost: 19456, // 19 MiB in KiB
  timeCost: 2, // 2 iterations
  parallelism: 1, // 1 thread
  outputLen: 32, // 256-bit derived key
  algorithm: Algorithm.Argon2id,
  version: Version.V0x13,
} as const;

/**
 * Pre-computed, complete, known-good Argon2id PHC verifier generated with ARGON2ID_CONFIG.
 * Used for dummy verification on unknown accounts to mitigate timing-based account enumeration.
 */
export const DUMMY_ARGON2ID_VERIFIER =
  '$argon2id$v=19$m=19456,t=2,p=1$CQVP+ubBYTGFzi8wzBtdJA$UkiBvSeyQp8YC/a7ScZcdijvhAgWDvO6xGBrgn27/Gk';

/**
 * Validates that a supplied password is a valid string within the 128-byte UTF-8 cap.
 * Throws AuthenticationError with 'INVALID_INPUT' on violation.
 */
export function validatePasswordInput(password: unknown): string {
  if (typeof password !== 'string') {
    throw new AuthenticationError('INVALID_INPUT', 'Password must be a string');
  }

  if (password.length === 0) {
    throw new AuthenticationError('INVALID_INPUT', 'Password must not be empty');
  }

  const byteLength = Buffer.byteLength(password, 'utf8');
  if (byteLength > MAX_PASSWORD_BYTE_LENGTH) {
    throw new AuthenticationError(
      'INVALID_INPUT',
      `Password exceeds maximum allowed length of ${MAX_PASSWORD_BYTE_LENGTH} bytes (received ${byteLength} bytes)`,
    );
  }

  return password;
}

/**
 * Interface and configuration for bounded Argon2 concurrency management.
 */
export interface Argon2LimiterOptions {
  maxConcurrency?: number;
  queueCapacity?: number;
  timeoutMs?: number;
}

/**
 * Shared asynchronous concurrency limiter for CPU/memory-intensive Argon2id operations.
 * Enforces bounded parallelism and a bounded waiting queue, failing closed on overload.
 */
export class Argon2ConcurrencyLimiter {
  private activeCount = 0;
  private readonly maxConcurrency: number;
  private readonly queueCapacity: number;
  private readonly timeoutMs: number;
  private readonly waitQueue: Array<{
    resolve: () => void;
    reject: (err: Error) => void;
    timer: NodeJS.Timeout;
  }> = [];

  constructor(options?: Argon2LimiterOptions) {
    this.maxConcurrency = options?.maxConcurrency ?? 4;
    this.queueCapacity = options?.queueCapacity ?? 16;
    this.timeoutMs = options?.timeoutMs ?? 5000;
  }

  public get active(): number {
    return this.activeCount;
  }

  public get queued(): number {
    return this.waitQueue.length;
  }

  /**
   * Acquires a concurrency permit, waiting if active count is at maximum.
   * Fails closed if the queue is full or wait exceeds timeoutMs.
   */
  public async acquire(): Promise<void> {
    if (this.activeCount < this.maxConcurrency) {
      this.activeCount++;
      return;
    }

    if (this.waitQueue.length >= this.queueCapacity) {
      throw new AuthenticationError(
        'SERVICE_UNAVAILABLE',
        'Authentication service is overloaded: maximum hashing queue capacity exceeded',
      );
    }

    return new Promise<void>((resolve, reject) => {
      const entry: {
        resolve: () => void;
        reject: (err: Error) => void;
        timer: NodeJS.Timeout;
      } = {
        resolve: () => {},
        reject: () => {},
        timer: setTimeout(() => {
          const idx = this.waitQueue.indexOf(entry);
          if (idx !== -1) {
            this.waitQueue.splice(idx, 1);
            reject(
              new AuthenticationError(
                'SERVICE_UNAVAILABLE',
                'Authentication request timed out waiting for password processing capacity',
              ),
            );
          }
        }, this.timeoutMs),
      };

      entry.resolve = () => {
        clearTimeout(entry.timer);
        resolve();
      };
      entry.reject = (err: Error) => {
        clearTimeout(entry.timer);
        reject(err);
      };

      this.waitQueue.push(entry);
    });
  }

  /**
   * Releases a concurrency permit and dispatches the next queued item, if any.
   */
  public release(): void {
    if (this.waitQueue.length > 0) {
      const next = this.waitQueue.shift();
      if (next) {
        next.resolve();
        return;
      }
    }
    this.activeCount = Math.max(0, this.activeCount - 1);
  }

  /**
   * Runs an operation with bounded concurrency, guaranteeing permit release on success or failure.
   */
  public async run<T>(operation: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await operation();
    } finally {
      this.release();
    }
  }
}

/**
 * Global shared limiter instance for password operations.
 */
export const defaultArgon2Limiter = new Argon2ConcurrencyLimiter();

/**
 * Hashes a plaintext password using Argon2id with OWASP baseline parameters,
 * managed by the provided or default concurrency limiter.
 */
export async function hashPassword(
  password: unknown,
  limiter: Argon2ConcurrencyLimiter = defaultArgon2Limiter,
): Promise<string> {
  const validPassword = validatePasswordInput(password);

  return limiter.run(async () => {
    return argon2Hash(validPassword, ARGON2ID_CONFIG);
  });
}

/**
 * Verifies a plaintext password against a stored Argon2id PHC verifier,
 * managed by the provided or default concurrency limiter.
 * Fails safely and returns false on unusable or malformed hashes.
 */
export async function verifyPassword(
  storedVerifier: string,
  suppliedPassword: unknown,
  limiter: Argon2ConcurrencyLimiter = defaultArgon2Limiter,
): Promise<boolean> {
  // Pre-validate password input; if invalid, reject fail-closed without expensive verification
  if (typeof suppliedPassword !== 'string' || suppliedPassword.length === 0) {
    return false;
  }
  if (Buffer.byteLength(suppliedPassword, 'utf8') > MAX_PASSWORD_BYTE_LENGTH) {
    return false;
  }

  // Pre-validate stored verifier format
  if (typeof storedVerifier !== 'string' || !storedVerifier.startsWith('$argon2id$')) {
    return false;
  }

  return limiter.run(async () => {
    try {
      return await argon2Verify(storedVerifier, suppliedPassword);
    } catch {
      // Never leak internal crypto errors to external callers
      return false;
    }
  });
}

/**
 * Executes a dummy Argon2id verification for an unknown user account
 * to equalize response timing between existing and nonexistent accounts.
 */
export async function dummyVerifyPassword(
  suppliedPassword: unknown,
  limiter: Argon2ConcurrencyLimiter = defaultArgon2Limiter,
): Promise<void> {
  await verifyPassword(DUMMY_ARGON2ID_VERIFIER, suppliedPassword, limiter);
}
