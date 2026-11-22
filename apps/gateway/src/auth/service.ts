import type pg from 'pg';
import { bootstrapOrganizationWithAdmin as bootstrapOrganization } from './bootstrap.js';
import { normalizeEmail } from './email.js';
import {
  type Argon2ConcurrencyLimiter,
  defaultArgon2Limiter,
  dummyVerifyPassword,
  validatePasswordInput,
  verifyPassword,
} from './password.js';
import type { LoginRateLimiter } from './rate-limiter.js';
import {
  type AuthenticatedUser,
  AuthenticationError,
  type InternalBootstrapParams,
  type InternalBootstrapResult,
} from './types.js';

export interface AuthenticationServiceOptions {
  pool: pg.Pool;
  rateLimiter: LoginRateLimiter;
  argon2Limiter?: Argon2ConcurrencyLimiter;
}

export class AuthenticationService {
  private readonly pool: pg.Pool;
  private readonly rateLimiter: LoginRateLimiter;
  private readonly argon2Limiter: Argon2ConcurrencyLimiter;

  constructor(options: AuthenticationServiceOptions) {
    if (!options || !options.rateLimiter) {
      throw new AuthenticationError(
        'CONFIGURATION_ERROR',
        'LoginRateLimiter is a mandatory dependency for AuthenticationService',
      );
    }
    this.pool = options.pool;
    this.rateLimiter = options.rateLimiter;
    this.argon2Limiter = options.argon2Limiter ?? defaultArgon2Limiter;
  }

  /**
   * Authenticates a user given email, password, and client IP.
   *
   * Security sequence:
   * 1. Validate email and password representations fail-closed before any database or crypto operations.
   * 2. Apply mandatory Redis-backed abuse/rate-limit checks before costly database lookups or Argon2id hashing.
   * 3. Look up user via restricted privileged function app_private.lookup_user_for_login(p_email_normalized).
   * 4. For known accounts, verify supplied password against stored Argon2id verifier.
   * 5. For unknown accounts, execute a dummy Argon2id verification with OWASP baseline parameters to mitigate timing differences.
   * 6. Return trusted principal representation on success; fail closed with generic error on failure.
   * 7. Never log passwords, password hashes, or return sensitive verifiers.
   */
  public async authenticate(
    rawEmail: unknown,
    rawPassword: unknown,
    clientIp: string,
  ): Promise<AuthenticatedUser> {
    // 1. Pre-validate email and password input
    const normalizedEmail = normalizeEmail(rawEmail);
    const validPassword = validatePasswordInput(rawPassword);

    // 2. Abuse / Rate limiting (mandatory)
    await this.rateLimiter.assertNotRateLimited(clientIp, normalizedEmail);

    // 3. Pre-tenant login lookup via privileged function
    let lookupResult: {
      id: string;
      org_id: string;
      role: 'admin' | 'member';
      password_hash: string;
    } | null = null;

    try {
      const { rows } = await this.pool.query<{
        id: string;
        org_id: string;
        role: 'admin' | 'member';
        password_hash: string;
      }>('SELECT id, org_id, role, password_hash FROM app_private.lookup_user_for_login($1)', [
        normalizedEmail,
      ]);

      if (rows.length > 0 && rows[0]) {
        lookupResult = rows[0];
      }
    } catch (err) {
      throw new AuthenticationError(
        'SERVICE_UNAVAILABLE',
        'Authentication database lookup failed',
        { cause: err },
      );
    }

    // 4. Unknown account path: execute dummy Argon2id verification
    if (!lookupResult) {
      await dummyVerifyPassword(validPassword, this.argon2Limiter);
      throw new AuthenticationError('INVALID_CREDENTIALS', 'Invalid email or password');
    }

    // 5. Known account path: verify password against stored verifier
    const isValid = await verifyPassword(
      lookupResult.password_hash,
      validPassword,
      this.argon2Limiter,
    );

    if (!isValid) {
      throw new AuthenticationError('INVALID_CREDENTIALS', 'Invalid email or password');
    }

    // 6. Return trusted principal representation (never returning password_hash)
    return {
      id: lookupResult.id,
      orgId: lookupResult.org_id,
      role: lookupResult.role,
      emailNormalized: normalizedEmail,
    };
  }

  /**
   * Internal organization and initial administrator bootstrap service.
   * Invokes the privileged function app_private.create_organization_with_admin(...).
   *
   * Strictly internal: public self-registration is disabled until SW-1.7 envelope encryption
   * and self-enrollment policies are approved and integrated.
   */
  public async bootstrapOrganizationWithAdmin(
    params: InternalBootstrapParams,
  ): Promise<InternalBootstrapResult> {
    return bootstrapOrganization(this.pool, params, this.argon2Limiter);
  }
}
