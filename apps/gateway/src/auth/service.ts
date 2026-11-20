import crypto from 'node:crypto';
import type pg from 'pg';
import { assertCanonicalEmail, normalizeEmail } from './email.js';
import {
  type Argon2ConcurrencyLimiter,
  defaultArgon2Limiter,
  dummyVerifyPassword,
  hashPassword,
  validatePasswordInput,
  verifyPassword,
} from './password.js';
import type { LoginRateLimiter } from './rate-limiter.js';
import {
  type AuthenticatedUser,
  AuthenticationError,
  BootstrapError,
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
    const orgId = params.orgId ?? crypto.randomUUID();
    const adminUserId = params.adminUserId ?? crypto.randomUUID();

    if (!params.orgName || params.orgName.trim().length === 0 || params.orgName.length > 255) {
      throw new BootstrapError('INVALID_ORG_NAME', 'Organization name must be 1 to 255 characters');
    }

    if (
      params.monthlyBudgetMicrodollars === undefined ||
      params.monthlyBudgetMicrodollars < 0n ||
      params.monthlyBudgetMicrodollars > 1000000000000000n
    ) {
      throw new BootstrapError(
        'INVALID_BUDGET',
        'Monthly budget microdollars must be between 0 and 1,000,000,000,000,000',
      );
    }

    if (!params.kekVersion || params.kekVersion <= 0) {
      throw new BootstrapError('INVALID_KEK_VERSION', 'KEK version must be a positive integer');
    }

    if (
      !Buffer.isBuffer(params.wrappedDek) ||
      params.wrappedDek.length === 0 ||
      !Buffer.isBuffer(params.dekIv) ||
      params.dekIv.length === 0 ||
      !Buffer.isBuffer(params.dekAuthTag) ||
      params.dekAuthTag.length === 0
    ) {
      throw new BootstrapError(
        'INVALID_DEK_MATERIAL',
        'Wrapped DEK, IV, and auth tag must be non-empty Buffers',
      );
    }

    // Assert canonical email (bootstrap requires already-canonical input)
    const canonicalEmail = assertCanonicalEmail(params.adminEmail);

    // Validate password length and hash with Argon2id
    const validPassword = validatePasswordInput(params.adminPassword);
    const passwordHash = await hashPassword(validPassword, this.argon2Limiter);

    try {
      const { rows } = await this.pool.query<{
        org_id: string;
        admin_user_id: string;
      }>(
        `SELECT org_id, admin_user_id FROM app_private.create_organization_with_admin(
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
        )`,
        [
          orgId,
          params.orgName.trim(),
          params.monthlyBudgetMicrodollars.toString(),
          params.kekVersion,
          params.wrappedDek,
          params.dekIv,
          params.dekAuthTag,
          adminUserId,
          canonicalEmail,
          passwordHash,
        ],
      );

      const result = rows[0];
      if (!result) {
        throw new BootstrapError(
          'BOOTSTRAP_FAILED',
          'Failed to create organization and admin user: empty result from database function',
        );
      }

      return {
        orgId: result.org_id,
        adminUserId: result.admin_user_id,
      };
    } catch (err: unknown) {
      if (err instanceof BootstrapError) {
        throw err;
      }
      const pgCode =
        err && typeof err === 'object' && 'code' in err && typeof err.code === 'string'
          ? err.code
          : 'UNKNOWN';

      if (pgCode === '23505') {
        throw new BootstrapError(
          'DUPLICATE_RESOURCE',
          'Organization or admin user already exists',
          { cause: err },
        );
      }
      if (pgCode === '22023' || pgCode === '22004') {
        throw new BootstrapError('INVALID_INPUT', 'Database rejected bootstrap input parameters', {
          cause: err,
        });
      }

      throw new BootstrapError(
        'BOOTSTRAP_DATABASE_ERROR',
        `Database bootstrap operation failed with error code ${pgCode}`,
        { cause: err },
      );
    }
  }
}
