import crypto from 'node:crypto';
import type pg from 'pg';
import { assertCanonicalEmail } from './email.js';
import {
  type Argon2ConcurrencyLimiter,
  defaultArgon2Limiter,
  hashPassword,
  validatePasswordInput,
} from './password.js';
import {
  BootstrapError,
  type InternalBootstrapParams,
  type InternalBootstrapResult,
} from './types.js';

/**
 * Internal organization and initial administrator bootstrap operation.
 *
 * This is the single authoritative application implementation of the privileged
 * `app_private.create_organization_with_admin(...)` contract. `AuthenticationService` delegates to
 * it, and the development-only demo seeder reuses it directly so the CLI does not need a Redis
 * login rate limiter or an HTTP server merely to construct the authentication service.
 *
 * Security invariants:
 * - Runs on the caller's restricted `gateway_app` pool. No executor or owner credentials.
 * - Validates organization name, budget, KEK version, DEK bytes, canonical email and password
 *   before issuing the privileged function call.
 * - Hashes the password with the existing Argon2id configuration and concurrency limiter.
 * - Relies on the database function for atomic organization + admin creation.
 */
export async function bootstrapOrganizationWithAdmin(
  pool: pg.Pool,
  params: InternalBootstrapParams,
  argon2Limiter: Argon2ConcurrencyLimiter = defaultArgon2Limiter,
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
  const passwordHash = await hashPassword(validPassword, argon2Limiter);

  try {
    const { rows } = await pool.query<{
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
      throw new BootstrapError('DUPLICATE_RESOURCE', 'Organization or admin user already exists', {
        cause: err,
      });
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
