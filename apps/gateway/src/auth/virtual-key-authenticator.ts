import crypto from 'node:crypto';
import type pg from 'pg';
import { parseRawKey } from './virtual-key.js';
import {
  type IVirtualKeyRateLimiter,
  VirtualKeyAuthError,
  type VirtualKeyAuthErrorReason,
} from './virtual-key-rate-limiter.js';
import type {
  VirtualKeyAuthenticator,
  VirtualKeyPolicy,
  VirtualKeyPrincipal,
  VirtualKeyVerificationResult,
} from './authorization.js';

export { VirtualKeyAuthError, type VirtualKeyAuthErrorReason, type IVirtualKeyRateLimiter };
export {
  type VirtualKeyPolicy,
  type VirtualKeyPrincipal,
  type VirtualKeyVerificationResult,
  type VirtualKeyAuthenticator,
} from './authorization.js';

/**
 * Service options for VirtualKeyAuthenticatorService.
 */
export interface VirtualKeyAuthenticatorOptions {
  pool: pg.Pool;
  rateLimiter: IVirtualKeyRateLimiter;
}

/**
 * Row shape returned by app_private.lookup_virtual_key_by_hash(p_key_hash BYTEA).
 */
interface DbVirtualKeyRow {
  id: string;
  org_id: string;
  revoked_at: Date | string | null;
  allowed_models: string[];
  rpm_limit: number;
  tpm_limit: number;
  concurrent_stream_limit: number;
  exact_cache_enabled: boolean;
  semantic_cache_enabled: boolean;
  pii_redaction_enabled: boolean;
  store_payloads: boolean;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isValidUuid(id: unknown): id is string {
  return typeof id === 'string' && UUID_REGEX.test(id.trim());
}

/**
 * Parameterized query to resolve virtual key identity and policy using the
 * restricted SECURITY DEFINER function app_private.lookup_virtual_key_by_hash.
 */
const LOOKUP_VIRTUAL_KEY_SQL = `
SELECT
  id,
  org_id,
  revoked_at,
  allowed_models,
  rpm_limit,
  tpm_limit,
  concurrent_stream_limit,
  exact_cache_enabled,
  semantic_cache_enabled,
  pii_redaction_enabled,
  store_payloads
FROM app_private.lookup_virtual_key_by_hash($1::bytea)
`;

/**
 * Application-level Virtual API Key Authenticator Service (SW-1.6.2).
 *
 * Security and Architecture Sequence:
 * 1. Enforces per-IP abuse rate limits before PostgreSQL lookup.
 * 2. Validates canonical format ('gw_live_<11>_<43>') via parseRawKey().
 * 3. Decodes 32-byte secret and computes SHA-256 verifier (zeroing buffers on a best-effort basis).
 * 4. Resolves identity and policy via app_private.lookup_virtual_key_by_hash($1::bytea).
 * 5. Rejects unknown, malformed, and revoked credentials (returning uniform failure reasons).
 * 6. Validates returned database policy fields fail-closed against corruption or nulls.
 * 7. Constructs an immutable VirtualKeyPrincipal with typed VirtualKeyPolicy.
 * 8. Never logs, caches, or exposes raw keys, secrets, or binary verifiers.
 *
 * ARCHITECTURAL LIMITATION & PHASE 2 ADMISSION NOTICE:
 * This initial lookup determines pre-tenant identity and initial policy only.
 * It does NOT replace the Phase 2 requirement to row-lock and re-check the virtual-key
 * record inside durable provider-attempt admission. A key revoked after this initial
 * authentication lookup must be caught and denied by the subsequent transactional admission lock.
 */
export class VirtualKeyAuthenticatorService implements VirtualKeyAuthenticator {
  private readonly pool: pg.Pool;
  private readonly rateLimiter: IVirtualKeyRateLimiter;

  constructor(options: VirtualKeyAuthenticatorOptions) {
    if (!options || typeof options !== 'object') {
      throw new VirtualKeyAuthError(
        'CONFIGURATION_ERROR',
        'VirtualKeyAuthenticator options must be provided',
      );
    }
    if (!options.pool) {
      throw new VirtualKeyAuthError(
        'CONFIGURATION_ERROR',
        'PostgreSQL pool is a mandatory dependency for VirtualKeyAuthenticatorService',
      );
    }
    if (!options.rateLimiter) {
      throw new VirtualKeyAuthError(
        'CONFIGURATION_ERROR',
        'VirtualKeyRateLimiter is a mandatory dependency for VirtualKeyAuthenticatorService',
      );
    }
    this.pool = options.pool;
    this.rateLimiter = options.rateLimiter;
  }

  /**
   * Authenticates a virtual API key and resolves its principal and policy.
   *
   * @param rawKey The raw virtual API key presented in the HTTP Authorization header.
   * @param clientIp The trusted client IP address derived from transport configuration.
   * @returns VirtualKeyVerificationResult indicating validity and attached principal.
   */
  public async authenticateKey(
    rawKey: string,
    clientIp?: string,
  ): Promise<VirtualKeyVerificationResult> {
    // 1. Mandatory client IP validation fail-closed
    if (!clientIp || typeof clientIp !== 'string' || clientIp.trim() === '') {
      throw new VirtualKeyAuthError(
        'INVALID_INPUT',
        'Client IP is required for virtual key authentication',
      );
    }

    // 2. Enforce per-IP abuse rate limit BEFORE database lookup (protects PostgreSQL)
    await this.rateLimiter.assertNotRateLimited(clientIp);

    // 3. Validate key envelope and canonical base64url encoding
    if (typeof rawKey !== 'string') {
      return { valid: false, reason: 'MALFORMED_KEY' };
    }

    const parsed = parseRawKey(rawKey);
    if (!parsed) {
      return { valid: false, reason: 'MALFORMED_KEY' };
    }

    // 4. Decode 32-byte secret and compute SHA-256 verifier
    let secretBytes: Buffer | undefined;
    let keyHash: Buffer | undefined;

    try {
      secretBytes = Buffer.from(parsed.secret, 'base64url');
      if (secretBytes.length !== 32) {
        return { valid: false, reason: 'MALFORMED_KEY' };
      }
      keyHash = crypto.createHash('sha256').update(secretBytes).digest();
    } finally {
      if (secretBytes) {
        secretBytes.fill(0);
      }
    }

    // 5. Query restricted PostgreSQL lookup function using parameterized query
    let rows: DbVirtualKeyRow[];
    try {
      const res = await this.pool.query<DbVirtualKeyRow>(LOOKUP_VIRTUAL_KEY_SQL, [keyHash]);
      rows = res.rows;
    } catch (err) {
      throw new VirtualKeyAuthError(
        'SERVICE_UNAVAILABLE',
        'Authentication database lookup failed',
        { cause: err },
      );
    } finally {
      if (keyHash) {
        keyHash.fill(0);
      }
    }

    // 6. Require exactly one matching record
    if (rows.length === 0) {
      return { valid: false, reason: 'KEY_NOT_FOUND' };
    }

    if (rows.length > 1) {
      throw new VirtualKeyAuthError(
        'INTEGRITY_ERROR',
        'Multiple virtual key records matched hash verifier',
      );
    }

    const row = rows[0]!;

    // 7. Validate revocation metadata fail-closed and reject revoked keys (VK-AUTH-01)
    if (
      !('revoked_at' in (row as unknown as Record<string, unknown>)) ||
      row.revoked_at === undefined
    ) {
      throw new VirtualKeyAuthError(
        'INTEGRITY_ERROR',
        'Virtual key revoked_at is missing or undefined',
      );
    }

    if (row.revoked_at !== null) {
      const revokedAt = row.revoked_at;
      let isValidTimestamp = false;

      if (revokedAt instanceof Date) {
        isValidTimestamp = !Number.isNaN(revokedAt.getTime());
      } else if (typeof revokedAt === 'string') {
        if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/.test(revokedAt)) {
          const parsed = Date.parse(revokedAt);
          isValidTimestamp = !Number.isNaN(parsed);
        }
      }

      if (!isValidTimestamp) {
        throw new VirtualKeyAuthError(
          'INTEGRITY_ERROR',
          'Virtual key revoked_at contains an invalid timestamp representation',
        );
      }

      return { valid: false, reason: 'KEY_REVOKED' };
    }

    // 8. Validate returned database identity and policy fields fail-closed
    if (!isValidUuid(row.id)) {
      throw new VirtualKeyAuthError('INTEGRITY_ERROR', 'Virtual key ID is missing or malformed');
    }
    if (!isValidUuid(row.org_id)) {
      throw new VirtualKeyAuthError(
        'INTEGRITY_ERROR',
        'Virtual key organization ID is missing or malformed',
      );
    }
    if (
      !Array.isArray(row.allowed_models) ||
      row.allowed_models.some((m) => typeof m !== 'string')
    ) {
      throw new VirtualKeyAuthError(
        'INTEGRITY_ERROR',
        'Virtual key allowed_models is missing or malformed',
      );
    }
    if (
      typeof row.rpm_limit !== 'number' ||
      !Number.isInteger(row.rpm_limit) ||
      row.rpm_limit <= 0
    ) {
      throw new VirtualKeyAuthError(
        'INTEGRITY_ERROR',
        'Virtual key rpm_limit is missing or malformed',
      );
    }
    if (
      typeof row.tpm_limit !== 'number' ||
      !Number.isInteger(row.tpm_limit) ||
      row.tpm_limit <= 0
    ) {
      throw new VirtualKeyAuthError(
        'INTEGRITY_ERROR',
        'Virtual key tpm_limit is missing or malformed',
      );
    }
    if (
      typeof row.concurrent_stream_limit !== 'number' ||
      !Number.isInteger(row.concurrent_stream_limit) ||
      row.concurrent_stream_limit <= 0
    ) {
      throw new VirtualKeyAuthError(
        'INTEGRITY_ERROR',
        'Virtual key concurrent_stream_limit is missing or malformed',
      );
    }
    if (typeof row.exact_cache_enabled !== 'boolean') {
      throw new VirtualKeyAuthError(
        'INTEGRITY_ERROR',
        'Virtual key exact_cache_enabled is missing or malformed',
      );
    }
    if (typeof row.semantic_cache_enabled !== 'boolean') {
      throw new VirtualKeyAuthError(
        'INTEGRITY_ERROR',
        'Virtual key semantic_cache_enabled is missing or malformed',
      );
    }
    if (typeof row.pii_redaction_enabled !== 'boolean') {
      throw new VirtualKeyAuthError(
        'INTEGRITY_ERROR',
        'Virtual key pii_redaction_enabled is missing or malformed',
      );
    }
    if (typeof row.store_payloads !== 'boolean') {
      throw new VirtualKeyAuthError(
        'INTEGRITY_ERROR',
        'Virtual key store_payloads is missing or malformed',
      );
    }

    // 9. Construct typed, immutable principal and policy
    const keyPolicy: VirtualKeyPolicy = Object.freeze({
      allowedModels: Object.freeze([...row.allowed_models]),
      rpmLimit: row.rpm_limit,
      tpmLimit: row.tpm_limit,
      concurrentStreamLimit: row.concurrent_stream_limit,
      exactCacheEnabled: row.exact_cache_enabled,
      semanticCacheEnabled: row.semantic_cache_enabled,
      piiRedactionEnabled: row.pii_redaction_enabled,
      storePayloads: row.store_payloads,
    });

    const principal: VirtualKeyPrincipal = Object.freeze({
      type: 'virtual_key',
      keyId: row.id,
      orgId: row.org_id,
      keyPolicy,
    });

    return {
      valid: true,
      principal,
    };
  }
}
