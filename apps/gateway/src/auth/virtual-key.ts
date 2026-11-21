import crypto from 'node:crypto';
import type pg from 'pg';
import { validateTenantId, withTenant } from '../db/tenant.js';

/**
 * Error reason classifications for VirtualKeyError.
 */
export type VirtualKeyErrorReason =
  'INVALID_INPUT' | 'KEY_COLLISION_EXHAUSTED' | 'DATABASE_CONFLICT' | 'DATABASE_ERROR';

/**
 * Strongly typed domain error for virtual key issuance operations.
 * Enforces non-sensitive, generic error messages without interpolating secrets,
 * keys, hashes, SQL parameters, or connection details.
 */
export class VirtualKeyError extends Error {
  public readonly reason: VirtualKeyErrorReason;

  constructor(reason: VirtualKeyErrorReason, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'VirtualKeyError';
    this.reason = reason;
  }
}

/**
 * Input contract for virtual key creation.
 * Accepts only trusted organization ID and display name.
 */
export interface CreateVirtualKeyInput {
  orgId: string;
  name: string;
}

/**
 * Successful one-time virtual key creation result.
 * Plaintext rawKey is disclosed exactly once upon confirmed database commit.
 * Verifier hashes, credentials, and SQL row internals are strictly excluded.
 */
export interface CreateVirtualKeyResult {
  id: string;
  orgId: string;
  name: string;
  keyPrefix: string;
  createdAt: Date;
  rawKey: string;
}

/**
 * Service options for VirtualKeyService.
 */
export interface VirtualKeyServiceOptions {
  pool: pg.Pool;
}

/**
 * Maximum key-hash collision retry attempts before failing closed.
 */
const MAX_COLLISION_ATTEMPTS = 3;

/**
 * Regex matching NUL (U+0000), C0 control characters (U+0001-U+001F, U+007F DEL),
 * and C1 control characters (U+0080-U+009F).
 */
const CONTROL_CHARS_REGEX = /[\u0000-\u001F\u007F-\u009F]/;

/**
 * Qualifying unique constraint names on the public.virtual_keys table that
 * justify collision regeneration and retry.
 */
const QUALIFYING_COLLISION_CONSTRAINTS = new Set([
  'virtual_keys_key_hash_key',
  'virtual_keys_pkey',
  'virtual_keys_id_org_id_key',
]);

/**
 * Inspects an error or wrapped error cause to extract PostgreSQL SQLSTATE and constraint name.
 */
function extractDbError(err: unknown): { code: string; constraint?: string } | undefined {
  if (!err || typeof err !== 'object') {
    return undefined;
  }
  const e = err as { code?: unknown; constraint?: unknown; cause?: unknown };
  if (typeof e.code === 'string') {
    return typeof e.constraint === 'string'
      ? { code: e.code, constraint: e.constraint }
      : { code: e.code };
  }
  if (e.cause && typeof e.cause === 'object') {
    const c = e.cause as { code?: unknown; constraint?: unknown };
    if (typeof c.code === 'string') {
      return typeof c.constraint === 'string'
        ? { code: c.code, constraint: c.constraint }
        : { code: c.code };
    }
  }
  return undefined;
}

/**
 * Determines whether a database error is a qualifying uniqueness collision on virtual_keys.
 */
function isQualifyingCollision(err: unknown): boolean {
  const dbErr = extractDbError(err);
  if (!dbErr || dbErr.code !== '23505') {
    return false;
  }
  // If constraint name is reported, verify it matches virtual_keys unique constraints
  if (dbErr.constraint && !QUALIFYING_COLLISION_CONSTRAINTS.has(dbErr.constraint)) {
    return false;
  }
  return true;
}

/**
 * Determines whether a database error is a foreign key violation (e.g. non-existent organization).
 */
function isForeignKeyViolation(err: unknown): boolean {
  const dbErr = extractDbError(err);
  return dbErr?.code === '23503';
}

/**
 * Internal helper to generate fresh, independent cryptographic key material.
 */
export function generateKeyMaterial(): {
  id: string;
  publicPrefix: string;
  keyPrefix: string;
  rawKey: string;
  keyHash: Buffer;
} {
  const prefixBytes = crypto.randomBytes(8);
  const secretBytes = crypto.randomBytes(32);
  const id = crypto.randomUUID();

  const publicPrefix = prefixBytes.toString('base64url'); // exactly 11 chars
  const keyPrefix = `gw_live_${publicPrefix}`;
  const secret = secretBytes.toString('base64url'); // exactly 43 chars
  const rawKey = `gw_live_${publicPrefix}_${secret}`; // exactly 63 ASCII chars

  // SHA-256 verifier computed directly from the 32 raw secret bytes
  const keyHash = crypto.createHash('sha256').update(secretBytes).digest();

  // Best-effort memory hygiene: zero out mutable secret byte buffers
  prefixBytes.fill(0);
  secretBytes.fill(0);

  return {
    id,
    publicPrefix,
    keyPrefix,
    rawKey,
    keyHash,
  };
}

/**
 * Canonical virtual API key format parser.
 * Extracts the 11-character public prefix and 43-character base64url secret.
 * Returns null if the key envelope does not match gw_live_<11>_<43>.
 */
export function parseRawKey(rawKey: string): { publicPrefix: string; secret: string } | null {
  const match = /^gw_live_([A-Za-z0-9_-]{11})_([A-Za-z0-9_-]{43})$/.exec(rawKey);
  if (!match) {
    return null;
  }
  return {
    publicPrefix: match[1]!,
    secret: match[2]!,
  };
}

/**
 * Internal Virtual API Key Service.
 * Implements secure 256-bit gateway key generation, SHA-256 verifier persistence,
 * tenant-scoped storage, and one-time plaintext key disclosure.
 */
export class VirtualKeyService {
  private readonly pool: pg.Pool;

  constructor(poolOrOptions: pg.Pool | VirtualKeyServiceOptions) {
    this.pool = 'pool' in poolOrOptions ? poolOrOptions.pool : poolOrOptions;
  }

  /**
   * Validates input parameters for virtual key creation fail-closed.
   */
  private validateInput(input: unknown): { orgId: string; name: string } {
    if (!input || typeof input !== 'object') {
      throw new VirtualKeyError('INVALID_INPUT', 'Invalid input: expected an object');
    }

    const { orgId, name } = input as Record<string, unknown>;

    // Validate organization ID
    if (typeof orgId !== 'string') {
      throw new VirtualKeyError('INVALID_INPUT', 'Invalid organization ID: expected string');
    }
    let validatedOrgId: string;
    try {
      validatedOrgId = validateTenantId(orgId);
    } catch (err: unknown) {
      throw new VirtualKeyError('INVALID_INPUT', 'Invalid organization ID: malformed UUID', {
        cause: err,
      });
    }

    // Validate name
    if (typeof name !== 'string') {
      throw new VirtualKeyError('INVALID_INPUT', 'Invalid key name: expected string');
    }
    const trimmedName = name.trim();
    if (trimmedName.length === 0) {
      throw new VirtualKeyError('INVALID_INPUT', 'Invalid key name: name cannot be empty');
    }
    if (Buffer.byteLength(trimmedName, 'utf8') > 255) {
      throw new VirtualKeyError(
        'INVALID_INPUT',
        'Invalid key name: exceeds maximum 255 UTF-8 bytes',
      );
    }
    if (CONTROL_CHARS_REGEX.test(trimmedName)) {
      throw new VirtualKeyError(
        'INVALID_INPUT',
        'Invalid key name: control characters are prohibited',
      );
    }

    return { orgId: validatedOrgId, name: trimmedName };
  }

  /**
   * Issues a new virtual API key for the specified organization.
   *
   * Security & Lifecycle Invariants:
   * 1. Validates organization ID and display name fail-closed.
   * 2. Generates 8-byte public prefix and independent 32-byte secret (256-bit entropy).
   * 3. Formats canonical key: gw_live_<11-char-prefix>_<43-char-secret> (63 ASCII chars).
   * 4. Computes 32-byte SHA-256 verifier from raw secret bytes.
   * 5. Enters tenant transaction via withTenant(pool, orgId).
   * 6. Executes parameterized INSERT with initial deny-all policy (allowed_models = '{}',
   *    rpm_limit = 1, tpm_limit = 1, concurrent_stream_limit = 1, exact_cache = false,
   *    semantic_cache = false, pii_redaction = true, store_payloads = false, revoked_at = null).
   * 7. Handles uniqueness collisions with bounded regeneration (max 3 attempts).
   * 8. Returns plaintext rawKey ONLY after confirmed transaction commit.
   */
  async createKey(input: CreateVirtualKeyInput): Promise<CreateVirtualKeyResult> {
    const { orgId, name } = this.validateInput(input);

    for (let attempt = 1; attempt <= MAX_COLLISION_ATTEMPTS; attempt++) {
      const { id, keyPrefix, rawKey, keyHash } = generateKeyMaterial();

      try {
        const row = await withTenant(this.pool, orgId, async (client) => {
          const res = await client.query<{
            id: string;
            org_id: string;
            name: string;
            key_prefix: string;
            created_at: Date;
          }>(
            `INSERT INTO virtual_keys (
              id,
              org_id,
              name,
              key_prefix,
              key_hash,
              allowed_models,
              rpm_limit,
              tpm_limit,
              concurrent_stream_limit,
              exact_cache_enabled,
              semantic_cache_enabled,
              pii_redaction_enabled,
              store_payloads,
              revoked_at
            ) VALUES (
              $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
            )
            RETURNING id, org_id, name, key_prefix, created_at`,
            [
              id,
              orgId,
              name,
              keyPrefix,
              keyHash,
              [], // allowed_models: empty array (deny-all)
              1, // rpm_limit: integer 1 (satisfies NOT NULL + CHECK > 0)
              1, // tpm_limit: integer 1 (satisfies NOT NULL + CHECK > 0)
              1, // concurrent_stream_limit: integer 1 (satisfies NOT NULL + CHECK > 0)
              false, // exact_cache_enabled: false
              false, // semantic_cache_enabled: false
              true, // pii_redaction_enabled: true
              false, // store_payloads: false
              null, // revoked_at: null
            ],
          );
          return res.rows[0];
        });

        if (!row) {
          throw new VirtualKeyError('DATABASE_ERROR', 'Database error during virtual key creation');
        }

        // Return plaintext rawKey ONLY after confirmed commit
        return {
          id: row.id,
          orgId: row.org_id,
          name: row.name,
          keyPrefix: row.key_prefix,
          createdAt: row.created_at,
          rawKey,
        };
      } catch (err: unknown) {
        if (err instanceof VirtualKeyError) {
          throw err;
        }

        // Check for qualifying unique constraint collision
        if (isQualifyingCollision(err)) {
          if (attempt < MAX_COLLISION_ATTEMPTS) {
            // Discard collision material and retry with fresh material
            continue;
          }
          throw new VirtualKeyError(
            'KEY_COLLISION_EXHAUSTED',
            'Exhausted maximum retry attempts due to key collision',
            { cause: err },
          );
        }

        // Relational conflict (e.g. non-existent organization foreign key)
        if (isForeignKeyViolation(err)) {
          throw new VirtualKeyError(
            'DATABASE_CONFLICT',
            'Referenced organization does not exist or violates relational constraint',
            { cause: err },
          );
        }

        // All other database, permission, RLS, or connection errors fail closed without retry
        throw new VirtualKeyError('DATABASE_ERROR', 'Database error during virtual key creation', {
          cause: err,
        });
      }
    }

    throw new VirtualKeyError(
      'KEY_COLLISION_EXHAUSTED',
      'Exhausted maximum retry attempts due to key collision',
    );
  }
}
