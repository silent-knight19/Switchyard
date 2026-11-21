import type pg from 'pg';
import { validateTenantId, withTenant } from '../db/tenant.js';
import { type CreateVirtualKeyResult, VirtualKeyError, VirtualKeyService } from './virtual-key.js';

export type VirtualKeyManagementErrorReason =
  'INVALID_INPUT' | 'KEY_NOT_FOUND' | 'KEY_REVOKED' | 'DATABASE_ERROR';

export class VirtualKeyManagementError extends Error {
  public readonly reason: VirtualKeyManagementErrorReason;

  constructor(
    reason: VirtualKeyManagementErrorReason,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = 'VirtualKeyManagementError';
    this.reason = reason;
  }
}

export interface KeyMetadataDto {
  id: string;
  name: string;
  keyPrefix: string;
  createdAt: string;
  revokedAt: string | null;
  allowedModels: string[];
  rpmLimit: number;
  tpmLimit: number;
  concurrentStreamLimit: number;
  exactCacheEnabled: boolean;
  semanticCacheEnabled: boolean;
  piiRedactionEnabled: boolean;
  storePayloads: boolean;
}

export interface CreateKeyResponseDto extends KeyMetadataDto {
  rawKey: string;
}

export interface ListKeysResult {
  items: KeyMetadataDto[];
  nextCursor: string | null;
}

export interface UpdatePolicyInput {
  allowedModels: string[];
  rpmLimit: number;
  tpmLimit: number;
  concurrentStreamLimit: number;
  exactCacheEnabled: boolean;
  semanticCacheEnabled: boolean;
  piiRedactionEnabled: boolean;
  storePayloads: boolean;
}

export interface VirtualKeyManagementServiceOptions {
  pool: pg.Pool;
  virtualKeyService?: VirtualKeyService;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONTROL_CHARS_REGEX = /[\u0000-\u001F\u007F-\u009F]/;
const MAX_ALLOWED_MODELS = 100;
const MAX_MODEL_ID_LENGTH = 128;
const MAX_PG_INTEGER = 2147483647;
const DEFAULT_PAGE_LIMIT = 20;
const MAX_PAGE_LIMIT = 100;

export function isValidUuid(id: unknown): id is string {
  return typeof id === 'string' && UUID_REGEX.test(id.trim());
}

export function validateKeyId(keyId: unknown): string {
  if (typeof keyId !== 'string') {
    throw new VirtualKeyManagementError(
      'INVALID_INPUT',
      `Invalid key ID: expected string, got ${keyId === null ? 'null' : typeof keyId}`,
    );
  }
  const trimmed = keyId.trim();
  if (trimmed.length === 0 || !UUID_REGEX.test(trimmed)) {
    throw new VirtualKeyManagementError(
      'INVALID_INPUT',
      `Invalid key ID: malformed UUID "${keyId}"`,
    );
  }
  return trimmed;
}

interface DecodedCursor {
  createdAt: string;
  id: string;
}

export function decodeCursor(cursor: unknown): DecodedCursor {
  if (typeof cursor !== 'string' || cursor.trim().length === 0) {
    throw new VirtualKeyManagementError('INVALID_INPUT', 'Invalid cursor: malformed cursor');
  }

  try {
    const rawJson = Buffer.from(cursor, 'base64url').toString('utf8');
    const parsed = JSON.parse(rawJson) as unknown;

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Not an object');
    }

    const rec = parsed as Record<string, unknown>;
    const keys = Object.keys(rec);
    if (keys.length !== 2 || !('createdAt' in rec) || !('id' in rec)) {
      throw new Error('Unexpected cursor keys');
    }

    if (typeof rec.createdAt !== 'string' || isNaN(Date.parse(rec.createdAt))) {
      throw new Error('Invalid cursor createdAt timestamp');
    }

    if (typeof rec.id !== 'string' || !UUID_REGEX.test(rec.id.trim())) {
      throw new Error('Invalid cursor key id');
    }

    return {
      createdAt: new Date(rec.createdAt).toISOString(),
      id: rec.id.trim(),
    };
  } catch (err) {
    throw new VirtualKeyManagementError('INVALID_INPUT', 'Invalid cursor: malformed cursor', {
      cause: err,
    });
  }
}

export function encodeCursor(createdAt: Date, id: string): string {
  return Buffer.from(
    JSON.stringify({
      createdAt: createdAt.toISOString(),
      id,
    }),
  ).toString('base64url');
}

export function validatePolicyInput(input: unknown): UpdatePolicyInput {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new VirtualKeyManagementError(
      'INVALID_INPUT',
      'Invalid policy: expected a non-null JSON object',
    );
  }

  const rec = input as Record<string, unknown>;
  const allowedKeys = new Set([
    'allowedModels',
    'rpmLimit',
    'tpmLimit',
    'concurrentStreamLimit',
    'exactCacheEnabled',
    'semanticCacheEnabled',
    'piiRedactionEnabled',
    'storePayloads',
  ]);

  const actualKeys = Object.keys(rec);
  if (actualKeys.length !== allowedKeys.size) {
    throw new VirtualKeyManagementError(
      'INVALID_INPUT',
      'Invalid policy: all policy fields must be explicitly supplied with no unknown fields',
    );
  }

  for (const key of actualKeys) {
    if (!allowedKeys.has(key)) {
      throw new VirtualKeyManagementError(
        'INVALID_INPUT',
        `Invalid policy: unknown property "${key}" is prohibited`,
      );
    }
  }

  // 1. allowedModels validation
  if (!Array.isArray(rec.allowedModels)) {
    throw new VirtualKeyManagementError(
      'INVALID_INPUT',
      'Invalid policy: allowedModels must be an array of strings',
    );
  }

  if (rec.allowedModels.length > MAX_ALLOWED_MODELS) {
    throw new VirtualKeyManagementError(
      'INVALID_INPUT',
      `Invalid policy: allowedModels exceeds maximum permitted length of ${MAX_ALLOWED_MODELS}`,
    );
  }

  const seenModels = new Set<string>();
  const validatedModels: string[] = [];

  for (let i = 0; i < rec.allowedModels.length; i++) {
    const model = rec.allowedModels[i];
    if (typeof model !== 'string') {
      throw new VirtualKeyManagementError(
        'INVALID_INPUT',
        `Invalid policy: allowedModels[${i}] must be a string`,
      );
    }

    if (model.length === 0) {
      throw new VirtualKeyManagementError(
        'INVALID_INPUT',
        `Invalid policy: allowedModels[${i}] cannot be an empty string`,
      );
    }

    if (model !== model.trim()) {
      throw new VirtualKeyManagementError(
        'INVALID_INPUT',
        `Invalid policy: allowedModels[${i}] contains prohibited leading or trailing whitespace`,
      );
    }

    if (model.length > MAX_MODEL_ID_LENGTH) {
      throw new VirtualKeyManagementError(
        'INVALID_INPUT',
        `Invalid policy: allowedModels[${i}] exceeds maximum length of ${MAX_MODEL_ID_LENGTH} characters`,
      );
    }

    if (CONTROL_CHARS_REGEX.test(model)) {
      throw new VirtualKeyManagementError(
        'INVALID_INPUT',
        `Invalid policy: allowedModels[${i}] contains prohibited control characters`,
      );
    }

    if (model.includes('*')) {
      throw new VirtualKeyManagementError(
        'INVALID_INPUT',
        `Invalid policy: wildcard pattern "${model}" in allowedModels is prohibited`,
      );
    }

    if (seenModels.has(model)) {
      throw new VirtualKeyManagementError(
        'INVALID_INPUT',
        `Invalid policy: duplicate model identifier "${model}" in allowedModels`,
      );
    }

    seenModels.add(model);
    validatedModels.push(model);
  }

  // 2. Numeric limit validation helper
  const validateIntegerLimit = (val: unknown, name: string): number => {
    if (typeof val !== 'number' || !Number.isFinite(val) || !Number.isSafeInteger(val)) {
      throw new VirtualKeyManagementError(
        'INVALID_INPUT',
        `Invalid policy: ${name} must be a positive safe integer`,
      );
    }
    if (val <= 0) {
      throw new VirtualKeyManagementError(
        'INVALID_INPUT',
        `Invalid policy: ${name} must be strictly positive (greater than 0)`,
      );
    }
    if (val > MAX_PG_INTEGER) {
      throw new VirtualKeyManagementError(
        'INVALID_INPUT',
        `Invalid policy: ${name} exceeds maximum PostgreSQL 32-bit integer (${MAX_PG_INTEGER})`,
      );
    }
    return val;
  };

  const rpmLimit = validateIntegerLimit(rec.rpmLimit, 'rpmLimit');
  const tpmLimit = validateIntegerLimit(rec.tpmLimit, 'tpmLimit');
  const concurrentStreamLimit = validateIntegerLimit(
    rec.concurrentStreamLimit,
    'concurrentStreamLimit',
  );

  // 3. Boolean flags validation
  const validateBoolean = (val: unknown, name: string): boolean => {
    if (typeof val !== 'boolean') {
      throw new VirtualKeyManagementError(
        'INVALID_INPUT',
        `Invalid policy: ${name} must be a boolean`,
      );
    }
    return val;
  };

  const exactCacheEnabled = validateBoolean(rec.exactCacheEnabled, 'exactCacheEnabled');
  const semanticCacheEnabled = validateBoolean(rec.semanticCacheEnabled, 'semanticCacheEnabled');
  const piiRedactionEnabled = validateBoolean(rec.piiRedactionEnabled, 'piiRedactionEnabled');
  const storePayloads = validateBoolean(rec.storePayloads, 'storePayloads');

  // Architecture v1.2 §16: exact and semantic cache functionalities are deferred until later phases
  if (exactCacheEnabled) {
    throw new VirtualKeyManagementError(
      'INVALID_INPUT',
      'Invalid policy: exactCacheEnabled cannot be enabled because caching is deferred',
    );
  }

  if (semanticCacheEnabled) {
    throw new VirtualKeyManagementError(
      'INVALID_INPUT',
      'Invalid policy: semanticCacheEnabled cannot be enabled because caching is deferred',
    );
  }

  return {
    allowedModels: validatedModels,
    rpmLimit,
    tpmLimit,
    concurrentStreamLimit,
    exactCacheEnabled,
    semanticCacheEnabled,
    piiRedactionEnabled,
    storePayloads,
  };
}

export class VirtualKeyManagementService {
  private readonly pool: pg.Pool;
  private readonly virtualKeyService: VirtualKeyService;

  constructor(options: VirtualKeyManagementServiceOptions) {
    this.pool = options.pool;
    if (options.virtualKeyService) {
      this.virtualKeyService = options.virtualKeyService;
    } else if (options.pool) {
      this.virtualKeyService = new VirtualKeyService(options.pool);
    } else {
      this.virtualKeyService = undefined as unknown as VirtualKeyService;
    }
  }

  /**
   * Creates a new organization-owned virtual API key.
   * Discloses the generated plaintext rawKey exactly once upon database commit.
   */
  async createKey(orgId: string, name: string): Promise<CreateKeyResponseDto> {
    const validatedOrgId = validateTenantId(orgId);

    if (!this.virtualKeyService || !this.pool) {
      throw new VirtualKeyManagementError('DATABASE_ERROR', 'Database pool unavailable');
    }

    let createResult: CreateVirtualKeyResult;
    try {
      createResult = await this.virtualKeyService.createKey({
        orgId: validatedOrgId,
        name,
      });
    } catch (err) {
      if (err instanceof VirtualKeyError) {
        if (err.reason === 'INVALID_INPUT') {
          throw new VirtualKeyManagementError('INVALID_INPUT', err.message, { cause: err });
        }
        throw new VirtualKeyManagementError('DATABASE_ERROR', 'Failed to create virtual key', {
          cause: err,
        });
      }
      throw err;
    }

    return {
      id: createResult.id,
      name: createResult.name,
      keyPrefix: createResult.keyPrefix,
      createdAt: createResult.createdAt.toISOString(),
      rawKey: createResult.rawKey,
      allowedModels: [],
      rpmLimit: 1,
      tpmLimit: 1,
      concurrentStreamLimit: 1,
      exactCacheEnabled: false,
      semanticCacheEnabled: false,
      piiRedactionEnabled: true,
      storePayloads: false,
      revokedAt: null,
    };
  }

  /**
   * Lists organization-owned virtual keys using bounded keyset pagination.
   * Never selects or returns raw key material, secrets, or verifier hashes.
   */
  async listKeys(
    orgId: string,
    options?: { limit?: number; cursor?: string },
  ): Promise<ListKeysResult> {
    const validatedOrgId = validateTenantId(orgId);

    let limit = DEFAULT_PAGE_LIMIT;
    if (options?.limit !== undefined) {
      if (
        typeof options.limit !== 'number' ||
        !Number.isFinite(options.limit) ||
        !Number.isSafeInteger(options.limit) ||
        options.limit < 1 ||
        options.limit > MAX_PAGE_LIMIT
      ) {
        throw new VirtualKeyManagementError(
          'INVALID_INPUT',
          `Invalid limit: must be a positive integer between 1 and ${MAX_PAGE_LIMIT}`,
        );
      }
      limit = options.limit;
    }

    let decodedCursor: DecodedCursor | null = null;
    if (options?.cursor !== undefined) {
      decodedCursor = decodeCursor(options.cursor);
    }

    if (!this.pool) {
      throw new VirtualKeyManagementError('DATABASE_ERROR', 'Database pool unavailable');
    }

    return withTenant(this.pool, validatedOrgId, async (client) => {
      let queryText: string;
      let queryParams: unknown[];

      if (decodedCursor) {
        queryText = `
          SELECT
            id,
            name,
            key_prefix,
            created_at,
            revoked_at,
            allowed_models,
            rpm_limit,
            tpm_limit,
            concurrent_stream_limit,
            exact_cache_enabled,
            semantic_cache_enabled,
            pii_redaction_enabled,
            store_payloads
          FROM virtual_keys
          WHERE (created_at < $1::timestamptz) OR (created_at = $1::timestamptz AND id < $2::uuid)
          ORDER BY created_at DESC, id DESC
          LIMIT $3
        `;
        queryParams = [decodedCursor.createdAt, decodedCursor.id, limit + 1];
      } else {
        queryText = `
          SELECT
            id,
            name,
            key_prefix,
            created_at,
            revoked_at,
            allowed_models,
            rpm_limit,
            tpm_limit,
            concurrent_stream_limit,
            exact_cache_enabled,
            semantic_cache_enabled,
            pii_redaction_enabled,
            store_payloads
          FROM virtual_keys
          ORDER BY created_at DESC, id DESC
          LIMIT $1
        `;
        queryParams = [limit + 1];
      }

      const res = await client.query<{
        id: string;
        name: string;
        key_prefix: string;
        created_at: Date;
        revoked_at: Date | null;
        allowed_models: string[];
        rpm_limit: number;
        tpm_limit: number;
        concurrent_stream_limit: number;
        exact_cache_enabled: boolean;
        semantic_cache_enabled: boolean;
        pii_redaction_enabled: boolean;
        store_payloads: boolean;
      }>(queryText, queryParams);

      const rows = res.rows;
      const hasMore = rows.length > limit;
      const resultRows = hasMore ? rows.slice(0, limit) : rows;

      let nextCursor: string | null = null;
      if (hasMore && resultRows.length > 0) {
        const lastRow = resultRows[resultRows.length - 1]!;
        nextCursor = encodeCursor(lastRow.created_at, lastRow.id);
      }

      const items: KeyMetadataDto[] = resultRows.map((r) => ({
        id: r.id,
        name: r.name,
        keyPrefix: r.key_prefix,
        createdAt: r.created_at.toISOString(),
        revokedAt: r.revoked_at ? r.revoked_at.toISOString() : null,
        allowedModels: r.allowed_models,
        rpmLimit: r.rpm_limit,
        tpmLimit: r.tpm_limit,
        concurrentStreamLimit: r.concurrent_stream_limit,
        exactCacheEnabled: r.exact_cache_enabled,
        semanticCacheEnabled: r.semantic_cache_enabled,
        piiRedactionEnabled: r.pii_redaction_enabled,
        storePayloads: r.store_payloads,
      }));

      return {
        items,
        nextCursor,
      };
    });
  }

  /**
   * Atomically replaces the complete mutable policy configuration of an active key.
   * Acquires row lock (SELECT ... FOR UPDATE) and fails closed on revoked or cross-tenant keys.
   */
  async replacePolicy(orgId: string, keyId: string, policyInput: unknown): Promise<KeyMetadataDto> {
    const validatedOrgId = validateTenantId(orgId);
    const validatedKeyId = validateKeyId(keyId);
    const policy = validatePolicyInput(policyInput);

    if (!this.pool) {
      throw new VirtualKeyManagementError('DATABASE_ERROR', 'Database pool unavailable');
    }

    return withTenant(this.pool, validatedOrgId, async (client) => {
      // 1. Locate and lock tenant-owned row
      const lockRes = await client.query<{ id: string; revoked_at: Date | null }>(
        'SELECT id, revoked_at FROM virtual_keys WHERE id = $1 FOR UPDATE',
        [validatedKeyId],
      );

      if (lockRes.rows.length === 0) {
        throw new VirtualKeyManagementError('KEY_NOT_FOUND', 'Virtual key not found');
      }

      const row = lockRes.rows[0]!;
      if (row.revoked_at !== null) {
        throw new VirtualKeyManagementError(
          'KEY_REVOKED',
          'Cannot update policy of a revoked virtual key',
        );
      }

      // 2. Atomically update mutable policy fields
      const updateRes = await client.query<{
        id: string;
        name: string;
        key_prefix: string;
        created_at: Date;
        revoked_at: Date | null;
        allowed_models: string[];
        rpm_limit: number;
        tpm_limit: number;
        concurrent_stream_limit: number;
        exact_cache_enabled: boolean;
        semantic_cache_enabled: boolean;
        pii_redaction_enabled: boolean;
        store_payloads: boolean;
      }>(
        `UPDATE virtual_keys
         SET
           allowed_models = $2,
           rpm_limit = $3,
           tpm_limit = $4,
           concurrent_stream_limit = $5,
           exact_cache_enabled = $6,
           semantic_cache_enabled = $7,
           pii_redaction_enabled = $8,
           store_payloads = $9
         WHERE id = $1
         RETURNING
           id,
           name,
           key_prefix,
           created_at,
           revoked_at,
           allowed_models,
           rpm_limit,
           tpm_limit,
           concurrent_stream_limit,
           exact_cache_enabled,
           semantic_cache_enabled,
           pii_redaction_enabled,
           store_payloads`,
        [
          validatedKeyId,
          policy.allowedModels,
          policy.rpmLimit,
          policy.tpmLimit,
          policy.concurrentStreamLimit,
          policy.exactCacheEnabled,
          policy.semanticCacheEnabled,
          policy.piiRedactionEnabled,
          policy.storePayloads,
        ],
      );

      const updated = updateRes.rows[0]!;
      return {
        id: updated.id,
        name: updated.name,
        keyPrefix: updated.key_prefix,
        createdAt: updated.created_at.toISOString(),
        revokedAt: updated.revoked_at ? updated.revoked_at.toISOString() : null,
        allowedModels: updated.allowed_models,
        rpmLimit: updated.rpm_limit,
        tpmLimit: updated.tpm_limit,
        concurrentStreamLimit: updated.concurrent_stream_limit,
        exactCacheEnabled: updated.exact_cache_enabled,
        semanticCacheEnabled: updated.semantic_cache_enabled,
        piiRedactionEnabled: updated.pii_redaction_enabled,
        storePayloads: updated.store_payloads,
      };
    });
  }

  /**
   * Logically revokes a virtual API key permanently.
   * Acquires row lock (SELECT ... FOR UPDATE) and sets revoked_at = clock_timestamp().
   * Operation is idempotent: repeated revocation on an already-revoked key leaves the
   * original revocation timestamp unchanged.
   */
  async revokeKey(orgId: string, keyId: string): Promise<void> {
    const validatedOrgId = validateTenantId(orgId);
    const validatedKeyId = validateKeyId(keyId);

    if (!this.pool) {
      throw new VirtualKeyManagementError('DATABASE_ERROR', 'Database pool unavailable');
    }

    await withTenant(this.pool, validatedOrgId, async (client) => {
      const lockRes = await client.query<{ id: string; revoked_at: Date | null }>(
        'SELECT id, revoked_at FROM virtual_keys WHERE id = $1 FOR UPDATE',
        [validatedKeyId],
      );

      if (lockRes.rows.length === 0) {
        throw new VirtualKeyManagementError('KEY_NOT_FOUND', 'Virtual key not found');
      }

      const row = lockRes.rows[0]!;
      if (row.revoked_at !== null) {
        // Already revoked: preserve original revocation timestamp idempotently
        return;
      }

      await client.query(
        'UPDATE virtual_keys SET revoked_at = clock_timestamp() WHERE id = $1 AND revoked_at IS NULL',
        [validatedKeyId],
      );
    });
  }
}
