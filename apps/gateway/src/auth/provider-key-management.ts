import crypto from 'node:crypto';
import type pg from 'pg';
import { validateTenantId, withTenant } from '../db/tenant.js';
import {
  EnvelopeVault,
  MAX_PROVIDER_CREDENTIAL_BYTES,
  SUPPORTED_PROVIDERS,
  type OrganizationDekEnvelope,
  type SupportedProvider,
} from '../vault/envelope.js';
import { VaultError } from '../vault/errors.js';

export type ProviderKeyManagementErrorReason =
  | 'INVALID_INPUT'
  | 'KEY_NOT_FOUND'
  | 'KEY_DISABLED'
  | 'VAULT_UNAVAILABLE'
  | 'AUTHENTICATION_FAILED'
  | 'DATABASE_ERROR';

export class ProviderKeyManagementError extends Error {
  public readonly reason: ProviderKeyManagementErrorReason;

  constructor(
    reason: ProviderKeyManagementErrorReason,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = 'ProviderKeyManagementError';
    this.reason = reason;
  }
}

export interface ProviderKeyMetadataDto {
  id: string;
  provider: SupportedProvider;
  label: string;
  keyHint: string;
  isActive: boolean;
  createdAt: string;
}

export interface CreateProviderKeyInput {
  provider: string;
  label: string;
  credential: string;
}

export interface ReplaceProviderKeyInput {
  label: string;
  credential: string;
}

export interface ListProviderKeysOptions {
  limit?: number | undefined;
  cursor?: string | undefined;
}

export interface ListProviderKeysResult {
  items: ProviderKeyMetadataDto[];
  nextCursor: string | null;
}

export interface ProviderKeyManagementServiceOptions {
  pool: pg.Pool;
  vault?: EnvelopeVault | undefined;
}

export const MAX_LABEL_BYTES = 255;
export const DEFAULT_PAGE_LIMIT = 20;
export const MAX_PAGE_LIMIT = 100;

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONTROL_CHARS_REGEX = /[\u0000-\u001F\u007F-\u009F]/;
const CURSOR_TIMESTAMP_REGEX = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{6})Z$/;
const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;
const MAX_CURSOR_LENGTH = 256;

export function isValidUuid(id: unknown): id is string {
  return typeof id === 'string' && UUID_REGEX.test(id.trim());
}

export function validateKeyId(keyId: unknown): string {
  if (typeof keyId !== 'string') {
    throw new ProviderKeyManagementError(
      'INVALID_INPUT',
      `Invalid key ID: expected string, got ${keyId === null ? 'null' : typeof keyId}`,
    );
  }
  const trimmed = keyId.trim();
  if (trimmed.length === 0 || !UUID_REGEX.test(trimmed)) {
    throw new ProviderKeyManagementError(
      'INVALID_INPUT',
      `Invalid key ID: malformed UUID "${keyId}"`,
    );
  }
  return trimmed.toLowerCase();
}

/**
 * Derives a safe key hint adhering to Architecture §11.5 last-four-character requirement.
 * Credentials with 4 or fewer characters return an entirely masked '****' hint to avoid
 * revealing the entire secret or its exact length.
 */
export function deriveKeyHint(credential: string): string {
  const chars = Array.from(credential);
  if (chars.length <= 4) {
    return '****';
  }
  const lastFour = chars.slice(-4).join('');
  const sanitizedLastFour = lastFour.replace(CONTROL_CHARS_REGEX, '');
  return `****${sanitizedLastFour}`;
}

export function validateLabel(rawLabel: unknown): string {
  if (typeof rawLabel !== 'string') {
    throw new ProviderKeyManagementError('INVALID_INPUT', 'Invalid label: expected string');
  }
  const trimmed = rawLabel.trim();
  if (trimmed.length === 0) {
    throw new ProviderKeyManagementError('INVALID_INPUT', 'Invalid label: label cannot be empty');
  }
  if (Buffer.byteLength(trimmed, 'utf8') > MAX_LABEL_BYTES) {
    throw new ProviderKeyManagementError(
      'INVALID_INPUT',
      `Invalid label: exceeds maximum ${MAX_LABEL_BYTES} UTF-8 bytes`,
    );
  }
  if (CONTROL_CHARS_REGEX.test(trimmed)) {
    throw new ProviderKeyManagementError(
      'INVALID_INPUT',
      'Invalid label: control characters are prohibited',
    );
  }
  return trimmed;
}

export function validateProvider(rawProvider: unknown): SupportedProvider {
  if (typeof rawProvider !== 'string') {
    throw new ProviderKeyManagementError('INVALID_INPUT', 'Invalid provider: expected string');
  }
  const trimmed = rawProvider.trim();
  if (!SUPPORTED_PROVIDERS.includes(trimmed as SupportedProvider)) {
    throw new ProviderKeyManagementError(
      'INVALID_INPUT',
      `Unsupported provider "${trimmed}": only "openai" is currently supported`,
    );
  }
  return trimmed as SupportedProvider;
}

function validateCanonicalTimestamp(timestamp: unknown): string {
  if (typeof timestamp !== 'string') {
    throw new Error('Not a string');
  }
  const match = CURSOR_TIMESTAMP_REGEX.exec(timestamp);
  if (!match) {
    throw new Error('Does not match canonical UTC microsecond format');
  }

  const [, yStr, mStr, dStr, hStr, minStr, sStr] = match;
  const year = parseInt(yStr!, 10);
  const month = parseInt(mStr!, 10);
  const day = parseInt(dStr!, 10);
  const hour = parseInt(hStr!, 10);
  const minute = parseInt(minStr!, 10);
  const second = parseInt(sStr!, 10);

  if (month < 1 || month > 12) throw new Error('Month out of range');
  if (day < 1 || day > 31) throw new Error('Day out of range');
  if (hour > 23 || minute > 59 || second > 59) throw new Error('Time out of range');

  const daysInMonth = (y: number, m: number): number => {
    switch (m) {
      case 2:
        return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28;
      case 4:
      case 6:
      case 9:
      case 11:
        return 30;
      default:
        return 31;
    }
  };

  if (day > daysInMonth(year, month)) {
    throw new Error('Day does not exist in specified month/year');
  }

  return timestamp;
}

interface DecodedCursor {
  createdAt: string;
  id: string;
}

export function decodeCursor(cursor: string): DecodedCursor {
  if (cursor.length > MAX_CURSOR_LENGTH || !BASE64URL_REGEX.test(cursor)) {
    throw new ProviderKeyManagementError('INVALID_INPUT', 'Invalid cursor: malformed cursor');
  }

  let rawJson: string;
  try {
    const buf = Buffer.from(cursor, 'base64url');
    if (buf.toString('base64url') !== cursor) {
      throw new Error('Non-canonical base64url encoding');
    }
    rawJson = buf.toString('utf8');
  } catch (err) {
    throw new ProviderKeyManagementError('INVALID_INPUT', 'Invalid cursor: malformed cursor', {
      cause: err,
    });
  }

  try {
    const parsed = JSON.parse(rawJson) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Not an object');
    }
    const rec = parsed as Record<string, unknown>;
    const keys = Object.keys(rec);
    if (keys.length !== 2 || !('createdAt' in rec) || !('id' in rec)) {
      throw new Error('Unexpected cursor keys');
    }
    const validatedCreatedAt = validateCanonicalTimestamp(rec.createdAt);
    if (typeof rec.id !== 'string' || !UUID_REGEX.test(rec.id.trim())) {
      throw new Error('Invalid cursor key id');
    }
    return {
      createdAt: validatedCreatedAt,
      id: rec.id.trim().toLowerCase(),
    };
  } catch (err) {
    throw new ProviderKeyManagementError('INVALID_INPUT', 'Invalid cursor: malformed cursor', {
      cause: err,
    });
  }
}

export function encodeCursor(cursorCreatedAt: string, id: string): string {
  const validatedCreatedAt = validateCanonicalTimestamp(cursorCreatedAt);
  const trimmedId = validateKeyId(id);

  return Buffer.from(
    JSON.stringify({
      createdAt: validatedCreatedAt,
      id: trimmedId,
    }),
    'utf8',
  ).toString('base64url');
}

export class ProviderKeyManagementService {
  private readonly pool: pg.Pool;
  private readonly vault?: EnvelopeVault | undefined;

  constructor(options: ProviderKeyManagementServiceOptions) {
    this.pool = options.pool;
    this.vault = options.vault;
  }

  public hasVault(): boolean {
    return this.vault !== undefined;
  }

  /**
   * Creates an encrypted provider credential for the organization.
   * Credential plaintext buffer is zeroized in a finally block.
   */
  async createKey(orgId: string, input: CreateProviderKeyInput): Promise<ProviderKeyMetadataDto> {
    const validatedOrgId = validateTenantId(orgId);

    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new ProviderKeyManagementError(
        'INVALID_INPUT',
        'Invalid request body: expected a non-null JSON object',
      );
    }

    const provider = validateProvider(input.provider);
    const label = validateLabel(input.label);

    if (typeof input.credential !== 'string') {
      throw new ProviderKeyManagementError('INVALID_INPUT', 'Invalid credential: expected string');
    }

    const credBuffer = Buffer.from(input.credential, 'utf8');
    try {
      if (credBuffer.length === 0) {
        throw new ProviderKeyManagementError(
          'INVALID_INPUT',
          'Invalid credential: credential cannot be empty',
        );
      }

      if (credBuffer.length > MAX_PROVIDER_CREDENTIAL_BYTES) {
        throw new ProviderKeyManagementError(
          'INVALID_INPUT',
          `Invalid credential: exceeds maximum ${MAX_PROVIDER_CREDENTIAL_BYTES} bytes`,
        );
      }

      if (!this.vault) {
        throw new ProviderKeyManagementError(
          'VAULT_UNAVAILABLE',
          'Provider credential vault is unavailable',
        );
      }

      const keyHint = deriveKeyHint(input.credential);
      const providerKeyId = crypto.randomUUID();

      return await withTenant(this.pool, validatedOrgId, async (client) => {
        // 1. Fetch organization DEK envelope
        const orgRes = await client.query<{
          kek_version: number;
          wrapped_dek: Buffer;
          dek_iv: Buffer;
          dek_auth_tag: Buffer;
        }>(
          `SELECT kek_version, wrapped_dek, dek_iv, dek_auth_tag
           FROM organizations
           WHERE id = $1`,
          [validatedOrgId],
        );

        if (orgRes.rows.length === 0) {
          throw new ProviderKeyManagementError('KEY_NOT_FOUND', 'Organization not found');
        }

        const orgRow = orgRes.rows[0]!;
        const organizationEnvelope: OrganizationDekEnvelope = {
          kekVersion: orgRow.kek_version,
          wrappedDek: orgRow.wrapped_dek,
          dekIv: orgRow.dek_iv,
          dekAuthTag: orgRow.dek_auth_tag,
        };

        // 2. Encrypt provider credential under organization DEK
        let encrypted;
        try {
          encrypted = this.vault!.encryptProviderCredential({
            orgId: validatedOrgId,
            providerKeyId,
            provider,
            plaintext: credBuffer,
            organizationEnvelope,
          });
        } catch (err) {
          if (err instanceof VaultError) {
            if (err.reason === 'CONFIGURATION_ERROR') {
              throw new ProviderKeyManagementError(
                'VAULT_UNAVAILABLE',
                'Provider credential vault configuration error',
                { cause: err },
              );
            }
            if (err.reason === 'AUTHENTICATION_FAILED') {
              throw new ProviderKeyManagementError(
                'AUTHENTICATION_FAILED',
                'Organization DEK authentication failed',
                { cause: err },
              );
            }
            if (err.reason === 'UNSUPPORTED_FORMAT') {
              throw new ProviderKeyManagementError(
                'AUTHENTICATION_FAILED',
                'Invalid stored organization envelope',
                { cause: err },
              );
            }
          }
          throw err;
        }

        // 3. Persist encrypted provider credential
        const insertRes = await client.query<{
          id: string;
          provider: SupportedProvider;
          label: string;
          key_hint: string;
          is_active: boolean;
          created_at: Date;
        }>(
          `INSERT INTO provider_keys (
             id,
             org_id,
             provider,
             label,
             key_hint,
             ciphertext,
             iv,
             auth_tag,
             is_active
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)
           RETURNING id, provider, label, key_hint, is_active, created_at`,
          [
            providerKeyId,
            validatedOrgId,
            provider,
            label,
            keyHint,
            encrypted.ciphertext,
            encrypted.iv,
            encrypted.authTag,
          ],
        );

        const row = insertRes.rows[0]!;
        return {
          id: row.id,
          provider: row.provider,
          label: row.label,
          keyHint: row.key_hint,
          isActive: row.is_active,
          createdAt:
            row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at),
        };
      });
    } finally {
      credBuffer.fill(0);
    }
  }

  /**
   * Atomically replaces a provider credential.
   * Disabled provider keys cannot be replaced.
   * Credential plaintext buffer is zeroized in a finally block.
   */
  async replaceKey(
    orgId: string,
    keyId: string,
    input: ReplaceProviderKeyInput,
  ): Promise<ProviderKeyMetadataDto> {
    const validatedOrgId = validateTenantId(orgId);
    const validatedKeyId = validateKeyId(keyId);

    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new ProviderKeyManagementError(
        'INVALID_INPUT',
        'Invalid request body: expected a non-null JSON object',
      );
    }

    const label = validateLabel(input.label);

    if (typeof input.credential !== 'string') {
      throw new ProviderKeyManagementError('INVALID_INPUT', 'Invalid credential: expected string');
    }

    const credBuffer = Buffer.from(input.credential, 'utf8');
    try {
      if (credBuffer.length === 0) {
        throw new ProviderKeyManagementError(
          'INVALID_INPUT',
          'Invalid credential: credential cannot be empty',
        );
      }

      if (credBuffer.length > MAX_PROVIDER_CREDENTIAL_BYTES) {
        throw new ProviderKeyManagementError(
          'INVALID_INPUT',
          `Invalid credential: exceeds maximum ${MAX_PROVIDER_CREDENTIAL_BYTES} bytes`,
        );
      }

      if (!this.vault) {
        throw new ProviderKeyManagementError(
          'VAULT_UNAVAILABLE',
          'Provider credential vault is unavailable',
        );
      }

      const keyHint = deriveKeyHint(input.credential);

      return await withTenant(this.pool, validatedOrgId, async (client) => {
        // 1. Lock existing provider key row
        const existingRes = await client.query<{
          id: string;
          provider: SupportedProvider;
          is_active: boolean;
        }>(
          `SELECT id, provider, is_active
           FROM provider_keys
           WHERE id = $1
           FOR UPDATE`,
          [validatedKeyId],
        );

        if (existingRes.rows.length === 0) {
          throw new ProviderKeyManagementError('KEY_NOT_FOUND', 'Provider key not found');
        }

        const existing = existingRes.rows[0]!;
        if (!existing.is_active) {
          throw new ProviderKeyManagementError(
            'KEY_DISABLED',
            'Cannot replace credential of a disabled provider key',
          );
        }

        // 2. Load organization DEK envelope
        const orgRes = await client.query<{
          kek_version: number;
          wrapped_dek: Buffer;
          dek_iv: Buffer;
          dek_auth_tag: Buffer;
        }>(
          `SELECT kek_version, wrapped_dek, dek_iv, dek_auth_tag
           FROM organizations
           WHERE id = $1`,
          [validatedOrgId],
        );

        if (orgRes.rows.length === 0) {
          throw new ProviderKeyManagementError('KEY_NOT_FOUND', 'Organization not found');
        }

        const orgRow = orgRes.rows[0]!;
        const organizationEnvelope: OrganizationDekEnvelope = {
          kekVersion: orgRow.kek_version,
          wrappedDek: orgRow.wrapped_dek,
          dekIv: orgRow.dek_iv,
          dekAuthTag: orgRow.dek_auth_tag,
        };

        // 3. Encrypt replacement credential with fresh IV
        let encrypted;
        try {
          encrypted = this.vault!.encryptProviderCredential({
            orgId: validatedOrgId,
            providerKeyId: validatedKeyId,
            provider: existing.provider,
            plaintext: credBuffer,
            organizationEnvelope,
          });
        } catch (err) {
          if (err instanceof VaultError) {
            if (err.reason === 'CONFIGURATION_ERROR') {
              throw new ProviderKeyManagementError(
                'VAULT_UNAVAILABLE',
                'Provider credential vault configuration error',
                { cause: err },
              );
            }
            if (err.reason === 'AUTHENTICATION_FAILED') {
              throw new ProviderKeyManagementError(
                'AUTHENTICATION_FAILED',
                'Organization DEK authentication failed',
                { cause: err },
              );
            }
            if (err.reason === 'UNSUPPORTED_FORMAT') {
              throw new ProviderKeyManagementError(
                'AUTHENTICATION_FAILED',
                'Invalid stored organization envelope',
                { cause: err },
              );
            }
          }
          throw err;
        }

        // 4. Update provider key row
        const updateRes = await client.query<{
          id: string;
          provider: SupportedProvider;
          label: string;
          key_hint: string;
          is_active: boolean;
          created_at: Date;
        }>(
          `UPDATE provider_keys
           SET
             label = $1,
             key_hint = $2,
             ciphertext = $3,
             iv = $4,
             auth_tag = $5
           WHERE id = $6 AND org_id = $7
           RETURNING id, provider, label, key_hint, is_active, created_at`,
          [
            label,
            keyHint,
            encrypted.ciphertext,
            encrypted.iv,
            encrypted.authTag,
            validatedKeyId,
            validatedOrgId,
          ],
        );

        const row = updateRes.rows[0]!;
        return {
          id: row.id,
          provider: row.provider,
          label: row.label,
          keyHint: row.key_hint,
          isActive: row.is_active,
          createdAt:
            row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at),
        };
      });
    } finally {
      credBuffer.fill(0);
    }
  }

  /**
   * Lists provider credentials using bounded keyset pagination.
   * Never selects or returns ciphertext, iv, auth_tag, or wrapping keys.
   */
  async listKeys(
    orgId: string,
    options?: ListProviderKeysOptions,
  ): Promise<ListProviderKeysResult> {
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
        throw new ProviderKeyManagementError(
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

    return withTenant(this.pool, validatedOrgId, async (client) => {
      let queryText: string;
      let queryParams: unknown[];

      if (decodedCursor) {
        queryText = `
          SELECT
            id,
            provider,
            label,
            key_hint,
            is_active,
            created_at,
            to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cursor_created_at
          FROM provider_keys
          WHERE (created_at, id) < ($1::timestamptz, $2::uuid)
          ORDER BY created_at DESC, id DESC
          LIMIT $3
        `;
        queryParams = [decodedCursor.createdAt, decodedCursor.id, limit + 1];
      } else {
        queryText = `
          SELECT
            id,
            provider,
            label,
            key_hint,
            is_active,
            created_at,
            to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cursor_created_at
          FROM provider_keys
          ORDER BY created_at DESC, id DESC
          LIMIT $1
        `;
        queryParams = [limit + 1];
      }

      const res = await client.query<{
        id: string;
        provider: SupportedProvider;
        label: string;
        key_hint: string;
        is_active: boolean;
        created_at: Date;
        cursor_created_at: string;
      }>(queryText, queryParams);

      const hasMore = res.rows.length > limit;
      const rows = hasMore ? res.rows.slice(0, limit) : res.rows;

      const items: ProviderKeyMetadataDto[] = rows.map((r) => ({
        id: r.id,
        provider: r.provider,
        label: r.label,
        keyHint: r.key_hint,
        isActive: r.is_active,
        createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : String(r.created_at),
      }));

      let nextCursor: string | null = null;
      if (hasMore && rows.length > 0) {
        const lastRow = rows[rows.length - 1]!;
        nextCursor = encodeCursor(lastRow.cursor_created_at, lastRow.id);
      }

      return {
        items,
        nextCursor,
      };
    });
  }

  /**
   * Disables an existing provider credential (soft disable).
   * Idempotent: repeated calls on already disabled keys return successfully.
   * Does not decrypt or expose any credential material.
   */
  async disableKey(orgId: string, keyId: string): Promise<void> {
    const validatedOrgId = validateTenantId(orgId);
    const validatedKeyId = validateKeyId(keyId);

    await withTenant(this.pool, validatedOrgId, async (client) => {
      const res = await client.query<{ id: string; is_active: boolean }>(
        `SELECT id, is_active
         FROM provider_keys
         WHERE id = $1
         FOR UPDATE`,
        [validatedKeyId],
      );

      if (res.rows.length === 0) {
        throw new ProviderKeyManagementError('KEY_NOT_FOUND', 'Provider key not found');
      }

      const existing = res.rows[0]!;
      if (!existing.is_active) {
        // Idempotent: already disabled
        return;
      }

      await client.query(
        `UPDATE provider_keys
         SET is_active = false
         WHERE id = $1 AND org_id = $2`,
        [validatedKeyId, validatedOrgId],
      );
    });
  }
}
