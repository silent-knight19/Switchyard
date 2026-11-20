import crypto from 'node:crypto';
import type pg from 'pg';
import { getConfig, type GatewayConfig } from '../config/index.js';
import { type TenantClient, withTenant } from '../db/tenant.js';
import {
  type AuthenticatedUser,
  type SessionCookieOptions,
  type SessionCreationResult,
  SessionError,
  type SessionRotationResult,
  type SessionValidationResult,
  type WebSession,
} from './types.js';

export const IDLE_EXPIRY_INTERVAL = "interval '2 hours'";
export const ABSOLUTE_EXPIRY_INTERVAL = "interval '7 days'";

/**
 * Validates whether an opaque session secret string is structurally valid:
 * Exact canonical unpadded base64url representation of a 32-byte secret (AUTH-04).
 * Rejects whitespace, non-base64url characters, padding, and noncanonical pad bits.
 */
export function decodeSessionSecret(secret: unknown): Buffer {
  if (typeof secret !== 'string') {
    throw new SessionError('MISSING_SECRET', 'Session secret must be a string');
  }

  // Exact length constraint: 32 bytes in unpadded base64url is exactly 43 characters (no trimming)
  if (secret.length !== 43) {
    throw new SessionError(
      'MALFORMED_SECRET',
      `Session secret length (${secret.length}) is invalid; expected exactly 43 base64url characters`,
    );
  }

  // Strict unpadded base64url alphabet (no whitespace, no +, no /, no =)
  if (!/^[A-Za-z0-9_-]{43}$/.test(secret)) {
    throw new SessionError(
      'MALFORMED_SECRET',
      'Session secret contains invalid characters; expected canonical unpadded base64url',
    );
  }

  const buf = Buffer.from(secret, 'base64url');
  if (buf.length !== 32) {
    throw new SessionError(
      'MALFORMED_SECRET',
      `Decoded session secret length (${buf.length} bytes) is invalid; expected exactly 32 bytes`,
    );
  }

  // Canonical round-trip verification:
  // Catches noncanonical pad bits where distinct 43-character strings decode to identical 32-byte buffers
  if (buf.toString('base64url') !== secret) {
    throw new SessionError(
      'MALFORMED_SECRET',
      'Session secret contains noncanonical base64url encoding or invalid pad bits',
    );
  }

  return buf;
}

export function hashSecret(secretBytes: Buffer): Buffer {
  return crypto.createHash('sha256').update(secretBytes).digest();
}

export interface SessionServiceOptions {
  pool: pg.Pool;
  config?: GatewayConfig;
  environment?: 'development' | 'test' | 'production';
  cookieOptions?: SessionCookieOptions;
}

export class SessionService {
  private readonly pool: pg.Pool;
  private readonly cookieName: string;
  private readonly isSecureCookie: boolean;

  constructor(options: SessionServiceOptions) {
    this.pool = options.pool;

    // Resolve authoritative trusted runtime environment (AUTH-07)
    // Priority:
    // 1. Explicit validated GatewayConfig passed in options
    // 2. Explicit environment passed in options
    // 3. Loaded GatewayConfig singleton (if initialized)
    // 4. Ambient process.env['NODE_ENV']
    const trustedEnv: 'development' | 'test' | 'production' = (() => {
      if (options.config?.NODE_ENV) {
        return options.config.NODE_ENV;
      }
      if (options.environment) {
        return options.environment;
      }
      try {
        const cfg = getConfig();
        if (cfg?.NODE_ENV) {
          return cfg.NODE_ENV;
        }
      } catch {
        // Fall back to process.env if getConfig() is uninitialized or invalid in bare test context
      }
      const env = process.env['NODE_ENV'];
      if (env === 'production') return 'production';
      if (env === 'test') return 'test';
      return 'development';
    })();

    if (trustedEnv === 'production') {
      // Production security requirements cannot be downgraded (AUTH-02, AUTH-07)
      if (options.cookieOptions?.isProduction === false) {
        throw new SessionError(
          'CONFIGURATION_ERROR',
          'Production environment cannot be overridden with isProduction: false',
        );
      }
      if (options.cookieOptions?.secure === false) {
        throw new SessionError(
          'CONFIGURATION_ERROR',
          'Insecure session cookies (secure: false) are strictly prohibited in production',
        );
      }
      if (
        options.cookieOptions?.cookieName !== undefined &&
        options.cookieOptions.cookieName !== '__Host-session'
      ) {
        throw new SessionError(
          'CONFIGURATION_ERROR',
          `Production session cookies must use the "__Host-session" name; received "${options.cookieOptions.cookieName}"`,
        );
      }

      this.isSecureCookie = true;
      this.cookieName = '__Host-session';
    } else {
      // Non-production environment (development / test)
      if (options.cookieOptions?.isProduction === true) {
        // Explicit request to run with production cookie rules in dev/test
        if (options.cookieOptions?.secure === false) {
          throw new SessionError(
            'CONFIGURATION_ERROR',
            'Insecure session cookies (secure: false) are strictly prohibited when isProduction: true',
          );
        }
        if (
          options.cookieOptions?.cookieName !== undefined &&
          options.cookieOptions.cookieName !== '__Host-session'
        ) {
          throw new SessionError(
            'CONFIGURATION_ERROR',
            `Production session cookies must use the "__Host-session" name; received "${options.cookieOptions.cookieName}"`,
          );
        }

        this.isSecureCookie = true;
        this.cookieName = '__Host-session';
      } else {
        // Development / test behavior: explicitly support local development HTTP without weakening production
        this.isSecureCookie =
          options.cookieOptions?.secure ?? options.config?.COOKIE_SECURE ?? false;

        if (options.cookieOptions?.cookieName !== undefined) {
          // Enforce __Host- cookie security invariant: __Host- prefix MUST be Secure
          if (options.cookieOptions.cookieName.startsWith('__Host-') && !this.isSecureCookie) {
            throw new SessionError(
              'CONFIGURATION_ERROR',
              'Cookies with "__Host-" prefix require secure=true',
            );
          }
          this.cookieName = options.cookieOptions.cookieName;
        } else {
          this.cookieName = this.isSecureCookie ? '__Host-session' : 'switchyard_session';
        }
      }
    }
  }

  public getCookieName(): string {
    return this.cookieName;
  }

  /**
   * Constructs the Set-Cookie header string for an authenticated session.
   */
  public createSessionCookie(secret: string, maxAgeSeconds = 604800): string {
    const parts = [
      `${this.cookieName}=${secret}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Lax',
      `Max-Age=${maxAgeSeconds}`,
    ];

    if (this.isSecureCookie) {
      parts.push('Secure');
    }

    return parts.join('; ');
  }

  /**
   * Constructs an expired Set-Cookie header string to clear a session cookie.
   */
  public createClearSessionCookie(): string {
    const parts = [
      `${this.cookieName}=`,
      'Path=/',
      'HttpOnly',
      'SameSite=Lax',
      'Max-Age=0',
      'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    ];

    if (this.isSecureCookie) {
      parts.push('Secure');
    }

    return parts.join('; ');
  }

  /**
   * Extracts the session secret from a raw HTTP Cookie header.
   */
  public extractSessionSecretFromCookieHeader(cookieHeader: string | undefined): string | null {
    if (!cookieHeader || typeof cookieHeader !== 'string') {
      return null;
    }

    const cookies = cookieHeader.split(';');
    for (const cookie of cookies) {
      const [name, ...valParts] = cookie.trim().split('=');
      if (name === this.cookieName) {
        return valParts.join('=');
      }
    }

    return null;
  }

  /**
   * Creates and persists a new server-side session for a user within an organization.
   * Runs exclusively inside withTenant(orgId, ...).
   */
  public async createSession(orgId: string, userId: string): Promise<SessionCreationResult> {
    const secretBytes = crypto.randomBytes(32);
    const secret = secretBytes.toString('base64url');
    const sessionIdHash = hashSecret(secretBytes);

    const csrfBytes = crypto.randomBytes(32);
    const csrfToken = csrfBytes.toString('base64url');
    const csrfTokenHash = hashSecret(csrfBytes);

    return withTenant(this.pool, orgId, async (client: TenantClient) => {
      const { rows } = await client.query<{
        session_id_hash: Buffer;
        user_id: string;
        org_id: string;
        csrf_token_hash: Buffer;
        created_at: Date;
        last_seen_at: Date;
        idle_expires_at: Date;
        absolute_expires_at: Date;
        revoked_at: Date | null;
      }>(
        `INSERT INTO public.web_sessions (
          session_id_hash,
          user_id,
          org_id,
          csrf_token_hash,
          last_seen_at,
          idle_expires_at,
          absolute_expires_at
        ) VALUES (
          $1, $2, $3, $4,
          clock_timestamp(),
          clock_timestamp() + interval '2 hours',
          clock_timestamp() + interval '7 days'
        ) RETURNING
          session_id_hash,
          user_id,
          org_id,
          csrf_token_hash,
          created_at,
          last_seen_at,
          idle_expires_at,
          absolute_expires_at,
          revoked_at;`,
        [sessionIdHash, userId, orgId, csrfTokenHash],
      );

      const row = rows[0];
      if (!row) {
        throw new SessionError('DATABASE_ERROR', 'Failed to insert session row');
      }

      const session: WebSession = {
        sessionIdHash: row.session_id_hash,
        userId: row.user_id,
        orgId: row.org_id,
        csrfTokenHash: row.csrf_token_hash,
        createdAt: row.created_at,
        lastSeenAt: row.last_seen_at,
        idleExpiresAt: row.idle_expires_at,
        absoluteExpiresAt: row.absolute_expires_at,
        revokedAt: row.revoked_at,
      };

      return {
        secret,
        csrfToken,
        session,
      };
    });
  }

  /**
   * Pre-tenant lookup: resolves the tenant organization ID from an opaque session secret.
   * Invokes restricted privileged function app_private.lookup_session_org_by_hash.
   */
  public async lookupSessionOrgId(secretBytes: Buffer): Promise<string | null> {
    const sessionIdHash = hashSecret(secretBytes);

    try {
      const { rows } = await this.pool.query<{ org_id: string }>(
        'SELECT org_id FROM app_private.lookup_session_org_by_hash($1)',
        [sessionIdHash],
      );

      if (rows.length === 0 || !rows[0]) {
        return null;
      }

      return rows[0].org_id;
    } catch {
      return null;
    }
  }

  /**
   * Resolves and validates an incoming session from its opaque secret string.
   *
   * Lifecycle:
   * 1. Validates and decodes secret string (fail closed on malformed representation).
   * 2. Computes SHA-256 verifier.
   * 3. Invokes app_private.lookup_session_org_by_hash to resolve routing org_id.
   * 4. Enters withTenant(resolvedOrgId, ...) under strict RLS.
   * 5. Locks and verifies session row (revocation status, idle and absolute expiration).
   * 6. Verifies associated user identity.
   * 7. Atomically updates last_seen_at and renews idle_expires_at.
   */
  public async resolveAndValidateSession(rawSecret: unknown): Promise<SessionValidationResult> {
    let secretBytes: Buffer;
    try {
      secretBytes = decodeSessionSecret(rawSecret);
    } catch (err) {
      if (err instanceof SessionError) {
        return { valid: false, reason: err.reason };
      }
      return { valid: false, reason: 'MALFORMED_SECRET' };
    }

    const orgId = await this.lookupSessionOrgId(secretBytes);
    if (!orgId) {
      return { valid: false, reason: 'SESSION_NOT_FOUND' };
    }

    const sessionIdHash = hashSecret(secretBytes);

    return withTenant(this.pool, orgId, async (client: TenantClient) => {
      // Re-query web_sessions with lock (FOR UPDATE OF ws)
      const { rows } = await client.query<{
        session_id_hash: Buffer;
        user_id: string;
        org_id: string;
        csrf_token_hash: Buffer;
        created_at: Date;
        last_seen_at: Date;
        idle_expires_at: Date;
        absolute_expires_at: Date;
        revoked_at: Date | null;
        user_role: 'admin' | 'member';
        email_normalized: string;
        db_now: Date;
      }>(
        `SELECT
          ws.session_id_hash,
          ws.user_id,
          ws.org_id,
          ws.csrf_token_hash,
          ws.created_at,
          ws.last_seen_at,
          ws.idle_expires_at,
          ws.absolute_expires_at,
          ws.revoked_at,
          u.role AS user_role,
          u.email_normalized,
          clock_timestamp() AS db_now
        FROM public.web_sessions ws
        JOIN public.users u ON u.id = ws.user_id AND u.org_id = ws.org_id
        WHERE ws.session_id_hash = $1
        FOR UPDATE OF ws;`,
        [sessionIdHash],
      );

      const row = rows[0];
      if (!row) {
        return { valid: false, reason: 'SESSION_NOT_FOUND' };
      }

      // Check revocation
      if (row.revoked_at !== null) {
        return { valid: false, reason: 'SESSION_REVOKED' };
      }

      const now = row.db_now.getTime();
      const absExp = row.absolute_expires_at.getTime();
      const idleExp = row.idle_expires_at.getTime();

      // Check absolute expiration
      if (now >= absExp) {
        return { valid: false, reason: 'SESSION_EXPIRED_ABSOLUTE' };
      }

      // Check idle expiration
      if (now >= idleExp) {
        return { valid: false, reason: 'SESSION_EXPIRED_IDLE' };
      }

      // Atomically renew last_seen_at and idle_expires_at (bounded by absolute_expires_at)
      const { rows: renewedRows } = await client.query<{
        last_seen_at: Date;
        idle_expires_at: Date;
      }>(
        `UPDATE public.web_sessions
        SET
          last_seen_at = clock_timestamp(),
          idle_expires_at = LEAST(clock_timestamp() + interval '2 hours', absolute_expires_at)
        WHERE session_id_hash = $1
        RETURNING last_seen_at, idle_expires_at;`,
        [sessionIdHash],
      );

      const renewed = renewedRows[0];

      const session: WebSession = {
        sessionIdHash: row.session_id_hash,
        userId: row.user_id,
        orgId: row.org_id,
        csrfTokenHash: row.csrf_token_hash,
        createdAt: row.created_at,
        lastSeenAt: renewed?.last_seen_at ?? row.last_seen_at,
        idleExpiresAt: renewed?.idle_expires_at ?? row.idle_expires_at,
        absoluteExpiresAt: row.absolute_expires_at,
        revokedAt: row.revoked_at,
      };

      const user: AuthenticatedUser = {
        id: row.user_id,
        orgId: row.org_id,
        role: row.user_role,
        emailNormalized: row.email_normalized,
      };

      return {
        valid: true,
        session,
        user,
      };
    });
  }

  /**
   * Rotates an active session to a fresh secret.
   * Guarantees atomicity and concurrency safety:
   * 1. Locks the old session row (FOR UPDATE).
   * 2. Asserts it is currently valid (not revoked, not expired).
   * 3. Generates new secret & CSRF token.
   * 4. Inserts new web_sessions row with preserved user/org binding.
   * 5. Atomically revokes the old session row.
   * 6. Prevents concurrent double-rotations of the same old session.
   */
  public async rotateSession(rawOldSecret: unknown): Promise<SessionRotationResult> {
    const oldSecretBytes = decodeSessionSecret(rawOldSecret);
    const orgId = await this.lookupSessionOrgId(oldSecretBytes);
    if (!orgId) {
      throw new SessionError('SESSION_NOT_FOUND', 'Session not found for rotation');
    }

    const oldSessionIdHash = hashSecret(oldSecretBytes);

    return withTenant(this.pool, orgId, async (client: TenantClient) => {
      // 1. Lock old session
      const { rows } = await client.query<{
        user_id: string;
        org_id: string;
        created_at: Date;
        absolute_expires_at: Date;
        revoked_at: Date | null;
        idle_expires_at: Date;
        db_now: Date;
      }>(
        `SELECT
          ws.user_id,
          ws.org_id,
          ws.created_at,
          ws.absolute_expires_at,
          ws.revoked_at,
          ws.idle_expires_at,
          clock_timestamp() AS db_now
        FROM public.web_sessions ws
        WHERE ws.session_id_hash = $1
        FOR UPDATE;`,
        [oldSessionIdHash],
      );

      const oldRow = rows[0];
      if (!oldRow) {
        throw new SessionError('SESSION_NOT_FOUND', 'Old session row not found');
      }

      if (oldRow.revoked_at !== null) {
        throw new SessionError('SESSION_REVOKED', 'Cannot rotate an already revoked session');
      }

      const now = oldRow.db_now.getTime();
      const absExp = oldRow.absolute_expires_at.getTime();
      const idleExp = oldRow.idle_expires_at.getTime();

      if (now >= absExp) {
        throw new SessionError(
          'SESSION_EXPIRED_ABSOLUTE',
          'Cannot rotate an absolute-expired session',
        );
      }
      if (now >= idleExp) {
        throw new SessionError('SESSION_EXPIRED_IDLE', 'Cannot rotate an idle-expired session');
      }

      // 2. Generate new session secret & CSRF token
      const newSecretBytes = crypto.randomBytes(32);
      const newSecret = newSecretBytes.toString('base64url');
      const newSessionIdHash = hashSecret(newSecretBytes);

      const newCsrfBytes = crypto.randomBytes(32);
      const newCsrfToken = newCsrfBytes.toString('base64url');
      const newCsrfTokenHash = hashSecret(newCsrfBytes);

      // 3. Insert new session row
      // CRITICAL INVARIANT (AUTH-03):
      // new_idle_expires_at = LEAST(database_now + idle_interval, inherited_absolute_expires_at)
      // Never extend absolute expiration during rotation.
      // Never create a rotated session whose idle expiry exceeds absolute expiry.
      const insertRes = await client.query<{
        session_id_hash: Buffer;
        user_id: string;
        org_id: string;
        csrf_token_hash: Buffer;
        created_at: Date;
        last_seen_at: Date;
        idle_expires_at: Date;
        absolute_expires_at: Date;
        revoked_at: Date | null;
      }>(
        `INSERT INTO public.web_sessions (
          session_id_hash,
          user_id,
          org_id,
          csrf_token_hash,
          last_seen_at,
          idle_expires_at,
          absolute_expires_at
        ) VALUES (
          $1, $2, $3, $4,
          clock_timestamp(),
          LEAST(clock_timestamp() + interval '2 hours', $5::timestamptz),
          $5
        ) RETURNING
          session_id_hash,
          user_id,
          org_id,
          csrf_token_hash,
          created_at,
          last_seen_at,
          idle_expires_at,
          absolute_expires_at,
          revoked_at;`,
        [
          newSessionIdHash,
          oldRow.user_id,
          oldRow.org_id,
          newCsrfTokenHash,
          oldRow.absolute_expires_at,
        ],
      );

      const newRow = insertRes.rows[0];
      if (!newRow) {
        throw new SessionError('DATABASE_ERROR', 'Failed to insert rotated session');
      }

      // 4. Atomically revoke old session
      await client.query(
        `UPDATE public.web_sessions
        SET revoked_at = clock_timestamp()
        WHERE session_id_hash = $1;`,
        [oldSessionIdHash],
      );

      const session: WebSession = {
        sessionIdHash: newRow.session_id_hash,
        userId: newRow.user_id,
        orgId: newRow.org_id,
        csrfTokenHash: newRow.csrf_token_hash,
        createdAt: newRow.created_at,
        lastSeenAt: newRow.last_seen_at,
        idleExpiresAt: newRow.idle_expires_at,
        absoluteExpiresAt: newRow.absolute_expires_at,
        revokedAt: newRow.revoked_at,
      };

      return {
        newSecret,
        newCsrfToken,
        session,
      };
    });
  }

  /**
   * Explicit logout: revokes the active session matching the provided secret.
   * Safe for repeated logout calls (idempotent).
   */
  public async revokeSession(rawSecret: unknown): Promise<boolean> {
    let secretBytes: Buffer;
    try {
      secretBytes = decodeSessionSecret(rawSecret);
    } catch {
      return false;
    }

    const orgId = await this.lookupSessionOrgId(secretBytes);
    if (!orgId) {
      return false;
    }

    const sessionIdHash = hashSecret(secretBytes);

    return withTenant(this.pool, orgId, async (client: TenantClient) => {
      const res = await client.query(
        `UPDATE public.web_sessions
        SET revoked_at = clock_timestamp()
        WHERE session_id_hash = $1 AND revoked_at IS NULL;`,
        [sessionIdHash],
      );

      return (res.rowCount ?? 0) > 0;
    });
  }

  /**
   * Revokes all active sessions for a given user across an organization.
   * Used upon password change or security-sensitive privilege change.
   */
  public async revokeAllUserSessions(orgId: string, userId: string): Promise<number> {
    return withTenant(this.pool, orgId, async (client: TenantClient) => {
      const res = await client.query(
        `UPDATE public.web_sessions
        SET revoked_at = clock_timestamp()
        WHERE user_id = $1 AND org_id = $2 AND revoked_at IS NULL;`,
        [userId, orgId],
      );

      return res.rowCount ?? 0;
    });
  }
}
