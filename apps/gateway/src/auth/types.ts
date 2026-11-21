/**
 * Domain errors, interfaces, and types for Switchyard Authentication and Session services (SW-1.5.1, SW-1.5.2).
 */

export type AuthFailureReason =
  | 'INVALID_CREDENTIALS'
  | 'RATE_LIMITED'
  | 'SERVICE_UNAVAILABLE'
  | 'INVALID_INPUT'
  | 'CONFIGURATION_ERROR';

export class AuthenticationError extends Error {
  public readonly reason: AuthFailureReason;

  constructor(reason: AuthFailureReason, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'AuthenticationError';
    this.reason = reason;
  }
}

export type SessionFailureReason =
  | 'MISSING_SECRET'
  | 'MALFORMED_SECRET'
  | 'SESSION_NOT_FOUND'
  | 'SESSION_REVOKED'
  | 'SESSION_EXPIRED_IDLE'
  | 'SESSION_EXPIRED_ABSOLUTE'
  | 'TENANT_MISMATCH'
  | 'DATABASE_ERROR'
  | 'CONFIGURATION_ERROR';

export class SessionError extends Error {
  public readonly reason: SessionFailureReason;

  constructor(reason: SessionFailureReason, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'SessionError';
    this.reason = reason;
  }
}

export class BootstrapError extends Error {
  public readonly code: string;

  constructor(code: string, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'BootstrapError';
    this.code = code;
  }
}

export interface AuthenticatedUser {
  readonly id: string;
  readonly orgId: string;
  readonly role: 'admin' | 'member';
  readonly emailNormalized: string;
}

export interface WebSession {
  readonly sessionIdHash: Buffer;
  readonly userId: string;
  readonly orgId: string;
  readonly csrfTokenHash: Buffer;
  readonly createdAt: Date;
  readonly lastSeenAt: Date;
  readonly idleExpiresAt: Date;
  readonly absoluteExpiresAt: Date;
  readonly revokedAt: Date | null;
}

export interface SessionValidationResult {
  readonly valid: boolean;
  readonly session?: WebSession;
  readonly user?: AuthenticatedUser;
  readonly reason?: SessionFailureReason;
}

export interface SessionCreationResult {
  readonly secret: string;
  readonly csrfToken: string;
  readonly session: WebSession;
}

export interface SessionRotationResult {
  readonly newSecret: string;
  readonly newCsrfToken: string;
  readonly session: WebSession;
}

export interface InternalBootstrapParams {
  readonly orgId?: string;
  readonly orgName: string;
  readonly monthlyBudgetMicrodollars: bigint;
  readonly kekVersion: number;
  readonly wrappedDek: Buffer;
  readonly dekIv: Buffer;
  readonly dekAuthTag: Buffer;
  readonly adminUserId?: string;
  readonly adminEmail: string;
  readonly adminPassword: string;
}

export interface InternalBootstrapResult {
  readonly orgId: string;
  readonly adminUserId: string;
}

export interface SessionCookieOptions {
  cookieName?: string;
  secure?: boolean;
  isProduction?: boolean;
}
