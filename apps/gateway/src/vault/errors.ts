/**
 * Typed, secret-free error classification for the provider credential envelope vault
 * (Architecture v1.2 §14.1–§14.3, SW-1.7.1/SW-1.7.2).
 *
 * Every message is deliberately generic: callers and logs must never receive raw KEKs, DEKs,
 * provider credentials, ciphertext bytes, authentication tags, or configuration values.
 */
export type VaultErrorReason =
  | 'CONFIGURATION_ERROR'
  | 'INVALID_INPUT'
  | 'UNSUPPORTED_FORMAT'
  | 'UNKNOWN_KEK_VERSION'
  | 'AUTHENTICATION_FAILED'
  | 'DATABASE_ERROR';

export class VaultError extends Error {
  public readonly reason: VaultErrorReason;

  constructor(reason: VaultErrorReason, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'VaultError';
    this.reason = reason;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
