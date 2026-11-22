import { VaultError } from './errors.js';

/**
 * Versioned environment-backed KEK configuration for provider credential envelope encryption
 * (Architecture v1.2 §14.1–§14.2, SW-1.7.1).
 *
 * V1 representation contract:
 * - A KEK is exactly 32 bytes encoded as canonical, unpadded base64url (43 characters).
 * - `ACTIVE_KEK_VERSION` is exactly the decimal string "1" or "2" and must reference a supplied key.
 * - No KEK configuration means the vault is uninitialised (no usable vault is constructed).
 * - Partially supplied, malformed, duplicate, or all-zero KEK material fails closed.
 */

export type KekVersion = 1 | 2;

export const SUPPORTED_KEK_VERSIONS: readonly KekVersion[] = Object.freeze([1, 2]);
export const KEK_BYTE_LENGTH = 32;
export const KEK_ENCODED_LENGTH = 43;

const CANONICAL_BASE64URL_43 = /^[A-Za-z0-9_-]{43}$/;

export interface KekEnvironment {
  readonly MASTER_KEK_V1?: string | undefined;
  readonly MASTER_KEK_V2?: string | undefined;
  readonly ACTIVE_KEK_VERSION?: string | undefined;
}

export type KekField = 'MASTER_KEK_V1' | 'MASTER_KEK_V2' | 'ACTIVE_KEK_VERSION';

export interface KekConfigIssue {
  readonly field: KekField;
  readonly message: string;
}

export type KekEnvironmentInspection =
  | { readonly status: 'absent' }
  | { readonly status: 'valid'; readonly keyring: KekKeyring }
  | { readonly status: 'invalid'; readonly issues: readonly KekConfigIssue[] };

export interface KekKeyringInput {
  readonly activeVersion: KekVersion;
  readonly keys: Partial<Record<KekVersion, Buffer>>;
}

const INVALID_KEK_MATERIAL_MESSAGE =
  'KEK material must be canonical unpadded base64url encoding exactly 32 bytes';
const ALL_ZERO_KEK_MESSAGE = 'KEK material must not be all zero bytes';
const DUPLICATE_KEK_MESSAGE = 'KEK V1 and KEK V2 must not contain identical key material';
const MISSING_ACTIVE_KEK_MESSAGE = 'ACTIVE_KEK_VERSION must reference a supplied valid KEK';
const INVALID_ACTIVE_VERSION_MESSAGE = 'ACTIVE_KEK_VERSION must be exactly "1" or "2"';
const MISSING_ACTIVE_VERSION_MESSAGE =
  'ACTIVE_KEK_VERSION is required when KEK configuration is supplied';

function decodeKek(value: string): { ok: true; value: Buffer } | { ok: false } {
  if (value.length !== KEK_ENCODED_LENGTH || !CANONICAL_BASE64URL_43.test(value)) {
    return { ok: false };
  }

  let decoded: Buffer;
  try {
    decoded = Buffer.from(value, 'base64url');
  } catch {
    return { ok: false };
  }

  // Re-encoding equality rejects noncanonical trailing pad bits, padding, and alternate alphabets.
  if (decoded.length !== KEK_BYTE_LENGTH || decoded.toString('base64url') !== value) {
    decoded.fill(0);
    return { ok: false };
  }

  if (decoded.every((byte) => byte === 0)) {
    decoded.fill(0);
    return { ok: false };
  }

  return { ok: true, value: decoded };
}

function isAllZero(buffer: Buffer): boolean {
  return buffer.every((byte) => byte === 0);
}

/**
 * Versioned KEK keyring. The keyring owns private, process-lifetime KEK Buffers; they are copied on
 * construction and are never exposed directly. `resolve(version)` returns an independent temporary
 * Buffer copy that the caller owns and MUST clear after use. `withKey(version, operation)` resolves
 * such a copy, runs a synchronous operation, and clears the copy in a `finally` block on success and
 * every exception path. No public API intentionally exposes the keyring's internal KEK material.
 */
export class KekKeyring {
  private readonly active: KekVersion;
  private readonly keys: ReadonlyMap<KekVersion, Buffer>;

  constructor(input: KekKeyringInput) {
    if (input.activeVersion !== 1 && input.activeVersion !== 2) {
      throw new VaultError('CONFIGURATION_ERROR', INVALID_ACTIVE_VERSION_MESSAGE);
    }

    const keys = new Map<KekVersion, Buffer>();
    for (const version of SUPPORTED_KEK_VERSIONS) {
      const key = input.keys[version];
      if (key === undefined) {
        continue;
      }
      if (!Buffer.isBuffer(key) || key.length !== KEK_BYTE_LENGTH) {
        for (const existing of keys.values()) existing.fill(0);
        throw new VaultError('CONFIGURATION_ERROR', INVALID_KEK_MATERIAL_MESSAGE);
      }
      if (isAllZero(key)) {
        for (const existing of keys.values()) existing.fill(0);
        throw new VaultError('CONFIGURATION_ERROR', ALL_ZERO_KEK_MESSAGE);
      }
      // Own a private copy so external mutation of caller buffers cannot change the keyring.
      keys.set(version, Buffer.from(key));
    }

    if (!keys.has(input.activeVersion)) {
      for (const existing of keys.values()) existing.fill(0);
      throw new VaultError('CONFIGURATION_ERROR', MISSING_ACTIVE_KEK_MESSAGE);
    }

    const v1 = keys.get(1);
    const v2 = keys.get(2);
    if (v1 !== undefined && v2 !== undefined && v1.equals(v2)) {
      for (const existing of keys.values()) existing.fill(0);
      throw new VaultError('CONFIGURATION_ERROR', DUPLICATE_KEK_MESSAGE);
    }

    this.active = input.activeVersion;
    this.keys = keys;
  }

  public get activeVersion(): KekVersion {
    return this.active;
  }

  public has(version: number): boolean {
    return (version === 1 || version === 2) && this.keys.has(version);
  }

  /**
   * Resolve exactly the requested KEK version. There is no fallback to another configured key.
   *
   * The returned Buffer is an independent copy owned by the caller. Mutating it cannot alter the
   * keyring's process-lifetime material. The caller MUST clear the copy after use; prefer
   * {@link withKey}, which performs that cleanup with exception-safe semantics.
   */
  public resolve(version: number): Buffer {
    if (version !== 1 && version !== 2) {
      throw new VaultError('UNKNOWN_KEK_VERSION', 'KEK version is not supported');
    }
    const key = this.keys.get(version);
    if (key === undefined) {
      throw new VaultError('UNKNOWN_KEK_VERSION', 'KEK version is not configured');
    }
    return Buffer.from(key);
  }

  /**
   * Run a synchronous cryptographic operation with an independent KEK copy that is always cleared
   * afterwards, including when the operation throws. The keyring retains ownership of its internal
   * material; callers never receive a mutable reference to it.
   */
  public withKey<T>(version: number, operation: (kek: Buffer) => T): T {
    const kek = this.resolve(version);
    try {
      return operation(kek);
    } finally {
      kek.fill(0);
    }
  }
}

/**
 * Inspect optional KEK environment values without throwing and without echoing secret values.
 * Used by both the central configuration validator and explicit vault construction.
 */
export function inspectKekEnvironment(env: KekEnvironment): KekEnvironmentInspection {
  const supplied = [env.MASTER_KEK_V1, env.MASTER_KEK_V2, env.ACTIVE_KEK_VERSION].some(
    (value) => value !== undefined,
  );

  if (!supplied) {
    return { status: 'absent' };
  }

  const issues: KekConfigIssue[] = [];
  const decoded = new Map<KekVersion, Buffer>();

  let activeVersion: KekVersion | null = null;
  const rawActiveVersion = env.ACTIVE_KEK_VERSION;
  if (rawActiveVersion === undefined || rawActiveVersion === '') {
    issues.push({ field: 'ACTIVE_KEK_VERSION', message: MISSING_ACTIVE_VERSION_MESSAGE });
  } else if (rawActiveVersion === '1' || rawActiveVersion === '2') {
    activeVersion = rawActiveVersion === '1' ? 1 : 2;
  } else {
    issues.push({ field: 'ACTIVE_KEK_VERSION', message: INVALID_ACTIVE_VERSION_MESSAGE });
  }

  for (const version of SUPPORTED_KEK_VERSIONS) {
    const field: KekField = version === 1 ? 'MASTER_KEK_V1' : 'MASTER_KEK_V2';
    const raw = version === 1 ? env.MASTER_KEK_V1 : env.MASTER_KEK_V2;
    if (raw === undefined) {
      // An absent historical key is allowed; the active-version check below enforces presence
      // whenever that version is actually required. An explicitly supplied empty or
      // whitespace-only value is not absent: it is invalid material and is rejected by decodeKek.
      continue;
    }

    const result = decodeKek(raw);
    if (result.ok) {
      decoded.set(version, result.value);
    } else {
      issues.push({ field, message: INVALID_KEK_MATERIAL_MESSAGE });
    }
  }

  if (activeVersion !== null && !decoded.has(activeVersion)) {
    issues.push({ field: 'ACTIVE_KEK_VERSION', message: MISSING_ACTIVE_KEK_MESSAGE });
  }

  const v1 = decoded.get(1);
  const v2 = decoded.get(2);
  if (v1 !== undefined && v2 !== undefined && v1.equals(v2)) {
    issues.push({ field: 'MASTER_KEK_V2', message: DUPLICATE_KEK_MESSAGE });
  }

  if (issues.length > 0) {
    for (const buffer of decoded.values()) {
      buffer.fill(0);
    }
    return { status: 'invalid', issues };
  }

  if (activeVersion === null) {
    // Defensive: the branch above always records an issue when activeVersion is null.
    for (const buffer of decoded.values()) {
      buffer.fill(0);
    }
    return {
      status: 'invalid',
      issues: [{ field: 'ACTIVE_KEK_VERSION', message: MISSING_ACTIVE_VERSION_MESSAGE }],
    };
  }

  const keys: Partial<Record<KekVersion, Buffer>> = {};
  const v1Key = decoded.get(1);
  const v2Key = decoded.get(2);
  if (v1Key !== undefined) keys[1] = v1Key;
  if (v2Key !== undefined) keys[2] = v2Key;

  try {
    const keyring = new KekKeyring({ activeVersion, keys });
    return { status: 'valid', keyring };
  } finally {
    // KekKeyring owns private copies; transient decode buffers can be cleared.
    for (const buffer of decoded.values()) {
      buffer.fill(0);
    }
  }
}

/**
 * Construct a keyring from environment values. Missing or invalid configuration fails closed with
 * CONFIGURATION_ERROR. No default, development, or placeholder KEK is ever substituted.
 */
export function createKekKeyringFromEnvironment(env: KekEnvironment): KekKeyring {
  const inspection = inspectKekEnvironment(env);
  if (inspection.status === 'absent') {
    throw new VaultError('CONFIGURATION_ERROR', 'KEK configuration is not supplied');
  }
  if (inspection.status === 'invalid') {
    throw new VaultError('CONFIGURATION_ERROR', 'KEK configuration is invalid');
  }
  return inspection.keyring;
}
