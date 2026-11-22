import crypto from 'node:crypto';
import { VaultError } from './errors.js';
import { KekKeyring } from './kek.js';

/**
 * AES-256-GCM provider credential envelope vault (Architecture v1.2 §14.1–§14.3,
 * SW-1.7.1/SW-1.7.2).
 *
 * Storage contract:
 * - Organization DEK: 32 random bytes wrapped under the active versioned KEK.
 *   `wrapped_dek` = 0x01 || AES-GCM ciphertext, with `dek_iv` and `dek_auth_tag` separate.
 * - Provider credential: opaque bytes encrypted under the organization DEK.
 *   `ciphertext` = 0x01 || AES-GCM ciphertext, with `iv` and `auth_tag` separate.
 * - The one-byte marker describes the encrypted blob format; `organizations.kek_version`
 *   remains the authoritative KEK selector.
 */

export const ENVELOPE_FORMAT_VERSION = 0x01;
export const AES_GCM_IV_BYTES = 12;
export const AES_GCM_TAG_BYTES = 16;
export const DEK_BYTES = 32;
export const WRAPPED_DEK_BYTES = 1 + DEK_BYTES;
export const MAX_PROVIDER_CREDENTIAL_BYTES = 4096;

export const SUPPORTED_PROVIDERS = Object.freeze(['openai'] as const);
export type SupportedProvider = (typeof SUPPORTED_PROVIDERS)[number];

export interface OrganizationDekEnvelope {
  readonly kekVersion: number;
  readonly wrappedDek: Buffer;
  readonly dekIv: Buffer;
  readonly dekAuthTag: Buffer;
}

export interface ProviderCredentialEnvelope {
  readonly ciphertext: Buffer;
  readonly iv: Buffer;
  readonly authTag: Buffer;
}

export interface EncryptProviderCredentialParams {
  readonly orgId: string;
  readonly providerKeyId: string;
  readonly provider: string;
  readonly plaintext: Buffer;
  readonly organizationEnvelope: OrganizationDekEnvelope;
}

export interface DecryptProviderCredentialParams {
  readonly orgId: string;
  readonly providerKeyId: string;
  readonly provider: string;
  readonly providerEnvelope: ProviderCredentialEnvelope;
  readonly organizationEnvelope: OrganizationDekEnvelope;
}

const CANONICAL_LOWERCASE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const INVALID_ORG_ID_MESSAGE = 'Invalid organization identifier';
const INVALID_PROVIDER_KEY_ID_MESSAGE = 'Invalid provider-key identifier';
const INVALID_ORGANIZATION_ENVELOPE_MESSAGE = 'Invalid organization DEK envelope';
const INVALID_PROVIDER_ENVELOPE_MESSAGE = 'Invalid provider credential envelope';

function assertCanonicalUuid(value: unknown, message: string): string {
  if (typeof value !== 'string' || !CANONICAL_LOWERCASE_UUID.test(value)) {
    throw new VaultError('INVALID_INPUT', message);
  }
  return value;
}

function assertOrganizationId(value: unknown): string {
  return assertCanonicalUuid(value, INVALID_ORG_ID_MESSAGE);
}

function assertProviderKeyId(value: unknown): string {
  return assertCanonicalUuid(value, INVALID_PROVIDER_KEY_ID_MESSAGE);
}

function assertSupportedProvider(value: unknown): SupportedProvider {
  if (value !== 'openai') {
    throw new VaultError('INVALID_INPUT', 'Unsupported provider identifier');
  }
  return value;
}

function assertPlaintext(value: unknown): Buffer {
  if (!Buffer.isBuffer(value)) {
    throw new VaultError('INVALID_INPUT', 'Provider credential must be a Buffer');
  }
  if (value.length === 0) {
    throw new VaultError('INVALID_INPUT', 'Provider credential must not be empty');
  }
  if (value.length > MAX_PROVIDER_CREDENTIAL_BYTES) {
    throw new VaultError(
      'INVALID_INPUT',
      `Provider credential must not exceed ${MAX_PROVIDER_CREDENTIAL_BYTES} bytes`,
    );
  }
  return value;
}

function assertOrganizationEnvelope(value: unknown): OrganizationDekEnvelope {
  if (typeof value !== 'object' || value === null) {
    throw new VaultError('UNSUPPORTED_FORMAT', INVALID_ORGANIZATION_ENVELOPE_MESSAGE);
  }
  const envelope = value as Partial<OrganizationDekEnvelope>;
  if (!Buffer.isBuffer(envelope.wrappedDek) || envelope.wrappedDek.length !== WRAPPED_DEK_BYTES) {
    throw new VaultError('UNSUPPORTED_FORMAT', INVALID_ORGANIZATION_ENVELOPE_MESSAGE);
  }
  if (envelope.wrappedDek[0] !== ENVELOPE_FORMAT_VERSION) {
    throw new VaultError('UNSUPPORTED_FORMAT', 'Unsupported organization DEK format version');
  }
  if (!Buffer.isBuffer(envelope.dekIv) || envelope.dekIv.length !== AES_GCM_IV_BYTES) {
    throw new VaultError('UNSUPPORTED_FORMAT', INVALID_ORGANIZATION_ENVELOPE_MESSAGE);
  }
  if (!Buffer.isBuffer(envelope.dekAuthTag) || envelope.dekAuthTag.length !== AES_GCM_TAG_BYTES) {
    throw new VaultError('UNSUPPORTED_FORMAT', INVALID_ORGANIZATION_ENVELOPE_MESSAGE);
  }
  if (
    typeof envelope.kekVersion !== 'number' ||
    !Number.isInteger(envelope.kekVersion) ||
    envelope.kekVersion <= 0
  ) {
    throw new VaultError('UNSUPPORTED_FORMAT', 'Invalid stored KEK version');
  }
  return {
    kekVersion: envelope.kekVersion,
    wrappedDek: envelope.wrappedDek,
    dekIv: envelope.dekIv,
    dekAuthTag: envelope.dekAuthTag,
  };
}

function assertProviderEnvelope(value: unknown): ProviderCredentialEnvelope {
  if (typeof value !== 'object' || value === null) {
    throw new VaultError('UNSUPPORTED_FORMAT', INVALID_PROVIDER_ENVELOPE_MESSAGE);
  }
  const envelope = value as Partial<ProviderCredentialEnvelope>;
  if (
    !Buffer.isBuffer(envelope.ciphertext) ||
    envelope.ciphertext.length < 2 ||
    envelope.ciphertext.length > MAX_PROVIDER_CREDENTIAL_BYTES + 1
  ) {
    throw new VaultError('UNSUPPORTED_FORMAT', INVALID_PROVIDER_ENVELOPE_MESSAGE);
  }
  if (envelope.ciphertext[0] !== ENVELOPE_FORMAT_VERSION) {
    throw new VaultError('UNSUPPORTED_FORMAT', 'Unsupported provider credential format version');
  }
  if (!Buffer.isBuffer(envelope.iv) || envelope.iv.length !== AES_GCM_IV_BYTES) {
    throw new VaultError('UNSUPPORTED_FORMAT', INVALID_PROVIDER_ENVELOPE_MESSAGE);
  }
  if (!Buffer.isBuffer(envelope.authTag) || envelope.authTag.length !== AES_GCM_TAG_BYTES) {
    throw new VaultError('UNSUPPORTED_FORMAT', INVALID_PROVIDER_ENVELOPE_MESSAGE);
  }
  return {
    ciphertext: envelope.ciphertext,
    iv: envelope.iv,
    authTag: envelope.authTag,
  };
}

function dekAad(orgId: string, kekVersion: number): Buffer {
  return Buffer.from(`dek:${orgId}:v${kekVersion}`, 'utf8');
}

function providerAad(orgId: string, providerKeyId: string, provider: string): Buffer {
  return Buffer.from(`pk:${orgId}:${providerKeyId}:${provider}`, 'utf8');
}

export class EnvelopeVault {
  private readonly keyring: KekKeyring;

  constructor(keyring: KekKeyring) {
    if (!(keyring instanceof KekKeyring)) {
      throw new VaultError('CONFIGURATION_ERROR', 'A valid KEK keyring is required');
    }
    this.keyring = keyring;
  }

  /**
   * Generate a fresh organization DEK and return only its encrypted envelope. The plaintext DEK
   * never appears in the returned value.
   */
  public createOrganizationEnvelope(orgId: string): OrganizationDekEnvelope {
    const trustedOrgId = assertOrganizationId(orgId);
    const kekVersion = this.keyring.activeVersion;

    return this.keyring.withKey(kekVersion, (kek) => {
      const dek = crypto.randomBytes(DEK_BYTES);
      try {
        const iv = crypto.randomBytes(AES_GCM_IV_BYTES);
        const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv, {
          authTagLength: AES_GCM_TAG_BYTES,
        });
        cipher.setAAD(dekAad(trustedOrgId, kekVersion));
        const encrypted = Buffer.concat([cipher.update(dek), cipher.final()]);
        const authTag = cipher.getAuthTag();

        if (
          encrypted.length !== DEK_BYTES ||
          iv.length !== AES_GCM_IV_BYTES ||
          authTag.length !== AES_GCM_TAG_BYTES
        ) {
          throw new VaultError('CONFIGURATION_ERROR', 'Organization DEK wrapping failed');
        }

        return {
          kekVersion,
          wrappedDek: Buffer.concat([Buffer.from([ENVELOPE_FORMAT_VERSION]), encrypted]),
          dekIv: iv,
          dekAuthTag: authTag,
        };
      } finally {
        dek.fill(0);
      }
    });
  }

  /**
   * Encrypt an opaque provider credential under the organization's authenticated DEK envelope.
   * The caller owns the plaintext input Buffer and must clear it after authorised use.
   */
  public encryptProviderCredential(
    params: EncryptProviderCredentialParams,
  ): ProviderCredentialEnvelope {
    const orgId = assertOrganizationId(params.orgId);
    const providerKeyId = assertProviderKeyId(params.providerKeyId);
    const provider = assertSupportedProvider(params.provider);
    const plaintext = assertPlaintext(params.plaintext);

    const dek = this.unwrapOrganizationDek(orgId, params.organizationEnvelope);
    try {
      const iv = crypto.randomBytes(AES_GCM_IV_BYTES);
      const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv, {
        authTagLength: AES_GCM_TAG_BYTES,
      });
      cipher.setAAD(providerAad(orgId, providerKeyId, provider));
      const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const authTag = cipher.getAuthTag();

      if (iv.length !== AES_GCM_IV_BYTES || authTag.length !== AES_GCM_TAG_BYTES) {
        throw new VaultError('CONFIGURATION_ERROR', 'Provider credential encryption failed');
      }

      return {
        ciphertext: Buffer.concat([Buffer.from([ENVELOPE_FORMAT_VERSION]), encrypted]),
        iv,
        authTag,
      };
    } finally {
      dek.fill(0);
    }
  }

  /**
   * Authenticated provider credential decryption. Plaintext is returned only after AES-GCM
   * authentication succeeds; the caller owns the returned Buffer and must clear it after use.
   */
  public decryptProviderCredential(params: DecryptProviderCredentialParams): Buffer {
    const orgId = assertOrganizationId(params.orgId);
    const providerKeyId = assertProviderKeyId(params.providerKeyId);
    const provider = assertSupportedProvider(params.provider);
    const providerEnvelope = assertProviderEnvelope(params.providerEnvelope);

    const dek = this.unwrapOrganizationDek(orgId, params.organizationEnvelope);
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', dek, providerEnvelope.iv, {
        authTagLength: AES_GCM_TAG_BYTES,
      });
      decipher.setAAD(providerAad(orgId, providerKeyId, provider));
      decipher.setAuthTag(providerEnvelope.authTag);

      const chunks: Buffer[] = [];
      try {
        chunks.push(decipher.update(providerEnvelope.ciphertext.subarray(1)));
        chunks.push(decipher.final());
        // Buffer.concat allocates the caller-owned result before the finally block clears the
        // redundant intermediate chunks.
        return Buffer.concat(chunks);
      } catch {
        throw new VaultError('AUTHENTICATION_FAILED', 'Provider credential authentication failed');
      } finally {
        for (const chunk of chunks) {
          chunk.fill(0);
        }
      }
    } finally {
      dek.fill(0);
    }
  }

  /**
   * Internal authenticated unwrap. The raw DEK is never exposed through a public result object;
   * it is consumed by the provider encrypt/decrypt operations and cleared afterwards.
   */
  private unwrapOrganizationDek(
    orgId: string,
    organizationEnvelope: OrganizationDekEnvelope,
  ): Buffer {
    const envelope = assertOrganizationEnvelope(organizationEnvelope);

    return this.keyring.withKey(envelope.kekVersion, (kek) => {
      const decipher = crypto.createDecipheriv('aes-256-gcm', kek, envelope.dekIv, {
        authTagLength: AES_GCM_TAG_BYTES,
      });
      decipher.setAAD(dekAad(orgId, envelope.kekVersion));
      decipher.setAuthTag(envelope.dekAuthTag);

      const chunks: Buffer[] = [];
      try {
        chunks.push(decipher.update(envelope.wrappedDek.subarray(1)));
        chunks.push(decipher.final());
        // Buffer.concat allocates the returned DEK before the finally block clears the redundant
        // intermediate chunks.
        const dek = Buffer.concat(chunks);
        if (dek.length !== DEK_BYTES) {
          dek.fill(0);
          throw new VaultError('AUTHENTICATION_FAILED', 'Organization DEK authentication failed');
        }
        return dek;
      } catch {
        throw new VaultError('AUTHENTICATION_FAILED', 'Organization DEK authentication failed');
      } finally {
        for (const chunk of chunks) {
          chunk.fill(0);
        }
      }
    });
  }
}
