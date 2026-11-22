import crypto from 'node:crypto';
import { Writable } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';
import { createLogger } from '../logging/index.js';
import {
  AES_GCM_IV_BYTES,
  AES_GCM_TAG_BYTES,
  DEK_BYTES,
  EnvelopeVault,
  ENVELOPE_FORMAT_VERSION,
  MAX_PROVIDER_CREDENTIAL_BYTES,
  WRAPPED_DEK_BYTES,
  type OrganizationDekEnvelope,
  type ProviderCredentialEnvelope,
} from './envelope.js';
import { VaultError, type VaultErrorReason } from './errors.js';
import { KekKeyring, type KekVersion } from './kek.js';

const KEK_V1 = crypto.randomBytes(32);
const KEK_V2 = crypto.randomBytes(32);

const ORG_A = '11111111-1111-4111-8111-111111111111';
const ORG_B = '22222222-2222-4222-8222-222222222222';
const PROVIDER_KEY_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const PROVIDER_KEY_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

const CANARY = Buffer.from('sk-synthetic-canary-provider-credential-0123456789', 'utf8');

function createVault(
  activeVersion: KekVersion,
  options: { includeV1?: boolean; includeV2?: boolean } = {},
): EnvelopeVault {
  const { includeV1 = true, includeV2 = true } = options;
  const keys: Partial<Record<KekVersion, Buffer>> = {};
  if (includeV1) keys[1] = KEK_V1;
  if (includeV2) keys[2] = KEK_V2;
  return new EnvelopeVault(new KekKeyring({ activeVersion, keys }));
}

function cloneOrgEnvelope(envelope: OrganizationDekEnvelope): {
  kekVersion: number;
  wrappedDek: Buffer;
  dekIv: Buffer;
  dekAuthTag: Buffer;
} {
  return {
    kekVersion: envelope.kekVersion,
    wrappedDek: Buffer.from(envelope.wrappedDek),
    dekIv: Buffer.from(envelope.dekIv),
    dekAuthTag: Buffer.from(envelope.dekAuthTag),
  };
}

function cloneProviderEnvelope(envelope: ProviderCredentialEnvelope): {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
} {
  return {
    ciphertext: Buffer.from(envelope.ciphertext),
    iv: Buffer.from(envelope.iv),
    authTag: Buffer.from(envelope.authTag),
  };
}

function providerEnvelopeWithCiphertextLength(length: number): ProviderCredentialEnvelope {
  const ciphertext =
    length === 1
      ? Buffer.alloc(1, ENVELOPE_FORMAT_VERSION)
      : Buffer.concat([Buffer.from([ENVELOPE_FORMAT_VERSION]), Buffer.alloc(length - 1, 0x41)]);
  return {
    ciphertext,
    iv: Buffer.alloc(AES_GCM_IV_BYTES, 1),
    authTag: Buffer.alloc(AES_GCM_TAG_BYTES, 2),
  };
}

type GcmDecipher = ReturnType<typeof crypto.createDecipheriv> & {
  setAAD(aad: Buffer): GcmDecipher;
};

interface CapturedDecipherChunks {
  dekUnwrap: Buffer[];
  providerDecrypt: Buffer[];
  restore: () => void;
}

function captureDecipherChunksByOperation(): CapturedDecipherChunks {
  const dekUnwrap: Buffer[] = [];
  const providerDecrypt: Buffer[] = [];
  const realCreateDecipheriv = crypto.createDecipheriv;
  const spy = vi
    .spyOn(crypto, 'createDecipheriv')
    .mockImplementation((algorithm, key, iv, options) => {
      const decipher = realCreateDecipheriv(algorithm, key, iv, options) as GcmDecipher;
      let operationChunks: Buffer[] | null = null;

      return new Proxy(decipher, {
        get(target, property, receiver) {
          if (property === 'setAAD') {
            return (aad: Buffer) => {
              // Production AAD is `dek:<orgId>:v<kekVersion>` for DEK unwrapping and
              // `pk:<orgId>:<providerKeyId>:<provider>` for provider-credential decryption.
              const prefix = aad.toString('utf8', 0, 4);
              if (prefix.startsWith('dek:')) {
                operationChunks = dekUnwrap;
              } else if (prefix.startsWith('pk:')) {
                operationChunks = providerDecrypt;
              } else {
                throw new Error('Unexpected vault AAD prefix in test instrumentation');
              }
              return target.setAAD(aad);
            };
          }
          if (property === 'update') {
            return (data: Buffer) => {
              const chunks = operationChunks;
              if (chunks === null) {
                throw new Error('Vault decipher update before setAAD');
              }
              const output = target.update(data);
              chunks.push(output);
              return output;
            };
          }
          if (property === 'final') {
            return () => {
              const chunks = operationChunks;
              if (chunks === null) {
                throw new Error('Vault decipher final before setAAD');
              }
              const output = target.final();
              chunks.push(output);
              return output;
            };
          }
          return Reflect.get(target, property, receiver);
        },
      });
    });
  return { dekUnwrap, providerDecrypt, restore: () => spy.mockRestore() };
}

function independentUnwrapDek(
  orgId: string,
  envelope: OrganizationDekEnvelope,
  kek: Buffer,
): Buffer {
  const decipher = crypto.createDecipheriv('aes-256-gcm', kek, envelope.dekIv, {
    authTagLength: AES_GCM_TAG_BYTES,
  });
  decipher.setAAD(Buffer.from(`dek:${orgId}:v${envelope.kekVersion}`, 'utf8'));
  decipher.setAuthTag(envelope.dekAuthTag);
  return Buffer.concat([decipher.update(envelope.wrappedDek.subarray(1)), decipher.final()]);
}

function independentEncryptProvider(
  dek: Buffer,
  orgId: string,
  providerKeyId: string,
  provider: string,
  plaintext: Buffer,
): ProviderCredentialEnvelope {
  const iv = crypto.randomBytes(AES_GCM_IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv, {
    authTagLength: AES_GCM_TAG_BYTES,
  });
  cipher.setAAD(Buffer.from(`pk:${orgId}:${providerKeyId}:${provider}`, 'utf8'));
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    ciphertext: Buffer.concat([Buffer.from([ENVELOPE_FORMAT_VERSION]), encrypted]),
    iv,
    authTag: cipher.getAuthTag(),
  };
}

function expectVaultError(fn: () => unknown, reason: VaultErrorReason): VaultError {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VaultError);
    const vaultError = error as VaultError;
    expect(vaultError.reason).toBe(reason);
    return vaultError;
  }
  expect.fail(`expected VaultError(${reason})`);
}

function encryptWithVault(
  vault: EnvelopeVault,
  orgId: string,
  envelope: OrganizationDekEnvelope,
  plaintext: Buffer = CANARY,
  providerKeyId: string = PROVIDER_KEY_A,
): ProviderCredentialEnvelope {
  return vault.encryptProviderCredential({
    orgId,
    providerKeyId,
    provider: 'openai',
    plaintext,
    organizationEnvelope: envelope,
  });
}

describe('SW-1.7.1 organization DEK wrapping', () => {
  it('wraps a fresh 32-byte DEK with the V1 marker, 12-byte IV and 16-byte tag', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);

    expect(envelope.kekVersion).toBe(1);
    expect(envelope.wrappedDek).toHaveLength(WRAPPED_DEK_BYTES);
    expect(envelope.wrappedDek[0]).toBe(ENVELOPE_FORMAT_VERSION);
    expect(envelope.dekIv).toHaveLength(AES_GCM_IV_BYTES);
    expect(envelope.dekAuthTag).toHaveLength(AES_GCM_TAG_BYTES);

    const dek = independentUnwrapDek(ORG_A, envelope, KEK_V1);
    expect(dek).toHaveLength(DEK_BYTES);
    dek.fill(0);
  });

  it('generates independent random DEKs for different organizations', () => {
    const vault = createVault(1);
    const envelopeA = vault.createOrganizationEnvelope(ORG_A);
    const envelopeB = vault.createOrganizationEnvelope(ORG_B);

    const dekA = independentUnwrapDek(ORG_A, envelopeA, KEK_V1);
    const dekB = independentUnwrapDek(ORG_B, envelopeB, KEK_V1);
    expect(dekA.equals(dekB)).toBe(false);
    dekA.fill(0);
    dekB.fill(0);
  });

  it('authenticates with the correct KEK and exact organization AAD', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);
    const providerEnvelope = encryptWithVault(vault, ORG_A, envelope);
    const plaintext = vault.decryptProviderCredential({
      orgId: ORG_A,
      providerKeyId: PROVIDER_KEY_A,
      provider: 'openai',
      providerEnvelope,
      organizationEnvelope: envelope,
    });
    expect(plaintext.equals(CANARY)).toBe(true);
    plaintext.fill(0);
  });

  it('rejects the wrong organization (AAD mismatch)', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);
    expectVaultError(() => encryptWithVault(vault, ORG_B, envelope), 'AUTHENTICATION_FAILED');
  });

  it('rejects a wrong stored KEK version and a missing historical KEK', () => {
    const v1Envelope = createVault(1).createOrganizationEnvelope(ORG_A);

    const v2OnlyVault = createVault(2, { includeV1: false, includeV2: true });
    expectVaultError(() => encryptWithVault(v2OnlyVault, ORG_A, v1Envelope), 'UNKNOWN_KEK_VERSION');

    const activeV2 = createVault(2);
    const forgedVersion = cloneOrgEnvelope(v1Envelope);
    forgedVersion.kekVersion = 2;
    expectVaultError(
      () => encryptWithVault(activeV2, ORG_A, forgedVersion),
      'AUTHENTICATION_FAILED',
    );
  });

  it('rejects tampered wrapped ciphertext, IV and authentication tag', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);

    const tamperedCiphertext = cloneOrgEnvelope(envelope);
    tamperedCiphertext.wrappedDek[1] = (tamperedCiphertext.wrappedDek[1] as number) ^ 0xff;
    expectVaultError(
      () => encryptWithVault(vault, ORG_A, tamperedCiphertext),
      'AUTHENTICATION_FAILED',
    );

    const tamperedIv = cloneOrgEnvelope(envelope);
    tamperedIv.dekIv[0] = (tamperedIv.dekIv[0] as number) ^ 0xff;
    expectVaultError(() => encryptWithVault(vault, ORG_A, tamperedIv), 'AUTHENTICATION_FAILED');

    const tamperedTag = cloneOrgEnvelope(envelope);
    tamperedTag.dekAuthTag[0] = (tamperedTag.dekAuthTag[0] as number) ^ 0xff;
    expectVaultError(() => encryptWithVault(vault, ORG_A, tamperedTag), 'AUTHENTICATION_FAILED');
  });

  it('rejects unknown formats and malformed envelope lengths', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);

    const unknownFormat = cloneOrgEnvelope(envelope);
    unknownFormat.wrappedDek[0] = 0x02;
    expectVaultError(() => encryptWithVault(vault, ORG_A, unknownFormat), 'UNSUPPORTED_FORMAT');

    const truncatedDek = cloneOrgEnvelope(envelope);
    truncatedDek.wrappedDek = truncatedDek.wrappedDek.subarray(0, 10);
    expectVaultError(() => encryptWithVault(vault, ORG_A, truncatedDek), 'UNSUPPORTED_FORMAT');

    const badIv = cloneOrgEnvelope(envelope);
    badIv.dekIv = Buffer.alloc(11);
    expectVaultError(() => encryptWithVault(vault, ORG_A, badIv), 'UNSUPPORTED_FORMAT');

    const badTag = cloneOrgEnvelope(envelope);
    badTag.dekAuthTag = Buffer.alloc(15);
    expectVaultError(() => encryptWithVault(vault, ORG_A, badTag), 'UNSUPPORTED_FORMAT');

    const badVersion = cloneOrgEnvelope(envelope);
    badVersion.kekVersion = 0;
    expectVaultError(() => encryptWithVault(vault, ORG_A, badVersion), 'UNSUPPORTED_FORMAT');
  });

  it('never returns cleartext DEK material in the organization envelope', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);
    const dek = independentUnwrapDek(ORG_A, envelope, KEK_V1);

    expect(Object.keys(envelope).sort()).toEqual([
      'dekAuthTag',
      'dekIv',
      'kekVersion',
      'wrappedDek',
    ]);
    expect(envelope.wrappedDek.includes(dek)).toBe(false);
    expect(envelope.dekIv.includes(dek)).toBe(false);
    expect(envelope.dekAuthTag.includes(dek)).toBe(false);
    expect(JSON.stringify(envelope)).not.toContain(dek.toString('base64url'));
    dek.fill(0);
  });

  it('does not regenerate an organization DEK after a failed unwrap', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);
    const before = independentUnwrapDek(ORG_A, envelope, KEK_V1);

    const tampered = cloneOrgEnvelope(envelope);
    tampered.wrappedDek[1] = (tampered.wrappedDek[1] as number) ^ 0xff;
    expectVaultError(() => encryptWithVault(vault, ORG_A, tampered), 'AUTHENTICATION_FAILED');

    const after = independentUnwrapDek(ORG_A, envelope, KEK_V1);
    expect(before.equals(after)).toBe(true);
    before.fill(0);
    after.fill(0);
  });

  it('supports V1 history after switching the active KEK to V2', () => {
    const v1Vault = createVault(1);
    const v1Envelope = v1Vault.createOrganizationEnvelope(ORG_A);
    const v1Provider = encryptWithVault(v1Vault, ORG_A, v1Envelope);

    const activeV2 = createVault(2);
    const stillReadable = activeV2.decryptProviderCredential({
      orgId: ORG_A,
      providerKeyId: PROVIDER_KEY_A,
      provider: 'openai',
      providerEnvelope: v1Provider,
      organizationEnvelope: v1Envelope,
    });
    expect(stillReadable.equals(CANARY)).toBe(true);
    stillReadable.fill(0);

    const v2Envelope = activeV2.createOrganizationEnvelope(ORG_B);
    expect(v2Envelope.kekVersion).toBe(2);

    const missingV1 = createVault(2, { includeV1: false, includeV2: true });
    expectVaultError(() => encryptWithVault(missingV1, ORG_A, v1Envelope), 'UNKNOWN_KEK_VERSION');

    const v2Provider = encryptWithVault(activeV2, ORG_B, v2Envelope);
    const v2Plaintext = missingV1.decryptProviderCredential({
      orgId: ORG_B,
      providerKeyId: PROVIDER_KEY_A,
      provider: 'openai',
      providerEnvelope: v2Provider,
      organizationEnvelope: v2Envelope,
    });
    expect(v2Plaintext.equals(CANARY)).toBe(true);
    v2Plaintext.fill(0);
  });

  it('rejects malformed and noncanonical organization identifiers', () => {
    const vault = createVault(1);
    for (const orgId of [
      '',
      'not-a-uuid',
      'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA',
      '11111111-1111-4111-8111-11111111111',
      ` ${ORG_A}`,
    ]) {
      expectVaultError(() => vault.createOrganizationEnvelope(orgId), 'INVALID_INPUT');
    }
  });
});

describe('SW-1.7.2 provider credential encryption', () => {
  it('round-trips text and arbitrary binary bytes exactly', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);

    const text = Buffer.from('sk-synthetic-openai-credential-value', 'utf8');
    const textCiphertext = encryptWithVault(vault, ORG_A, envelope, text);
    const textPlaintext = vault.decryptProviderCredential({
      orgId: ORG_A,
      providerKeyId: PROVIDER_KEY_A,
      provider: 'openai',
      providerEnvelope: textCiphertext,
      organizationEnvelope: envelope,
    });
    expect(textPlaintext.equals(text)).toBe(true);
    textPlaintext.fill(0);

    const binary = Buffer.from(Array.from({ length: 256 }, (_, index) => index));
    const binaryCiphertext = encryptWithVault(vault, ORG_A, envelope, binary);
    const binaryPlaintext = vault.decryptProviderCredential({
      orgId: ORG_A,
      providerKeyId: PROVIDER_KEY_A,
      provider: 'openai',
      providerEnvelope: binaryCiphertext,
      organizationEnvelope: envelope,
    });
    expect(binaryPlaintext.equals(binary)).toBe(true);
    binaryPlaintext.fill(0);
  });

  it('uses a fresh 12-byte IV and distinct ciphertext for every encryption', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);

    const first = encryptWithVault(vault, ORG_A, envelope);
    const second = encryptWithVault(vault, ORG_A, envelope);

    expect(first.iv).toHaveLength(AES_GCM_IV_BYTES);
    expect(second.iv).toHaveLength(AES_GCM_IV_BYTES);
    expect(first.iv.equals(second.iv)).toBe(false);
    expect(first.ciphertext.equals(second.ciphertext)).toBe(false);
    expect(first.authTag).toHaveLength(AES_GCM_TAG_BYTES);
    expect(second.authTag).toHaveLength(AES_GCM_TAG_BYTES);
    expect(first.ciphertext[0]).toBe(ENVELOPE_FORMAT_VERSION);
    expect(first.ciphertext.length).toBe(CANARY.length + 1);
  });

  it('decrypts V1 provider ciphertext after the active KEK moves to V2', () => {
    const v1Vault = createVault(1);
    const v1Envelope = v1Vault.createOrganizationEnvelope(ORG_A);
    const providerEnvelope = encryptWithVault(v1Vault, ORG_A, v1Envelope);

    const activeV2 = createVault(2);
    const plaintext = activeV2.decryptProviderCredential({
      orgId: ORG_A,
      providerKeyId: PROVIDER_KEY_A,
      provider: 'openai',
      providerEnvelope,
      organizationEnvelope: v1Envelope,
    });
    expect(plaintext.equals(CANARY)).toBe(true);
    plaintext.fill(0);
  });

  it('binds ciphertext to the organization, provider-key record and provider identifier', () => {
    const vault = createVault(1);
    const envelopeA = vault.createOrganizationEnvelope(ORG_A);
    const envelopeB = vault.createOrganizationEnvelope(ORG_B);
    const providerEnvelope = encryptWithVault(vault, ORG_A, envelopeA);

    expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_B,
          provider: 'openai',
          providerEnvelope,
          organizationEnvelope: envelopeA,
        }),
      'AUTHENTICATION_FAILED',
    );

    expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_B,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope,
          organizationEnvelope: envelopeB,
        }),
      'AUTHENTICATION_FAILED',
    );

    // A ciphertext produced under a different provider AAD cannot authenticate as openai.
    const dek = independentUnwrapDek(ORG_A, envelopeA, KEK_V1);
    const anthropicBound = independentEncryptProvider(
      dek,
      ORG_A,
      PROVIDER_KEY_A,
      'anthropic',
      CANARY,
    );
    dek.fill(0);
    expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope: anthropicBound,
          organizationEnvelope: envelopeA,
        }),
      'AUTHENTICATION_FAILED',
    );

    // Unsupported provider metadata is rejected before any decryption attempt.
    expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'anthropic',
          providerEnvelope,
          organizationEnvelope: envelopeA,
        }),
      'INVALID_INPUT',
    );
  });

  it('rejects cross-tenant ciphertext relocation and mismatched organization envelopes', () => {
    const vault = createVault(1);
    const envelopeA = vault.createOrganizationEnvelope(ORG_A);
    const envelopeB = vault.createOrganizationEnvelope(ORG_B);
    const providerEnvelope = encryptWithVault(vault, ORG_A, envelopeA);

    expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_B,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope,
          organizationEnvelope: envelopeB,
        }),
      'AUTHENTICATION_FAILED',
    );

    expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope,
          organizationEnvelope: envelopeB,
        }),
      'AUTHENTICATION_FAILED',
    );
  });

  it('rejects empty, oversized and non-Buffer plaintext', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);

    expectVaultError(
      () => encryptWithVault(vault, ORG_A, envelope, Buffer.alloc(0)),
      'INVALID_INPUT',
    );
    expectVaultError(
      () =>
        encryptWithVault(
          vault,
          ORG_A,
          envelope,
          Buffer.alloc(MAX_PROVIDER_CREDENTIAL_BYTES + 1, 1),
        ),
      'INVALID_INPUT',
    );
    expectVaultError(
      () =>
        vault.encryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          plaintext: 'not-a-buffer' as unknown as Buffer,
          organizationEnvelope: envelope,
        }),
      'INVALID_INPUT',
    );
  });

  it('rejects unsupported providers and malformed identifiers', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);

    for (const provider of ['anthropic', 'gemini', 'azure', 'openrouter', 'OpenAI', '']) {
      expectVaultError(
        () =>
          vault.encryptProviderCredential({
            orgId: ORG_A,
            providerKeyId: PROVIDER_KEY_A,
            provider,
            plaintext: CANARY,
            organizationEnvelope: envelope,
          }),
        'INVALID_INPUT',
      );
    }

    for (const orgId of ['', 'not-a-uuid', 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA']) {
      expectVaultError(() => encryptWithVault(vault, orgId, envelope), 'INVALID_INPUT');
    }
    for (const providerKeyId of ['', 'not-a-uuid', PROVIDER_KEY_A.toUpperCase()]) {
      expectVaultError(
        () =>
          vault.encryptProviderCredential({
            orgId: ORG_A,
            providerKeyId,
            provider: 'openai',
            plaintext: CANARY,
            organizationEnvelope: envelope,
          }),
        'INVALID_INPUT',
      );
    }
  });

  it('rejects unknown formats, truncated ciphertext, and incorrect IV/tag lengths', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);
    const providerEnvelope = encryptWithVault(vault, ORG_A, envelope);

    const unknownFormat = cloneProviderEnvelope(providerEnvelope);
    unknownFormat.ciphertext[0] = 0x02;
    expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope: unknownFormat,
          organizationEnvelope: envelope,
        }),
      'UNSUPPORTED_FORMAT',
    );

    const truncated = cloneProviderEnvelope(providerEnvelope);
    truncated.ciphertext = truncated.ciphertext.subarray(0, 1);
    expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope: truncated,
          organizationEnvelope: envelope,
        }),
      'UNSUPPORTED_FORMAT',
    );

    const badIv = cloneProviderEnvelope(providerEnvelope);
    badIv.iv = Buffer.alloc(11);
    expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope: badIv,
          organizationEnvelope: envelope,
        }),
      'UNSUPPORTED_FORMAT',
    );

    const badTag = cloneProviderEnvelope(providerEnvelope);
    badTag.authTag = Buffer.alloc(15);
    expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope: badTag,
          organizationEnvelope: envelope,
        }),
      'UNSUPPORTED_FORMAT',
    );
  });

  it('rejects tampered ciphertext, IV and authentication tag', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);
    const providerEnvelope = encryptWithVault(vault, ORG_A, envelope);

    const tamperedCiphertext = cloneProviderEnvelope(providerEnvelope);
    tamperedCiphertext.ciphertext[1] = (tamperedCiphertext.ciphertext[1] as number) ^ 0xff;
    expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope: tamperedCiphertext,
          organizationEnvelope: envelope,
        }),
      'AUTHENTICATION_FAILED',
    );

    const tamperedIv = cloneProviderEnvelope(providerEnvelope);
    tamperedIv.iv[0] = (tamperedIv.iv[0] as number) ^ 0xff;
    expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope: tamperedIv,
          organizationEnvelope: envelope,
        }),
      'AUTHENTICATION_FAILED',
    );

    const tamperedTag = cloneProviderEnvelope(providerEnvelope);
    tamperedTag.authTag[0] = (tamperedTag.authTag[0] as number) ^ 0xff;
    expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope: tamperedTag,
          organizationEnvelope: envelope,
        }),
      'AUTHENTICATION_FAILED',
    );
  });

  it('rejects missing KEKs and invalid wrapped DEK envelopes', () => {
    const v1Vault = createVault(1);
    const v1Envelope = v1Vault.createOrganizationEnvelope(ORG_A);
    const providerEnvelope = encryptWithVault(v1Vault, ORG_A, v1Envelope);

    const missingV1 = createVault(2, { includeV1: false, includeV2: true });
    expectVaultError(
      () =>
        missingV1.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope,
          organizationEnvelope: v1Envelope,
        }),
      'UNKNOWN_KEK_VERSION',
    );

    const invalidWrapped = cloneOrgEnvelope(v1Envelope);
    invalidWrapped.wrappedDek = Buffer.alloc(WRAPPED_DEK_BYTES, 1);
    invalidWrapped.wrappedDek[0] = ENVELOPE_FORMAT_VERSION;
    expectVaultError(
      () =>
        v1Vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope,
          organizationEnvelope: invalidWrapped,
        }),
      'AUTHENTICATION_FAILED',
    );
  });

  it('never exposes plaintext, DEK material or ciphertext in results and errors', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);
    const providerEnvelope = encryptWithVault(vault, ORG_A, envelope);
    const canaryText = CANARY.toString('utf8');

    expect(Object.keys(providerEnvelope).sort()).toEqual(['authTag', 'ciphertext', 'iv']);
    expect(providerEnvelope.ciphertext.includes(CANARY)).toBe(false);
    expect(JSON.stringify(providerEnvelope)).not.toContain(canaryText);

    const tampered = cloneProviderEnvelope(providerEnvelope);
    tampered.authTag[0] = (tampered.authTag[0] as number) ^ 0xff;
    const error = expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope: tampered,
          organizationEnvelope: envelope,
        }),
      'AUTHENTICATION_FAILED',
    );
    expect(error.message).not.toContain(canaryText);
    expect(JSON.stringify(error)).not.toContain(canaryText);
  });

  it('never emits provider credential canaries through Pino', () => {
    let raw = '';
    const stream = new Writable({
      write(chunk, _encoding, callback) {
        raw += chunk.toString();
        callback();
      },
    });
    const logger = createLogger({ stream });
    const canaryText = CANARY.toString('utf8');

    logger.info(
      {
        providerApiKey: canaryText,
        plaintext: canaryText,
        providerCredential: canaryText,
        nested: { credential: canaryText },
      },
      'Synthetic provider credential operation',
    );

    expect(raw).not.toContain(canaryText);
    expect(raw).toContain('[REDACTED]');
  });
});

describe('SW-1.7.1/SW-1.7.2 remediation', () => {
  it('keeps working after a caller mutates a resolved KEK copy', () => {
    const keyring = new KekKeyring({ activeVersion: 1, keys: { 1: Buffer.from(KEK_V1) } });
    const vault = new EnvelopeVault(keyring);
    const envelope = vault.createOrganizationEnvelope(ORG_A);

    const resolved = keyring.resolve(1);
    resolved.fill(0xff);
    resolved.fill(0);

    const providerEnvelope = encryptWithVault(vault, ORG_A, envelope);
    const plaintext = vault.decryptProviderCredential({
      orgId: ORG_A,
      providerKeyId: PROVIDER_KEY_A,
      provider: 'openai',
      providerEnvelope,
      organizationEnvelope: envelope,
    });
    expect(plaintext.equals(CANARY)).toBe(true);
    plaintext.fill(0);
  });

  it('clears temporary KEK copies after successful and failed vault operations', () => {
    const keyring = new KekKeyring({ activeVersion: 1, keys: { 1: Buffer.from(KEK_V1) } });
    const vault = new EnvelopeVault(keyring);
    const resolvedCopies: Buffer[] = [];
    const realResolve = keyring.resolve.bind(keyring);
    const spy = vi.spyOn(keyring, 'resolve').mockImplementation((version) => {
      const copy = realResolve(version);
      resolvedCopies.push(copy);
      return copy;
    });

    try {
      const envelope = vault.createOrganizationEnvelope(ORG_A);
      expect(resolvedCopies).toHaveLength(1);
      expect(resolvedCopies[0]?.every((byte) => byte === 0)).toBe(true);

      resolvedCopies.length = 0;
      const providerEnvelope = encryptWithVault(vault, ORG_A, envelope);
      expect(resolvedCopies).toHaveLength(1);
      expect(resolvedCopies[0]?.every((byte) => byte === 0)).toBe(true);

      resolvedCopies.length = 0;
      const plaintext = vault.decryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: PROVIDER_KEY_A,
        provider: 'openai',
        providerEnvelope,
        organizationEnvelope: envelope,
      });
      expect(plaintext.equals(CANARY)).toBe(true);
      plaintext.fill(0);
      expect(resolvedCopies).toHaveLength(1);
      expect(resolvedCopies[0]?.every((byte) => byte === 0)).toBe(true);

      resolvedCopies.length = 0;
      const tamperedTag = cloneProviderEnvelope(providerEnvelope);
      tamperedTag.authTag[0] = (tamperedTag.authTag[0] as number) ^ 0xff;
      expectVaultError(
        () =>
          vault.decryptProviderCredential({
            orgId: ORG_A,
            providerKeyId: PROVIDER_KEY_A,
            provider: 'openai',
            providerEnvelope: tamperedTag,
            organizationEnvelope: envelope,
          }),
        'AUTHENTICATION_FAILED',
      );
      expect(resolvedCopies).toHaveLength(1);
      expect(resolvedCopies[0]?.every((byte) => byte === 0)).toBe(true);

      resolvedCopies.length = 0;
      const tamperedDek = cloneOrgEnvelope(envelope);
      tamperedDek.wrappedDek[1] = (tamperedDek.wrappedDek[1] as number) ^ 0xff;
      expectVaultError(() => encryptWithVault(vault, ORG_A, tamperedDek), 'AUTHENTICATION_FAILED');
      expect(resolvedCopies).toHaveLength(1);
      expect(resolvedCopies[0]?.every((byte) => byte === 0)).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });

  it('scrubs both DEK-unwrap and provider-decrypt intermediates on success', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);
    const providerEnvelope = encryptWithVault(vault, ORG_A, envelope);
    const capture = captureDecipherChunksByOperation();

    try {
      const plaintext = vault.decryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: PROVIDER_KEY_A,
        provider: 'openai',
        providerEnvelope,
        organizationEnvelope: envelope,
      });

      // Both authenticated decryption paths executed during the round-trip.
      expect(capture.dekUnwrap.length).toBeGreaterThanOrEqual(2);
      expect(capture.providerDecrypt.length).toBeGreaterThanOrEqual(2);

      for (const chunk of [...capture.dekUnwrap, ...capture.providerDecrypt]) {
        expect(chunk.every((byte) => byte === 0)).toBe(true);
      }

      // The caller-owned result is a distinct allocation and is untouched by intermediate cleanup.
      expect(capture.dekUnwrap.includes(plaintext)).toBe(false);
      expect(capture.providerDecrypt.includes(plaintext)).toBe(false);
      expect(plaintext.equals(CANARY)).toBe(true);

      plaintext.fill(0);
      expect(plaintext.every((byte) => byte === 0)).toBe(true);
    } finally {
      capture.restore();
    }
  });

  it('scrubs DEK-unwrap intermediates on organization-DEK authentication failure', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);
    const providerEnvelope = encryptWithVault(vault, ORG_A, envelope);
    const tampered = cloneOrgEnvelope(envelope);
    tampered.wrappedDek[1] = (tampered.wrappedDek[1] as number) ^ 0xff;
    const capture = captureDecipherChunksByOperation();

    try {
      let returnedPlaintext: Buffer | undefined;
      try {
        returnedPlaintext = vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope,
          organizationEnvelope: tampered,
        });
      } catch (error) {
        expect(error).toBeInstanceOf(VaultError);
        expect((error as VaultError).reason).toBe('AUTHENTICATION_FAILED');
      }

      // No plaintext crosses the boundary when the organization DEK fails authentication.
      expect(returnedPlaintext).toBeUndefined();

      // The DEK unwrap produced intermediate chunks; provider decryption never started.
      expect(capture.dekUnwrap.length).toBeGreaterThanOrEqual(1);
      expect(capture.providerDecrypt).toHaveLength(0);
      for (const chunk of capture.dekUnwrap) {
        expect(chunk.every((byte) => byte === 0)).toBe(true);
      }
    } finally {
      capture.restore();
    }
  });

  it('scrubs both operations on provider authentication failure without returning plaintext', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);
    const providerEnvelope = encryptWithVault(vault, ORG_A, envelope);
    const tampered = cloneProviderEnvelope(providerEnvelope);
    tampered.authTag[0] = (tampered.authTag[0] as number) ^ 0xff;
    const capture = captureDecipherChunksByOperation();

    try {
      let returnedPlaintext: Buffer | undefined;
      try {
        returnedPlaintext = vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope: tampered,
          organizationEnvelope: envelope,
        });
      } catch (error) {
        expect(error).toBeInstanceOf(VaultError);
        expect((error as VaultError).reason).toBe('AUTHENTICATION_FAILED');
      }

      // No plaintext crosses the boundary when provider ciphertext fails authentication.
      expect(returnedPlaintext).toBeUndefined();

      // DEK unwrap succeeded; provider decryption produced an update chunk before final() failed.
      expect(capture.dekUnwrap.length).toBeGreaterThanOrEqual(2);
      expect(capture.providerDecrypt.length).toBeGreaterThanOrEqual(1);
      for (const chunk of [...capture.dekUnwrap, ...capture.providerDecrypt]) {
        expect(chunk.every((byte) => byte === 0)).toBe(true);
      }
    } finally {
      capture.restore();
    }
  });

  it('rejects provider ciphertext outside the 2..4097-byte structural bound', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);

    for (const length of [1, MAX_PROVIDER_CREDENTIAL_BYTES + 2, 10_000]) {
      expectVaultError(
        () =>
          vault.decryptProviderCredential({
            orgId: ORG_A,
            providerKeyId: PROVIDER_KEY_A,
            provider: 'openai',
            providerEnvelope: providerEnvelopeWithCiphertextLength(length),
            organizationEnvelope: envelope,
          }),
        'UNSUPPORTED_FORMAT',
      );
    }

    // Structurally valid boundary lengths reach authenticated decryption and fail there.
    for (const length of [2, MAX_PROVIDER_CREDENTIAL_BYTES + 1]) {
      expectVaultError(
        () =>
          vault.decryptProviderCredential({
            orgId: ORG_A,
            providerKeyId: PROVIDER_KEY_A,
            provider: 'openai',
            providerEnvelope: providerEnvelopeWithCiphertextLength(length),
            organizationEnvelope: envelope,
          }),
        'AUTHENTICATION_FAILED',
      );
    }
  });

  it('round-trips a maximum-length 4096-byte provider credential', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);
    const maxPlaintext = Buffer.alloc(MAX_PROVIDER_CREDENTIAL_BYTES, 0x5a);

    const providerEnvelope = encryptWithVault(vault, ORG_A, envelope, maxPlaintext);
    expect(providerEnvelope.ciphertext).toHaveLength(MAX_PROVIDER_CREDENTIAL_BYTES + 1);

    const plaintext = vault.decryptProviderCredential({
      orgId: ORG_A,
      providerKeyId: PROVIDER_KEY_A,
      provider: 'openai',
      providerEnvelope,
      organizationEnvelope: envelope,
    });
    expect(plaintext.equals(maxPlaintext)).toBe(true);
    plaintext.fill(0);
  });

  it('never exposes KEK material in returned envelopes or errors', () => {
    const vault = createVault(1);
    const envelope = vault.createOrganizationEnvelope(ORG_A);
    const providerEnvelope = encryptWithVault(vault, ORG_A, envelope);
    const kekBase64 = KEK_V1.toString('base64url');
    const kekHex = KEK_V1.toString('hex');

    for (const serialized of [JSON.stringify(envelope), JSON.stringify(providerEnvelope)]) {
      expect(serialized).not.toContain(kekBase64);
      expect(serialized).not.toContain(kekHex);
    }

    const tampered = cloneProviderEnvelope(providerEnvelope);
    tampered.authTag[0] = (tampered.authTag[0] as number) ^ 0xff;
    const error = expectVaultError(
      () =>
        vault.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope: tampered,
          organizationEnvelope: envelope,
        }),
      'AUTHENTICATION_FAILED',
    );
    expect(error.message).not.toContain(kekBase64);
    expect(JSON.stringify(error)).not.toContain(kekBase64);
  });
});
