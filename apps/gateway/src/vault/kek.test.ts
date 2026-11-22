import crypto from 'node:crypto';
import { Writable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { createLogger } from '../logging/index.js';
import { VaultError } from './errors.js';
import {
  createKekKeyringFromEnvironment,
  inspectKekEnvironment,
  KekKeyring,
  type KekEnvironment,
} from './kek.js';

function randomKek(): string {
  return crypto.randomBytes(32).toString('base64url');
}

function keyBytes(fill: number): Buffer {
  return Buffer.alloc(32, fill);
}

function createLogCapture(): {
  stream: Writable;
  getRawOutput: () => string;
} {
  let raw = '';
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      raw += chunk.toString();
      callback();
    },
  });
  return { stream, getRawOutput: () => raw };
}

function expectInvalid(env: KekEnvironment, field?: string): void {
  const inspection = inspectKekEnvironment(env);
  expect(inspection.status).toBe('invalid');
  if (inspection.status === 'invalid' && field !== undefined) {
    expect(inspection.issues.some((issue) => issue.field === field)).toBe(true);
  }
}

describe('SW-1.7.1 versioned KEK configuration', () => {
  it('accepts a valid V1-only keyring', () => {
    const encoded = randomKek();
    const inspection = inspectKekEnvironment({
      MASTER_KEK_V1: encoded,
      ACTIVE_KEK_VERSION: '1',
    });
    expect(inspection.status).toBe('valid');
    if (inspection.status === 'valid') {
      expect(inspection.keyring.activeVersion).toBe(1);
      const resolved = inspection.keyring.resolve(1);
      expect(resolved.toString('base64url')).toBe(encoded);
      resolved.fill(0);
      expect(() => inspection.keyring.resolve(2)).toThrowError(VaultError);
    }
  });

  it('accepts a valid V2-only keyring', () => {
    const encoded = randomKek();
    const inspection = inspectKekEnvironment({
      MASTER_KEK_V2: encoded,
      ACTIVE_KEK_VERSION: '2',
    });
    expect(inspection.status).toBe('valid');
    if (inspection.status === 'valid') {
      expect(inspection.keyring.activeVersion).toBe(2);
      const resolved = inspection.keyring.resolve(2);
      expect(resolved.toString('base64url')).toBe(encoded);
      resolved.fill(0);
      expect(() => inspection.keyring.resolve(1)).toThrowError(VaultError);
    }
  });

  it('accepts a valid V1+V2 keyring with active version 2', () => {
    const inspection = inspectKekEnvironment({
      MASTER_KEK_V1: randomKek(),
      MASTER_KEK_V2: randomKek(),
      ACTIVE_KEK_VERSION: '2',
    });
    expect(inspection.status).toBe('valid');
    if (inspection.status === 'valid') {
      expect(inspection.keyring.activeVersion).toBe(2);
      const resolvedV1 = inspection.keyring.resolve(1);
      const resolvedV2 = inspection.keyring.resolve(2);
      expect(resolvedV1).toHaveLength(32);
      expect(resolvedV2).toHaveLength(32);
      resolvedV1.fill(0);
      resolvedV2.fill(0);
    }
  });

  it('accepts active version 1 with both historical keys configured', () => {
    const inspection = inspectKekEnvironment({
      MASTER_KEK_V1: randomKek(),
      MASTER_KEK_V2: randomKek(),
      ACTIVE_KEK_VERSION: '1',
    });
    expect(inspection.status).toBe('valid');
    if (inspection.status === 'valid') {
      expect(inspection.keyring.activeVersion).toBe(1);
    }
  });

  it('treats a wholly absent KEK configuration as uninitialised, never as a default key', () => {
    expect(inspectKekEnvironment({})).toEqual({ status: 'absent' });
    expect(() => createKekKeyringFromEnvironment({})).toThrowError(VaultError);
    try {
      createKekKeyringFromEnvironment({});
    } catch (error) {
      expect(error).toBeInstanceOf(VaultError);
      expect((error as VaultError).reason).toBe('CONFIGURATION_ERROR');
    }
  });

  it('rejects a missing ACTIVE_KEK_VERSION when KEK material is supplied', () => {
    expectInvalid({ MASTER_KEK_V1: randomKek() }, 'ACTIVE_KEK_VERSION');
  });

  it('rejects an active version whose KEK is missing (no silent fallback)', () => {
    expectInvalid({ MASTER_KEK_V1: randomKek(), ACTIVE_KEK_VERSION: '2' }, 'ACTIVE_KEK_VERSION');
    expect(() =>
      createKekKeyringFromEnvironment({
        MASTER_KEK_V1: randomKek(),
        ACTIVE_KEK_VERSION: '2',
      }),
    ).toThrowError(VaultError);
  });

  it('rejects malformed ACTIVE_KEK_VERSION representations', () => {
    for (const version of ['', '0', '3', '01', '+1', '1.0', ' 1', '2 ', 'one', '1e0']) {
      expectInvalid(
        { MASTER_KEK_V1: randomKek(), ACTIVE_KEK_VERSION: version },
        'ACTIVE_KEK_VERSION',
      );
    }
  });

  it('rejects a KEK whose decoded length is not exactly 32 bytes', () => {
    expectInvalid({
      MASTER_KEK_V1: Buffer.alloc(31, 1).toString('base64url'),
      ACTIVE_KEK_VERSION: '1',
    });
    expectInvalid({
      MASTER_KEK_V1: Buffer.alloc(33, 1).toString('base64url'),
      ACTIVE_KEK_VERSION: '1',
    });
  });

  it('rejects non-base64url characters', () => {
    expectInvalid({
      MASTER_KEK_V1: `${'A'.repeat(42)}+`,
      ACTIVE_KEK_VERSION: '1',
    });
    expectInvalid({
      MASTER_KEK_V1: `${'A'.repeat(42)}/`,
      ACTIVE_KEK_VERSION: '1',
    });
  });

  it('rejects noncanonical base64url trailing pad bits', () => {
    const canonical = randomKek();
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const lastIndex = alphabet.indexOf(canonical[42] as string);
    expect(lastIndex).toBeGreaterThanOrEqual(0);
    const noncanonical = `${canonical.slice(0, 42)}${alphabet[lastIndex + 1]}`;

    expect(Buffer.from(noncanonical, 'base64url').toString('base64url')).toBe(canonical);
    expectInvalid({ MASTER_KEK_V1: noncanonical, ACTIVE_KEK_VERSION: '1' });
  });

  it('rejects padded representations', () => {
    expectInvalid({
      MASTER_KEK_V1: `${randomKek()}=`,
      ACTIVE_KEK_VERSION: '1',
    });
  });

  it('rejects explicitly empty or whitespace-only KEK values, including inactive versions', () => {
    const valid = randomKek();

    // An explicitly empty active KEK is invalid, not absent.
    expectInvalid({ MASTER_KEK_V1: '', ACTIVE_KEK_VERSION: '1' }, 'MASTER_KEK_V1');
    expectInvalid({ MASTER_KEK_V2: '', ACTIVE_KEK_VERSION: '2' }, 'MASTER_KEK_V2');

    // An explicitly empty inactive KEK is also invalid; only undefined means "not supplied".
    expectInvalid(
      { MASTER_KEK_V1: valid, MASTER_KEK_V2: '', ACTIVE_KEK_VERSION: '1' },
      'MASTER_KEK_V2',
    );
    expectInvalid(
      { MASTER_KEK_V1: '', MASTER_KEK_V2: valid, ACTIVE_KEK_VERSION: '2' },
      'MASTER_KEK_V1',
    );

    // Whitespace-only material is invalid regardless of active or inactive status.
    expectInvalid(
      { MASTER_KEK_V1: valid, MASTER_KEK_V2: '   ', ACTIVE_KEK_VERSION: '1' },
      'MASTER_KEK_V2',
    );
    expectInvalid({ MASTER_KEK_V1: ' '.repeat(43), ACTIVE_KEK_VERSION: '1' }, 'MASTER_KEK_V1');
  });

  it('rejects all-zero KEK material', () => {
    expectInvalid({
      MASTER_KEK_V1: Buffer.alloc(32, 0).toString('base64url'),
      ACTIVE_KEK_VERSION: '1',
    });
  });

  it('rejects duplicate KEK material across versions', () => {
    const duplicated = randomKek();
    expectInvalid(
      {
        MASTER_KEK_V1: duplicated,
        MASTER_KEK_V2: duplicated,
        ACTIVE_KEK_VERSION: '1',
      },
      'MASTER_KEK_V2',
    );
  });

  it('rejects invalid direct keyring construction', () => {
    expect(
      () => new KekKeyring({ activeVersion: 1, keys: { 1: Buffer.alloc(31, 1) } }),
    ).toThrowError(VaultError);
    expect(
      () => new KekKeyring({ activeVersion: 1, keys: { 1: Buffer.alloc(32, 0) } }),
    ).toThrowError(VaultError);
    expect(
      () =>
        new KekKeyring({
          activeVersion: 2,
          keys: { 1: keyBytes(1) },
        }),
    ).toThrowError(VaultError);
    expect(
      () =>
        new KekKeyring({
          activeVersion: 1,
          keys: { 1: keyBytes(1), 2: keyBytes(1) },
        }),
    ).toThrowError(VaultError);
  });

  it('resolves only an explicitly configured KEK version', () => {
    const keyring = new KekKeyring({ activeVersion: 2, keys: { 2: keyBytes(7) } });
    expect(keyring.has(2)).toBe(true);
    expect(keyring.has(1)).toBe(false);
    expect(() => keyring.resolve(1)).toThrowError(VaultError);
    expect(() => keyring.resolve(3)).toThrowError(VaultError);
    expect(() => keyring.resolve(0)).toThrowError(VaultError);
  });

  it('returns an independent KEK copy so caller mutation cannot alter keyring material', () => {
    const original = crypto.randomBytes(32);
    const keyring = new KekKeyring({ activeVersion: 1, keys: { 1: original } });

    const first = keyring.resolve(1);
    expect(first.equals(original)).toBe(true);
    first.fill(0xff);

    const second = keyring.resolve(1);
    expect(second.equals(original)).toBe(true);
    expect(second).not.toBe(first);

    first.fill(0);
    second.fill(0);
  });

  it('clears the scoped KEK copy after both success and failure', () => {
    const keyring = new KekKeyring({ activeVersion: 1, keys: { 1: keyBytes(9) } });

    let successCopy: Buffer | undefined;
    expect(
      keyring.withKey(1, (kek) => {
        successCopy = kek;
        expect(kek.every((byte) => byte === 9)).toBe(true);
        return 'completed';
      }),
    ).toBe('completed');
    expect(successCopy?.every((byte) => byte === 0)).toBe(true);

    let failureCopy: Buffer | undefined;
    expect(() =>
      keyring.withKey(1, (kek) => {
        failureCopy = kek;
        throw new Error('synthetic operation failure');
      }),
    ).toThrowError('synthetic operation failure');
    expect(failureCopy?.every((byte) => byte === 0)).toBe(true);
  });

  it('resolves historical V1 and V2 KEKs explicitly without fallback', () => {
    const v1 = crypto.randomBytes(32);
    const v2 = crypto.randomBytes(32);
    const keyring = new KekKeyring({ activeVersion: 2, keys: { 1: v1, 2: v2 } });

    const resolvedV1 = keyring.resolve(1);
    const resolvedV2 = keyring.resolve(2);
    expect(resolvedV1.equals(v1)).toBe(true);
    expect(resolvedV2.equals(v2)).toBe(true);
    expect(resolvedV1.equals(resolvedV2)).toBe(false);

    resolvedV1.fill(0);
    resolvedV2.fill(0);
  });

  it('never echoes KEK values in validation issues or configuration errors', () => {
    const canary = 'synthetic_kek_canary_value_should_never_leak_9f3c1d';
    const inspection = inspectKekEnvironment({
      MASTER_KEK_V1: canary,
      ACTIVE_KEK_VERSION: '1',
    });
    expect(inspection.status).toBe('invalid');
    expect(JSON.stringify(inspection)).not.toContain(canary);
    try {
      createKekKeyringFromEnvironment({ MASTER_KEK_V1: canary, ACTIVE_KEK_VERSION: '1' });
      expect.fail('expected configuration failure');
    } catch (error) {
      expect(error).toBeInstanceOf(VaultError);
      expect((error as Error).message).not.toContain(canary);
    }
  });

  it('never emits KEK material or DEK envelope fields through Pino', () => {
    const canary = 'synthetic_kek_log_canary_6f7a2b4e';
    const { stream, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    logger.info(
      {
        MASTER_KEK_V1: canary,
        masterKekV2: canary,
        config: { MASTER_KEK_V1: canary, activeKekVersion: '1' },
        wrappedDek: canary,
        dekIv: canary,
        dekAuthTag: canary,
        err: new VaultError('CONFIGURATION_ERROR', 'KEK configuration is invalid'),
      },
      'Synthetic vault configuration failure',
    );

    expect(getRawOutput()).not.toContain(canary);
    expect(getRawOutput()).toContain('[REDACTED]');
  });
});
