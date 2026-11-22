import type pg from 'pg';
import { describe, expect, it, vi } from 'vitest';
import {
  decodeCursor,
  deriveKeyHint,
  encodeCursor,
  isWellFormedUnicode,
  isValidUuid,
  ProviderKeyManagementError,
  ProviderKeyManagementService,
  validateKeyId,
  validateLabel,
  validateProvider,
} from './provider-key-management.js';
import { EnvelopeVault } from '../vault/envelope.js';
import { KekKeyring } from '../vault/kek.js';

const VALID_KEK_V1 = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY';
const VALID_ORG_ID = '11111111-1111-4111-8111-111111111111';
const VALID_KEY_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

function createTestVault(): EnvelopeVault {
  const keyring = new KekKeyring({
    activeVersion: 1,
    keys: {
      1: Buffer.from(VALID_KEK_V1, 'base64url'),
    },
  });
  return new EnvelopeVault(keyring);
}

describe('ProviderKeyManagement — Unit & Safety Tests', () => {
  describe('deriveKeyHint', () => {
    it('returns fixed masking prefix with last four characters for standard credentials', () => {
      expect(deriveKeyHint('synthetic-test-credential-123456')).toBe('****3456');
      expect(deriveKeyHint('sk-proj-abcde1234')).toBe('****1234');
      expect(deriveKeyHint('12345')).toBe('****2345');
    });

    it('returns an entirely masked hint for credentials with 4 or fewer characters', () => {
      expect(deriveKeyHint('1234')).toBe('****');
      expect(deriveKeyHint('abc')).toBe('****');
      expect(deriveKeyHint('12')).toBe('****');
      expect(deriveKeyHint('x')).toBe('****');
      expect(deriveKeyHint('')).toBe('****');
    });

    it('handles multibyte UTF-8 and emoji safely without splitting surrogate pairs', () => {
      expect(deriveKeyHint('key-with-emoji-🚀✨🔥🌟')).toBe('****🚀✨🔥🌟');
      expect(deriveKeyHint('prefix-🔑')).toBe('****ix-🔑');
      expect(deriveKeyHint('🔑')).toBe('****');
    });

    it('sanitizes control characters in the last four characters', () => {
      expect(deriveKeyHint('secret\n123')).toBe('****123');
      expect(deriveKeyHint('prefix\x00abc')).toBe('****abc');
    });
  });

  describe('validateLabel', () => {
    it('accepts valid labels and trims surrounding whitespace', () => {
      expect(validateLabel('  Primary OpenAI Key  ')).toBe('Primary OpenAI Key');
      expect(validateLabel('Production-Key-1')).toBe('Production-Key-1');
    });

    it('rejects empty or whitespace-only labels', () => {
      expect(() => validateLabel('')).toThrow(ProviderKeyManagementError);
      expect(() => validateLabel('   ')).toThrow(ProviderKeyManagementError);
      expect(() => validateLabel(null)).toThrow(ProviderKeyManagementError);
    });

    it('rejects labels exceeding 255 UTF-8 bytes', () => {
      const longLabel = 'a'.repeat(256);
      expect(() => validateLabel(longLabel)).toThrow(ProviderKeyManagementError);
      const multiByteLong = '🔑'.repeat(65); // 65 * 4 = 260 bytes
      expect(() => validateLabel(multiByteLong)).toThrow(ProviderKeyManagementError);
    });

    it('rejects labels containing prohibited control characters', () => {
      expect(() => validateLabel('Label\nNewline')).toThrow(ProviderKeyManagementError);
      expect(() => validateLabel('Label\x00Null')).toThrow(ProviderKeyManagementError);
      expect(() => validateLabel('Label\tTab')).toThrow(ProviderKeyManagementError);
    });
  });

  describe('validateProvider (PVAULT-05)', () => {
    it('accepts only supported provider "openai"', () => {
      expect(validateProvider('openai')).toBe('openai');
      expect(validateProvider(' openai ')).toBe('openai');
    });

    it('rejects unsupported providers with a static safe message without echoing input', () => {
      try {
        validateProvider('sk-synthetic-secret-like-provider-name-12345');
        expect.unreachable('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(ProviderKeyManagementError);
        const pkErr = err as ProviderKeyManagementError;
        expect(pkErr.reason).toBe('INVALID_INPUT');
        expect(pkErr.message).toBe('Unsupported provider: only "openai" is currently supported');
        expect(pkErr.message).not.toContain('sk-synthetic-secret-like-provider-name-12345');
      }

      expect(() => validateProvider('anthropic')).toThrow(
        'Unsupported provider: only "openai" is currently supported',
      );
      expect(() => validateProvider('')).toThrow(
        'Unsupported provider: only "openai" is currently supported',
      );
      expect(() => validateProvider(123)).toThrow('Invalid provider: expected string');
    });
  });

  describe('validateKeyId and isValidUuid (PVAULT-05)', () => {
    it('validates canonical and non-canonical UUIDs, returning lowercase canonical string', () => {
      expect(isValidUuid(VALID_KEY_ID)).toBe(true);
      expect(validateKeyId(VALID_KEY_ID.toUpperCase())).toBe(VALID_KEY_ID);
    });

    it('rejects malformed UUIDs with a static safe message without echoing input', () => {
      expect(isValidUuid('not-a-uuid')).toBe(false);
      try {
        validateKeyId('secret-token-key-id-attempt-12345');
        expect.unreachable('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(ProviderKeyManagementError);
        const pkErr = err as ProviderKeyManagementError;
        expect(pkErr.reason).toBe('INVALID_INPUT');
        expect(pkErr.message).toBe('Invalid key ID: malformed UUID');
        expect(pkErr.message).not.toContain('secret-token-key-id-attempt-12345');
      }

      expect(() => validateKeyId('')).toThrow('Invalid key ID: malformed UUID');
      expect(() => validateKeyId(null)).toThrow('Invalid key ID: expected string');
    });
  });

  describe('isWellFormedUnicode (PVAULT-02)', () => {
    it('accepts valid ASCII credential strings', () => {
      expect(isWellFormedUnicode('sk-proj-valid-ascii-credential-12345')).toBe(true);
      expect(isWellFormedUnicode('standard_alphanumeric_1234567890')).toBe(true);
    });

    it('accepts valid multibyte UTF-8 and valid surrogate pairs (emoji)', () => {
      expect(isWellFormedUnicode('key-with-multibyte-çéñø-123')).toBe(true);
      expect(isWellFormedUnicode('key-with-emoji-🚀✨🔥🌟')).toBe(true);
      expect(isWellFormedUnicode('\uD83D\uDE00')).toBe(true); // Grinning face surrogate pair
    });

    it('rejects isolated high surrogates', () => {
      expect(isWellFormedUnicode('\uD800')).toBe(false);
      expect(isWellFormedUnicode('\uDBFF')).toBe(false);
      expect(isWellFormedUnicode('prefix-\uD800-suffix')).toBe(false);
      expect(isWellFormedUnicode('\uD800abc')).toBe(false);
    });

    it('rejects isolated low surrogates', () => {
      expect(isWellFormedUnicode('\uDC00')).toBe(false);
      expect(isWellFormedUnicode('\uDFFF')).toBe(false);
      expect(isWellFormedUnicode('prefix-\uDFFF-suffix')).toBe(false);
      expect(isWellFormedUnicode('\uDFFFabc')).toBe(false);
    });

    it('rejects malformed surrogate ordering (low followed by high)', () => {
      expect(isWellFormedUnicode('\uDE00\uD83D')).toBe(false);
      expect(isWellFormedUnicode('bad-\uDE00\uD83D-ordering')).toBe(false);
    });
  });

  describe('Cursor encoding and decoding', () => {
    it('round-trips valid cursor timestamp and ID', () => {
      const ts = '2026-11-22T10:20:30.123456Z';
      const encoded = encodeCursor(ts, VALID_KEY_ID);
      expect(typeof encoded).toBe('string');

      const decoded = decodeCursor(encoded);
      expect(decoded.createdAt).toBe(ts);
      expect(decoded.id).toBe(VALID_KEY_ID);
    });

    it('rejects malformed or forged cursors', () => {
      expect(() => decodeCursor('not-base64url')).toThrow(ProviderKeyManagementError);
      expect(() => decodeCursor('')).toThrow(ProviderKeyManagementError);
      expect(() => decodeCursor('a'.repeat(300))).toThrow(ProviderKeyManagementError);

      // Non-canonical base64url
      const nonCanonical = Buffer.from(
        JSON.stringify({ createdAt: '2026-11-22T10:20:30.123456Z', id: VALID_KEY_ID }),
      ).toString('base64'); // with padding '='
      if (nonCanonical.includes('=')) {
        expect(() => decodeCursor(nonCanonical)).toThrow(ProviderKeyManagementError);
      }

      // Invalid JSON contents
      const badJson = Buffer.from('{"unexpected": 1}', 'utf8').toString('base64url');
      expect(() => decodeCursor(badJson)).toThrow(ProviderKeyManagementError);

      // Invalid timestamp
      const badTs = Buffer.from(
        JSON.stringify({ createdAt: 'invalid-date', id: VALID_KEY_ID }),
        'utf8',
      ).toString('base64url');
      expect(() => decodeCursor(badTs)).toThrow(ProviderKeyManagementError);
    });
  });

  describe('Consistent KEK gating across all four management methods (PVAULT-01)', () => {
    it('rejects createKey with VAULT_UNAVAILABLE when service has no vault', async () => {
      const service = new ProviderKeyManagementService({ pool: {} as pg.Pool });
      await expect(
        service.createKey(VALID_ORG_ID, {
          provider: 'openai',
          label: 'Test Key',
          credential: 'sk-test-valid-credential-123',
        }),
      ).rejects.toMatchObject({
        reason: 'VAULT_UNAVAILABLE',
        message: 'Provider credential vault is unavailable',
      });
    });

    it('rejects replaceKey with VAULT_UNAVAILABLE when service has no vault', async () => {
      const service = new ProviderKeyManagementService({ pool: {} as pg.Pool });
      await expect(
        service.replaceKey(VALID_ORG_ID, VALID_KEY_ID, {
          label: 'Test Replacement',
          credential: 'sk-test-valid-credential-123',
        }),
      ).rejects.toMatchObject({
        reason: 'VAULT_UNAVAILABLE',
        message: 'Provider credential vault is unavailable',
      });
    });

    it('rejects listKeys with VAULT_UNAVAILABLE when service has no vault', async () => {
      const service = new ProviderKeyManagementService({ pool: {} as pg.Pool });
      await expect(service.listKeys(VALID_ORG_ID)).rejects.toMatchObject({
        reason: 'VAULT_UNAVAILABLE',
        message: 'Provider credential vault is unavailable',
      });
    });

    it('rejects disableKey with VAULT_UNAVAILABLE when service has no vault', async () => {
      const service = new ProviderKeyManagementService({ pool: {} as pg.Pool });
      await expect(service.disableKey(VALID_ORG_ID, VALID_KEY_ID)).rejects.toMatchObject({
        reason: 'VAULT_UNAVAILABLE',
        message: 'Provider credential vault is unavailable',
      });
    });
  });

  describe('Credential Unicode validation in service (PVAULT-02)', () => {
    it('rejects malformed Unicode in createKey before buffer conversion and never echoes credential', async () => {
      const vault = createTestVault();
      const service = new ProviderKeyManagementService({ pool: {} as pg.Pool, vault });

      const malformedCredential = 'sk-canary-secret-\uD800-isolated-high';
      try {
        await service.createKey(VALID_ORG_ID, {
          provider: 'openai',
          label: 'Test',
          credential: malformedCredential,
        });
        expect.unreachable('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(ProviderKeyManagementError);
        const pkErr = err as ProviderKeyManagementError;
        expect(pkErr.reason).toBe('INVALID_INPUT');
        expect(pkErr.message).toBe('Invalid credential: malformed Unicode sequence');
        expect(pkErr.message).not.toContain('sk-canary-secret');
      }
    });

    it('rejects malformed Unicode in replaceKey before buffer conversion and never echoes credential', async () => {
      const vault = createTestVault();
      const service = new ProviderKeyManagementService({ pool: {} as pg.Pool, vault });

      const malformedCredential = 'sk-canary-secret-\uDFFF-isolated-low';
      try {
        await service.replaceKey(VALID_ORG_ID, VALID_KEY_ID, {
          label: 'Test',
          credential: malformedCredential,
        });
        expect.unreachable('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(ProviderKeyManagementError);
        const pkErr = err as ProviderKeyManagementError;
        expect(pkErr.reason).toBe('INVALID_INPUT');
        expect(pkErr.message).toBe('Invalid credential: malformed Unicode sequence');
        expect(pkErr.message).not.toContain('sk-canary-secret');
      }
    });

    it('fails closed when credential is empty or exceeds 4096 bytes', async () => {
      const vault = createTestVault();
      const service = new ProviderKeyManagementService({ pool: {} as pg.Pool, vault });

      await expect(
        service.createKey(VALID_ORG_ID, {
          provider: 'openai',
          label: 'Test',
          credential: '',
        }),
      ).rejects.toThrow('credential cannot be empty');

      await expect(
        service.createKey(VALID_ORG_ID, {
          provider: 'openai',
          label: 'Test',
          credential: 'x'.repeat(4097),
        }),
      ).rejects.toThrow('exceeds maximum 4096 bytes');
    });
  });

  describe('Buffer zeroization and secret hygiene observation (PVAULT-04)', () => {
    function extractSql(queryParam: unknown): string {
      if (typeof queryParam === 'string') return queryParam;
      if (queryParam && typeof queryParam === 'object' && 'text' in queryParam) {
        return String((queryParam as { text: unknown }).text);
      }
      return '';
    }

    function setupMockPoolForSuccess(orgEnvelope: {
      kekVersion: number;
      wrappedDek: Buffer;
      dekIv: Buffer;
      dekAuthTag: Buffer;
    }) {
      const mockClient = {
        query: vi.fn(async (param: unknown) => {
          const sql = extractSql(param);
          if (sql.includes('SELECT kek_version')) {
            return {
              command: 'SELECT',
              rows: [
                {
                  kek_version: orgEnvelope.kekVersion,
                  wrapped_dek: orgEnvelope.wrappedDek,
                  dek_iv: orgEnvelope.dekIv,
                  dek_auth_tag: orgEnvelope.dekAuthTag,
                },
              ],
            };
          }
          if (sql.includes('SELECT id, provider, is_active')) {
            return {
              command: 'SELECT',
              rows: [
                {
                  id: VALID_KEY_ID,
                  provider: 'openai',
                  is_active: true,
                },
              ],
            };
          }
          if (sql.includes('INSERT INTO provider_keys') || sql.includes('UPDATE provider_keys')) {
            return {
              command: 'INSERT',
              rows: [
                {
                  id: VALID_KEY_ID,
                  provider: 'openai',
                  label: 'Test Key',
                  key_hint: '****1234',
                  is_active: true,
                  created_at: new Date(),
                },
              ],
            };
          }
          if (sql.includes('COMMIT')) {
            return { command: 'COMMIT', rows: [] };
          }
          return { command: 'OK', rows: [] };
        }),
        release: vi.fn(),
      };
      const mockPool = {
        connect: vi.fn(async () => mockClient),
      } as unknown as pg.Pool;

      return { mockPool, mockClient };
    }

    it('independently observes that allocated temporary credential Buffer is zeroized on createKey success', async () => {
      const vault = createTestVault();
      const orgEnvelope = vault.createOrganizationEnvelope(VALID_ORG_ID);
      const { mockPool } = setupMockPoolForSuccess(orgEnvelope);
      const service = new ProviderKeyManagementService({ pool: mockPool, vault });

      const canary = 'sk-synthetic-track-canary-create-success-1234';
      const trackedBuffers: Buffer[] = [];
      const origBufferFrom = Buffer.from;

      const spy = vi.spyOn(Buffer, 'from').mockImplementation((...args: unknown[]) => {
        const buf = (origBufferFrom as (...a: unknown[]) => Buffer)(...args);
        if (typeof args[0] === 'string' && args[0].includes('synthetic-track-canary')) {
          trackedBuffers.push(buf);
        }
        return buf as unknown as Buffer<ArrayBuffer>;
      });

      try {
        const res = await service.createKey(VALID_ORG_ID, {
          provider: 'openai',
          label: 'Test Key',
          credential: canary,
        });

        expect(res.id).toBe(VALID_KEY_ID);
        expect(trackedBuffers.length).toBe(1);
        const allocatedBuffer = trackedBuffers[0]!;

        // Verify that the exact allocated buffer was zeroized in the finally block
        expect(allocatedBuffer.every((byte) => byte === 0)).toBe(true);
        expect(allocatedBuffer.toString('utf8')).not.toContain('synthetic-track-canary');
      } finally {
        spy.mockRestore();
      }
    });

    it('independently observes that allocated temporary credential Buffer is zeroized on createKey failure', async () => {
      const vault = createTestVault();
      // Mock pool where client query fails
      const mockClient = {
        query: vi.fn(async (param: unknown) => {
          const sql = extractSql(param);
          if (sql.includes('SELECT kek_version')) {
            throw new Error('Database connection dropped unexpectedly');
          }
          return { command: 'OK', rows: [] };
        }),
        release: vi.fn(),
      };
      const mockPool = {
        connect: vi.fn(async () => mockClient),
      } as unknown as pg.Pool;

      const service = new ProviderKeyManagementService({ pool: mockPool, vault });

      const canary = 'sk-synthetic-track-canary-create-failure-5678';
      const trackedBuffers: Buffer[] = [];
      const origBufferFrom = Buffer.from;

      const spy = vi.spyOn(Buffer, 'from').mockImplementation((...args: unknown[]) => {
        const buf = (origBufferFrom as (...a: unknown[]) => Buffer)(...args);
        if (typeof args[0] === 'string' && args[0].includes('synthetic-track-canary')) {
          trackedBuffers.push(buf);
        }
        return buf as unknown as Buffer<ArrayBuffer>;
      });

      try {
        await expect(
          service.createKey(VALID_ORG_ID, {
            provider: 'openai',
            label: 'Test Key',
            credential: canary,
          }),
        ).rejects.toThrow('Database connection dropped unexpectedly');

        expect(trackedBuffers.length).toBe(1);
        const allocatedBuffer = trackedBuffers[0]!;

        // Verify that even though the database operation failed, the buffer was zeroized
        expect(allocatedBuffer.every((byte) => byte === 0)).toBe(true);
        expect(allocatedBuffer.toString('utf8')).not.toContain('synthetic-track-canary');
      } finally {
        spy.mockRestore();
      }
    });

    it('independently observes that allocated temporary credential Buffer is zeroized on replaceKey success', async () => {
      const vault = createTestVault();
      const orgEnvelope = vault.createOrganizationEnvelope(VALID_ORG_ID);
      const { mockPool } = setupMockPoolForSuccess(orgEnvelope);
      const service = new ProviderKeyManagementService({ pool: mockPool, vault });

      const canary = 'sk-synthetic-track-canary-replace-success-9012';
      const trackedBuffers: Buffer[] = [];
      const origBufferFrom = Buffer.from;

      const spy = vi.spyOn(Buffer, 'from').mockImplementation((...args: unknown[]) => {
        const buf = (origBufferFrom as (...a: unknown[]) => Buffer)(...args);
        if (typeof args[0] === 'string' && args[0].includes('synthetic-track-canary')) {
          trackedBuffers.push(buf);
        }
        return buf as unknown as Buffer<ArrayBuffer>;
      });

      try {
        const res = await service.replaceKey(VALID_ORG_ID, VALID_KEY_ID, {
          label: 'Test Key',
          credential: canary,
        });

        expect(res.id).toBe(VALID_KEY_ID);
        expect(trackedBuffers.length).toBe(1);
        const allocatedBuffer = trackedBuffers[0]!;

        // Verify that the buffer was zeroized in finally block
        expect(allocatedBuffer.every((byte) => byte === 0)).toBe(true);
        expect(allocatedBuffer.toString('utf8')).not.toContain('synthetic-track-canary');
      } finally {
        spy.mockRestore();
      }
    });

    it('independently observes that allocated temporary credential Buffer is zeroized on replaceKey failure', async () => {
      const vault = createTestVault();
      // Mock pool returning a disabled key
      const mockClient = {
        query: vi.fn(async (param: unknown) => {
          const sql = extractSql(param);
          if (sql.includes('SELECT id, provider, is_active')) {
            return {
              command: 'SELECT',
              rows: [
                {
                  id: VALID_KEY_ID,
                  provider: 'openai',
                  is_active: false, // Disabled!
                },
              ],
            };
          }
          return { command: 'OK', rows: [] };
        }),
        release: vi.fn(),
      };
      const mockPool = {
        connect: vi.fn(async () => mockClient),
      } as unknown as pg.Pool;

      const service = new ProviderKeyManagementService({ pool: mockPool, vault });

      const canary = 'sk-synthetic-track-canary-replace-failure-3456';
      const trackedBuffers: Buffer[] = [];
      const origBufferFrom = Buffer.from;

      const spy = vi.spyOn(Buffer, 'from').mockImplementation((...args: unknown[]) => {
        const buf = (origBufferFrom as (...a: unknown[]) => Buffer)(...args);
        if (typeof args[0] === 'string' && args[0].includes('synthetic-track-canary')) {
          trackedBuffers.push(buf);
        }
        return buf as unknown as Buffer<ArrayBuffer>;
      });

      try {
        await expect(
          service.replaceKey(VALID_ORG_ID, VALID_KEY_ID, {
            label: 'Test Key',
            credential: canary,
          }),
        ).rejects.toMatchObject({
          reason: 'KEY_DISABLED',
        });

        expect(trackedBuffers.length).toBe(1);
        const allocatedBuffer = trackedBuffers[0]!;

        // Verify that even upon conflict rejection, the buffer was zeroized
        expect(allocatedBuffer.every((byte) => byte === 0)).toBe(true);
        expect(allocatedBuffer.toString('utf8')).not.toContain('synthetic-track-canary');
      } finally {
        spy.mockRestore();
      }
    });
  });
});
