import type pg from 'pg';
import { describe, expect, it } from 'vitest';
import {
  decodeCursor,
  deriveKeyHint,
  encodeCursor,
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

  describe('validateProvider', () => {
    it('accepts only supported provider "openai"', () => {
      expect(validateProvider('openai')).toBe('openai');
      expect(validateProvider(' openai ')).toBe('openai');
    });

    it('rejects unsupported providers', () => {
      expect(() => validateProvider('anthropic')).toThrow(ProviderKeyManagementError);
      expect(() => validateProvider('google')).toThrow(ProviderKeyManagementError);
      expect(() => validateProvider('')).toThrow(ProviderKeyManagementError);
      expect(() => validateProvider(123)).toThrow(ProviderKeyManagementError);
    });
  });

  describe('validateKeyId and isValidUuid', () => {
    it('validates canonical and non-canonical UUIDs, returning lowercase canonical string', () => {
      expect(isValidUuid(VALID_KEY_ID)).toBe(true);
      expect(validateKeyId(VALID_KEY_ID.toUpperCase())).toBe(VALID_KEY_ID);
    });

    it('rejects malformed UUIDs', () => {
      expect(isValidUuid('not-a-uuid')).toBe(false);
      expect(() => validateKeyId('not-a-uuid')).toThrow(ProviderKeyManagementError);
      expect(() => validateKeyId('')).toThrow(ProviderKeyManagementError);
      expect(() => validateKeyId(null)).toThrow(ProviderKeyManagementError);
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

  describe('Buffer zeroization and secret hygiene in service', () => {
    it('zeroizes the temporary credential buffer on createKey failure (vault unavailable)', async () => {
      const mockPool = {} as pg.Pool;
      // Service without vault
      const service = new ProviderKeyManagementService({ pool: mockPool });

      const canary = 'sk-synthetic-temp-zeroize-probe-123456';
      await expect(
        service.createKey(VALID_ORG_ID, {
          provider: 'openai',
          label: 'Test',
          credential: canary,
        }),
      ).rejects.toThrow('Provider credential vault is unavailable');
    });

    it('zeroizes the temporary credential buffer on replaceKey failure (vault unavailable)', async () => {
      const mockPool = {} as pg.Pool;
      const service = new ProviderKeyManagementService({ pool: mockPool });

      const canary = 'sk-synthetic-temp-zeroize-probe-654321';
      await expect(
        service.replaceKey(VALID_ORG_ID, VALID_KEY_ID, {
          label: 'Test',
          credential: canary,
        }),
      ).rejects.toThrow('Provider credential vault is unavailable');
    });

    it('fails closed when credential is empty or exceeds 4096 bytes', async () => {
      const mockPool = {} as pg.Pool;
      const vault = createTestVault();
      const service = new ProviderKeyManagementService({ pool: mockPool, vault });

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
});
