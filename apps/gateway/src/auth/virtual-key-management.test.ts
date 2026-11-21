import crypto from 'node:crypto';
import type pg from 'pg';
import { describe, expect, it, vi } from 'vitest';
import {
  decodeCursor,
  encodeCursor,
  isValidUuid,
  validateKeyId,
  validatePolicyInput,
  VirtualKeyManagementError,
  VirtualKeyManagementService,
} from './virtual-key-management.js';
import type { VirtualKeyService } from './virtual-key.js';

describe('SW-1.6.3: Virtual Key Management & Policy Unit Tests', () => {
  const VALID_UUID = '11111111-1111-4111-8111-111111111111';
  const VALID_UUID_2 = '22222222-2222-4222-8222-222222222222';

  describe('UUID & Key ID Validation', () => {
    it('accepts valid UUID strings', () => {
      expect(isValidUuid(VALID_UUID)).toBe(true);
      expect(validateKeyId(VALID_UUID)).toBe(VALID_UUID);
      expect(isValidUuid(crypto.randomUUID())).toBe(true);
    });

    it('rejects invalid or malformed UUIDs', () => {
      expect(isValidUuid('')).toBe(false);
      expect(isValidUuid('   ')).toBe(false);
      expect(isValidUuid('not-a-uuid')).toBe(false);
      expect(isValidUuid('11111111-1111-1111-1111-11111111111g')).toBe(false);
      expect(isValidUuid(null)).toBe(false);
      expect(isValidUuid(undefined)).toBe(false);
      expect(isValidUuid(12345)).toBe(false);
      expect(isValidUuid({})).toBe(false);

      expect(() => validateKeyId('invalid-uuid')).toThrow(VirtualKeyManagementError);
      expect(() => validateKeyId(null)).toThrow(VirtualKeyManagementError);
      expect(() => validateKeyId(undefined)).toThrow(VirtualKeyManagementError);
    });
  });

  describe('Cursor Encoding & Keyset Pagination Parsing', () => {
    const validMicrosecondTs = '2026-11-21T12:34:56.123456Z';

    it('encodes and decodes microsecond cursor round-trip faithfully', () => {
      const cursor = encodeCursor(validMicrosecondTs, VALID_UUID);
      expect(typeof cursor).toBe('string');

      const decoded = decodeCursor(cursor);
      expect(decoded.createdAt).toBe(validMicrosecondTs);
      expect(decoded.id).toBe(VALID_UUID);
    });

    it('rejects invalid inputs to encodeCursor', () => {
      // Millisecond timestamp (3 decimal places) rejected
      expect(() => encodeCursor('2026-11-21T12:34:56.123Z', VALID_UUID)).toThrow(
        VirtualKeyManagementError,
      );
      // No decimal places rejected
      expect(() => encodeCursor('2026-11-21T12:34:56Z', VALID_UUID)).toThrow(
        VirtualKeyManagementError,
      );
      // Invalid date string
      expect(() => encodeCursor('invalid-timestamp', VALID_UUID)).toThrow(
        VirtualKeyManagementError,
      );
      // Invalid UUID
      expect(() => encodeCursor(validMicrosecondTs, 'not-a-uuid')).toThrow(
        VirtualKeyManagementError,
      );
    });

    it('rejects malformed cursor inputs fail-closed', () => {
      expect(() => decodeCursor('')).toThrow(VirtualKeyManagementError);
      expect(() => decodeCursor('   ')).toThrow(VirtualKeyManagementError);
      expect(() => decodeCursor(null)).toThrow(VirtualKeyManagementError);
      expect(() => decodeCursor(123)).toThrow(VirtualKeyManagementError);
      expect(() => decodeCursor('not-base64url!@#$')).toThrow(VirtualKeyManagementError);

      // Oversized cursor (> 256 chars)
      const oversized = 'A'.repeat(257);
      expect(() => decodeCursor(oversized)).toThrow(VirtualKeyManagementError);

      // Non-canonical base64url encoding (e.g. padding characters '=')
      const canonicalCursor = encodeCursor(validMicrosecondTs, VALID_UUID);
      expect(() => decodeCursor(canonicalCursor + '=')).toThrow(VirtualKeyManagementError);

      // JSON that is not an object
      const invalidJson1 = Buffer.from(JSON.stringify([1, 2, 3])).toString('base64url');
      expect(() => decodeCursor(invalidJson1)).toThrow(VirtualKeyManagementError);

      // JSON missing id
      const invalidJson2 = Buffer.from(JSON.stringify({ createdAt: validMicrosecondTs })).toString(
        'base64url',
      );
      expect(() => decodeCursor(invalidJson2)).toThrow(VirtualKeyManagementError);

      // JSON missing createdAt
      const invalidJson3 = Buffer.from(JSON.stringify({ id: VALID_UUID })).toString('base64url');
      expect(() => decodeCursor(invalidJson3)).toThrow(VirtualKeyManagementError);

      // JSON with millisecond-only date (3 decimal digits instead of 6)
      const invalidJson4 = Buffer.from(
        JSON.stringify({ createdAt: '2026-11-21T12:34:56.123Z', id: VALID_UUID }),
      ).toString('base64url');
      expect(() => decodeCursor(invalidJson4)).toThrow(VirtualKeyManagementError);

      // JSON with invalid date
      const invalidJson5 = Buffer.from(
        JSON.stringify({ createdAt: 'invalid-date', id: VALID_UUID }),
      ).toString('base64url');
      expect(() => decodeCursor(invalidJson5)).toThrow(VirtualKeyManagementError);

      // JSON with invalid UUID id
      const invalidJson6 = Buffer.from(
        JSON.stringify({ createdAt: validMicrosecondTs, id: 'not-a-uuid' }),
      ).toString('base64url');
      expect(() => decodeCursor(invalidJson6)).toThrow(VirtualKeyManagementError);

      // JSON with unexpected extra properties
      const invalidJson7 = Buffer.from(
        JSON.stringify({
          createdAt: validMicrosecondTs,
          id: VALID_UUID,
          extra: 'malicious',
        }),
      ).toString('base64url');
      expect(() => decodeCursor(invalidJson7)).toThrow(VirtualKeyManagementError);
    });
  });

  describe('Policy Input Validation (PUT /api/keys/:id/policy)', () => {
    const validPolicy = {
      allowedModels: ['gpt-4o', 'claude-3-5-sonnet-20241022'],
      rpmLimit: 120,
      tpmLimit: 12000,
      concurrentStreamLimit: 5,
      exactCacheEnabled: false,
      semanticCacheEnabled: false,
      piiRedactionEnabled: true,
      storePayloads: false,
    };

    it('accepts valid full policy replacement', () => {
      const validated = validatePolicyInput(validPolicy);
      expect(validated.allowedModels).toEqual(['gpt-4o', 'claude-3-5-sonnet-20241022']);
      expect(validated.rpmLimit).toBe(120);
      expect(validated.tpmLimit).toBe(12000);
      expect(validated.concurrentStreamLimit).toBe(5);
      expect(validated.exactCacheEnabled).toBe(false);
      expect(validated.semanticCacheEnabled).toBe(false);
      expect(validated.piiRedactionEnabled).toBe(true);
      expect(validated.storePayloads).toBe(false);
    });

    it('accepts empty allowedModels as valid deny-all policy', () => {
      const policyWithEmptyModels = { ...validPolicy, allowedModels: [] };
      const validated = validatePolicyInput(policyWithEmptyModels);
      expect(validated.allowedModels).toEqual([]);
    });

    it('rejects non-object policy inputs', () => {
      expect(() => validatePolicyInput(null)).toThrow(VirtualKeyManagementError);
      expect(() => validatePolicyInput(undefined)).toThrow(VirtualKeyManagementError);
      expect(() => validatePolicyInput('string')).toThrow(VirtualKeyManagementError);
      expect(() => validatePolicyInput(123)).toThrow(VirtualKeyManagementError);
      expect(() => validatePolicyInput([])).toThrow(VirtualKeyManagementError);
    });

    it('rejects partial policy missing required fields', () => {
      const missingModels = { ...validPolicy };
      delete (missingModels as Record<string, unknown>)['allowedModels'];
      expect(() => validatePolicyInput(missingModels)).toThrow(
        /all policy fields must be explicitly supplied/,
      );

      const missingRpm = { ...validPolicy };
      delete (missingRpm as Record<string, unknown>)['rpmLimit'];
      expect(() => validatePolicyInput(missingRpm)).toThrow(
        /all policy fields must be explicitly supplied/,
      );

      const missingStorePayloads = { ...validPolicy };
      delete (missingStorePayloads as Record<string, unknown>)['storePayloads'];
      expect(() => validatePolicyInput(missingStorePayloads)).toThrow(
        /all policy fields must be explicitly supplied/,
      );
    });

    it('rejects unknown or unexpected extra fields', () => {
      const extraField = { ...validPolicy, maliciousField: true };
      expect(() => validatePolicyInput(extraField)).toThrow(
        /all policy fields must be explicitly supplied/,
      );
    });

    describe('Model allowlist validation', () => {
      it('rejects non-array allowedModels', () => {
        expect(() => validatePolicyInput({ ...validPolicy, allowedModels: 'gpt-4o' })).toThrow(
          /allowedModels must be an array/,
        );
      });

      it('rejects array containing non-strings or empty strings', () => {
        expect(() =>
          validatePolicyInput({ ...validPolicy, allowedModels: ['gpt-4o', 123] }),
        ).toThrow(/must be a string/);
        expect(() =>
          validatePolicyInput({ ...validPolicy, allowedModels: ['gpt-4o', ''] }),
        ).toThrow(/cannot be an empty string/);
      });

      it('rejects models with leading or trailing whitespace', () => {
        expect(() => validatePolicyInput({ ...validPolicy, allowedModels: [' gpt-4o'] })).toThrow(
          /leading or trailing whitespace/,
        );
        expect(() => validatePolicyInput({ ...validPolicy, allowedModels: ['gpt-4o '] })).toThrow(
          /leading or trailing whitespace/,
        );
      });

      it('rejects models containing control characters', () => {
        expect(() =>
          validatePolicyInput({ ...validPolicy, allowedModels: ['gpt-4o\u0000'] }),
        ).toThrow(/control characters/);
        expect(() => validatePolicyInput({ ...validPolicy, allowedModels: ['gpt\n4o'] })).toThrow(
          /control characters/,
        );
      });

      it('rejects wildcard or allow-all patterns in model list', () => {
        expect(() => validatePolicyInput({ ...validPolicy, allowedModels: ['*'] })).toThrow(
          /wildcard pattern "\*" in allowedModels is prohibited/,
        );
        expect(() => validatePolicyInput({ ...validPolicy, allowedModels: ['gpt-4*'] })).toThrow(
          /wildcard pattern "gpt-4\*" in allowedModels is prohibited/,
        );
      });

      it('rejects duplicate models in allowedModels', () => {
        expect(() =>
          validatePolicyInput({ ...validPolicy, allowedModels: ['gpt-4o', 'gpt-4o'] }),
        ).toThrow(/duplicate model identifier/);
      });

      it('rejects oversized allowedModels array', () => {
        const tooManyModels = Array.from({ length: 101 }, (_, i) => `model-${i}`);
        expect(() => validatePolicyInput({ ...validPolicy, allowedModels: tooManyModels })).toThrow(
          /exceeds maximum permitted length of 100/,
        );
      });

      it('rejects oversized model identifier string', () => {
        const longModel = 'a'.repeat(129);
        expect(() => validatePolicyInput({ ...validPolicy, allowedModels: [longModel] })).toThrow(
          /exceeds maximum length of 128 characters/,
        );
      });
    });

    describe('Numeric limits validation (RPM, TPM, concurrency)', () => {
      it('rejects non-numeric, string, null or undefined limits', () => {
        expect(() => validatePolicyInput({ ...validPolicy, rpmLimit: '120' })).toThrow(
          /rpmLimit must be a positive safe integer/,
        );
        expect(() => validatePolicyInput({ ...validPolicy, tpmLimit: null })).toThrow(
          /tpmLimit must be a positive safe integer/,
        );
        expect(() =>
          validatePolicyInput({ ...validPolicy, concurrentStreamLimit: undefined }),
        ).toThrow(/concurrentStreamLimit must be a positive safe integer/);
      });

      it('rejects zero or negative limits', () => {
        expect(() => validatePolicyInput({ ...validPolicy, rpmLimit: 0 })).toThrow(
          /rpmLimit must be strictly positive/,
        );
        expect(() => validatePolicyInput({ ...validPolicy, tpmLimit: -100 })).toThrow(
          /tpmLimit must be strictly positive/,
        );
        expect(() => validatePolicyInput({ ...validPolicy, concurrentStreamLimit: -1 })).toThrow(
          /concurrentStreamLimit must be strictly positive/,
        );
      });

      it('rejects fractional or non-safe-integer limits', () => {
        expect(() => validatePolicyInput({ ...validPolicy, rpmLimit: 120.5 })).toThrow(
          /rpmLimit must be a positive safe integer/,
        );
        expect(() => validatePolicyInput({ ...validPolicy, tpmLimit: NaN })).toThrow(
          /tpmLimit must be a positive safe integer/,
        );
        expect(() =>
          validatePolicyInput({ ...validPolicy, concurrentStreamLimit: Infinity }),
        ).toThrow(/concurrentStreamLimit must be a positive safe integer/);
      });

      it('rejects limits exceeding PostgreSQL 32-bit integer range (2147483647)', () => {
        expect(() => validatePolicyInput({ ...validPolicy, rpmLimit: 2147483648 })).toThrow(
          /exceeds maximum PostgreSQL 32-bit integer/,
        );
        expect(() => validatePolicyInput({ ...validPolicy, tpmLimit: 3000000000 })).toThrow(
          /exceeds maximum PostgreSQL 32-bit integer/,
        );
      });
    });

    describe('Privacy and cache flags validation', () => {
      it('rejects non-boolean values for privacy flags', () => {
        expect(() => validatePolicyInput({ ...validPolicy, piiRedactionEnabled: 'true' })).toThrow(
          /piiRedactionEnabled must be a boolean/,
        );
        expect(() => validatePolicyInput({ ...validPolicy, storePayloads: 1 })).toThrow(
          /storePayloads must be a boolean/,
        );
        expect(() => validatePolicyInput({ ...validPolicy, exactCacheEnabled: null })).toThrow(
          /exactCacheEnabled must be a boolean/,
        );
        expect(() =>
          validatePolicyInput({ ...validPolicy, semanticCacheEnabled: undefined }),
        ).toThrow(/semanticCacheEnabled must be a boolean/);
      });

      it('rejects exactCacheEnabled = true because caching is deferred', () => {
        expect(() => validatePolicyInput({ ...validPolicy, exactCacheEnabled: true })).toThrow(
          /exactCacheEnabled cannot be enabled because caching is deferred/,
        );
      });

      it('rejects semanticCacheEnabled = true because caching is deferred', () => {
        expect(() => validatePolicyInput({ ...validPolicy, semanticCacheEnabled: true })).toThrow(
          /semanticCacheEnabled cannot be enabled because caching is deferred/,
        );
      });
    });
  });

  describe('VirtualKeyManagementService Creation & Secret Containment', () => {
    it('creates key and returns plaintext rawKey exactly once with deny-all defaults', async () => {
      const mockPrefix = 'gw_live_' + 'A'.repeat(11);
      const mockSecret = 'B'.repeat(43);
      const mockRawKey = `${mockPrefix}_${mockSecret}`;

      const mockVkResult = {
        id: VALID_UUID,
        orgId: VALID_UUID_2,
        name: 'Production Key',
        keyPrefix: mockPrefix,
        createdAt: new Date('2026-11-21T10:00:00.000Z'),
        rawKey: mockRawKey,
      };

      const mockVkService = {
        createKey: vi.fn().mockResolvedValue(mockVkResult),
      };

      const mockPool = {} as pg.Pool;
      const service = new VirtualKeyManagementService({
        pool: mockPool,
        virtualKeyService: mockVkService as unknown as VirtualKeyService,
      });

      const res = await service.createKey(VALID_UUID_2, 'Production Key');

      expect(mockVkService.createKey).toHaveBeenCalledWith({
        orgId: VALID_UUID_2,
        name: 'Production Key',
      });

      expect(res.id).toBe(VALID_UUID);
      expect(res.name).toBe('Production Key');
      expect(res.keyPrefix).toBe(mockPrefix);
      expect(res.createdAt).toBe('2026-11-21T10:00:00.000Z');
      expect(res.rawKey).toBe(mockRawKey);
      expect(res.allowedModels).toEqual([]);
      expect(res.rpmLimit).toBe(1);
      expect(res.tpmLimit).toBe(1);
      expect(res.concurrentStreamLimit).toBe(1);
      expect(res.exactCacheEnabled).toBe(false);
      expect(res.semanticCacheEnabled).toBe(false);
      expect(res.piiRedactionEnabled).toBe(true);
      expect(res.storePayloads).toBe(false);
      expect(res.revokedAt).toBeNull();

      // Verifier hash is strictly excluded
      const record = res as unknown as Record<string, unknown>;
      expect(record['keyHash']).toBeUndefined();
      expect(record['key_hash']).toBeUndefined();
    });
  });
});
