import crypto from 'node:crypto';
import type pg from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { generateKeyMaterial } from './virtual-key.js';
import {
  type IVirtualKeyRateLimiter,
  VirtualKeyAuthError,
  VirtualKeyAuthenticatorService,
  type VirtualKeyPolicy,
} from './virtual-key-authenticator.js';

describe('VirtualKeyAuthenticatorService Unit Suite (SW-1.6.2)', () => {
  const TEST_ORG_ID = 'a0000001-0000-4000-8000-000000000001';
  const TEST_KEY_ID = 'b0000002-0000-4000-8000-000000000002';
  const VALID_CLIENT_IP = '198.51.100.1';

  function createMockRateLimiter(): IVirtualKeyRateLimiter {
    return {
      assertNotRateLimited: vi.fn().mockResolvedValue(undefined),
      reset: vi.fn().mockResolvedValue(undefined),
    };
  }

  function createMockPool(rows: unknown[] = []): pg.Pool {
    return {
      query: vi.fn().mockResolvedValue({ rows }),
    } as unknown as pg.Pool;
  }

  const validDbRow = {
    id: TEST_KEY_ID,
    org_id: TEST_ORG_ID,
    revoked_at: null,
    allowed_models: ['model-a', 'model-b'],
    rpm_limit: 100,
    tpm_limit: 10000,
    concurrent_stream_limit: 10,
    exact_cache_enabled: true,
    semantic_cache_enabled: false,
    pii_redaction_enabled: true,
    store_payloads: false,
  };

  describe('1. Configuration & Instantiation', () => {
    it('throws CONFIGURATION_ERROR if options object is missing', () => {
      expect(
        () =>
          new VirtualKeyAuthenticatorService(
            undefined as unknown as { pool: pg.Pool; rateLimiter: IVirtualKeyRateLimiter },
          ),
      ).toThrow(VirtualKeyAuthError);
      expect(
        () =>
          new VirtualKeyAuthenticatorService(
            undefined as unknown as { pool: pg.Pool; rateLimiter: IVirtualKeyRateLimiter },
          ),
      ).toThrow(/options must be provided/);
    });

    it('throws CONFIGURATION_ERROR if PostgreSQL pool is missing', () => {
      expect(
        () =>
          new VirtualKeyAuthenticatorService({
            pool: undefined as unknown as pg.Pool,
            rateLimiter: createMockRateLimiter(),
          }),
      ).toThrow(VirtualKeyAuthError);
    });

    it('throws CONFIGURATION_ERROR if rateLimiter is missing', () => {
      expect(
        () =>
          new VirtualKeyAuthenticatorService({
            pool: createMockPool(),
            rateLimiter: undefined as unknown as IVirtualKeyRateLimiter,
          }),
      ).toThrow(VirtualKeyAuthError);
    });
  });

  describe('2. Per-IP Abuse Limiting Enforcement', () => {
    it('fails closed when client IP is missing, empty, or whitespace', async () => {
      const service = new VirtualKeyAuthenticatorService({
        pool: createMockPool([validDbRow]),
        rateLimiter: createMockRateLimiter(),
      });

      await expect(service.authenticateKey('gw_live_any_key', '')).rejects.toThrow(
        VirtualKeyAuthError,
      );
      await expect(
        service.authenticateKey('gw_live_any_key', undefined as unknown as string),
      ).rejects.toThrow(VirtualKeyAuthError);
      await expect(service.authenticateKey('gw_live_any_key', '   ')).rejects.toThrow(
        VirtualKeyAuthError,
      );
    });

    it('enforces rate limiter check before any key parsing or database query', async () => {
      const rateLimiter = createMockRateLimiter();
      const pool = createMockPool([validDbRow]);
      const service = new VirtualKeyAuthenticatorService({ pool, rateLimiter });

      const material = generateKeyMaterial();
      await service.authenticateKey(material.rawKey, VALID_CLIENT_IP);

      expect(rateLimiter.assertNotRateLimited).toHaveBeenCalledWith(VALID_CLIENT_IP);
      expect(pool.query).toHaveBeenCalledTimes(1);
    });

    it('rate limiter failure (RATE_LIMITED) prevents database query', async () => {
      const rateLimiter = {
        assertNotRateLimited: vi
          .fn()
          .mockRejectedValue(new VirtualKeyAuthError('RATE_LIMITED', 'Too many attempts')),
      };
      const pool = createMockPool([validDbRow]);
      const service = new VirtualKeyAuthenticatorService({ pool, rateLimiter });

      const material = generateKeyMaterial();
      await expect(service.authenticateKey(material.rawKey, VALID_CLIENT_IP)).rejects.toThrow(
        VirtualKeyAuthError,
      );

      expect(pool.query).not.toHaveBeenCalled();
    });

    it('rate limiter failure (SERVICE_UNAVAILABLE) prevents database query', async () => {
      const rateLimiter = {
        assertNotRateLimited: vi
          .fn()
          .mockRejectedValue(new VirtualKeyAuthError('SERVICE_UNAVAILABLE', 'Redis down')),
      };
      const pool = createMockPool([validDbRow]);
      const service = new VirtualKeyAuthenticatorService({ pool, rateLimiter });

      const material = generateKeyMaterial();
      await expect(service.authenticateKey(material.rawKey, VALID_CLIENT_IP)).rejects.toThrow(
        VirtualKeyAuthError,
      );

      expect(pool.query).not.toHaveBeenCalled();
    });

    it('malformed key attempt consumes IP allowance before rejection', async () => {
      const rateLimiter = createMockRateLimiter();
      const pool = createMockPool();
      const service = new VirtualKeyAuthenticatorService({ pool, rateLimiter });

      const result = await service.authenticateKey('invalid-key-shape', VALID_CLIENT_IP);

      expect(rateLimiter.assertNotRateLimited).toHaveBeenCalledWith(VALID_CLIENT_IP);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('MALFORMED_KEY');
      expect(pool.query).not.toHaveBeenCalled();
    });
  });

  describe('3. Canonical Key Parsing and Hash Derivation', () => {
    it('computes 32-byte SHA-256 verifier directly from decoded 32 secret bytes', async () => {
      const pool = createMockPool([validDbRow]);
      const service = new VirtualKeyAuthenticatorService({
        pool,
        rateLimiter: createMockRateLimiter(),
      });

      const material = generateKeyMaterial();
      await service.authenticateKey(material.rawKey, VALID_CLIENT_IP);

      expect(pool.query).toHaveBeenCalledTimes(1);
      const queryCall = vi.mocked(pool.query).mock.calls[0]!;
      const boundArgs = queryCall[1] as unknown[];
      expect(boundArgs).toHaveLength(1);

      const boundHash = boundArgs[0] as Buffer;
      expect(Buffer.isBuffer(boundHash)).toBe(true);
      expect(boundHash.length).toBe(32);

      // The bound hash must NOT be the printable 63-char raw key or public prefix
      expect(boundHash.toString()).not.toBe(material.rawKey);
      expect(boundHash.toString()).not.toBe(material.publicPrefix);
      expect(boundHash.toString()).not.toBe(material.keyPrefix);
    });

    it('rejects keys with wrong length (not exactly 63 characters)', async () => {
      const service = new VirtualKeyAuthenticatorService({
        pool: createMockPool(),
        rateLimiter: createMockRateLimiter(),
      });

      // 62 chars
      const shortKey = 'gw_live_' + 'A'.repeat(11) + '_' + 'B'.repeat(42);
      expect(shortKey.length).toBe(62);
      const res1 = await service.authenticateKey(shortKey, VALID_CLIENT_IP);
      expect(res1.valid).toBe(false);
      expect(res1.reason).toBe('MALFORMED_KEY');

      // 64 chars
      const longKey = 'gw_live_' + 'A'.repeat(11) + '_' + 'B'.repeat(44);
      expect(longKey.length).toBe(64);
      const res2 = await service.authenticateKey(longKey, VALID_CLIENT_IP);
      expect(res2.valid).toBe(false);
      expect(res2.reason).toBe('MALFORMED_KEY');
    });

    it('rejects keys without "gw_live_" prefix', async () => {
      const service = new VirtualKeyAuthenticatorService({
        pool: createMockPool(),
        rateLimiter: createMockRateLimiter(),
      });

      const badPrefixKey = 'sk_live_' + 'A'.repeat(11) + '_' + 'B'.repeat(43);
      const res = await service.authenticateKey(badPrefixKey, VALID_CLIENT_IP);
      expect(res.valid).toBe(false);
      expect(res.reason).toBe('MALFORMED_KEY');
    });

    it('rejects noncanonical base64url padding bits in secret segment', async () => {
      const service = new VirtualKeyAuthenticatorService({
        pool: createMockPool(),
        rateLimiter: createMockRateLimiter(),
      });

      // 42 'A's + 'B' decodes to same 32 bytes as 43 'A's in noncanonical decoders
      const nonCanonicalSecret = 'A'.repeat(42) + 'B';
      const nonCanonicalKey = 'gw_live_' + 'A'.repeat(11) + '_' + nonCanonicalSecret;

      const res = await service.authenticateKey(nonCanonicalKey, VALID_CLIENT_IP);
      expect(res.valid).toBe(false);
      expect(res.reason).toBe('MALFORMED_KEY');
    });

    it('rejects noncanonical base64url padding bits in prefix segment', async () => {
      const service = new VirtualKeyAuthenticatorService({
        pool: createMockPool(),
        rateLimiter: createMockRateLimiter(),
      });

      // 10 'A's + 'B'
      const nonCanonicalPrefix = 'A'.repeat(10) + 'B';
      const nonCanonicalKey = 'gw_live_' + nonCanonicalPrefix + '_' + 'A'.repeat(43);

      const res = await service.authenticateKey(nonCanonicalKey, VALID_CLIENT_IP);
      expect(res.valid).toBe(false);
      expect(res.reason).toBe('MALFORMED_KEY');
    });

    it('rejects padding characters ("=")', async () => {
      const service = new VirtualKeyAuthenticatorService({
        pool: createMockPool(),
        rateLimiter: createMockRateLimiter(),
      });

      const paddedKey = 'gw_live_' + 'A'.repeat(11) + '_' + 'B'.repeat(42) + '=';
      const res = await service.authenticateKey(paddedKey, VALID_CLIENT_IP);
      expect(res.valid).toBe(false);
      expect(res.reason).toBe('MALFORMED_KEY');
    });

    it('rejects non-base64url characters ("+" and "/")', async () => {
      const service = new VirtualKeyAuthenticatorService({
        pool: createMockPool(),
        rateLimiter: createMockRateLimiter(),
      });

      const plusKey = 'gw_live_' + 'A'.repeat(10) + '+' + '_' + 'B'.repeat(43);
      const slashKey = 'gw_live_' + 'A'.repeat(11) + '_' + 'B'.repeat(42) + '/';

      expect((await service.authenticateKey(plusKey, VALID_CLIENT_IP)).valid).toBe(false);
      expect((await service.authenticateKey(slashKey, VALID_CLIENT_IP)).valid).toBe(false);
    });

    it('rejects whitespace and control characters', async () => {
      const service = new VirtualKeyAuthenticatorService({
        pool: createMockPool(),
        rateLimiter: createMockRateLimiter(),
      });

      const spaceKey = 'gw_live_ ' + 'A'.repeat(10) + '_' + 'B'.repeat(43);
      const tabKey = 'gw_live_' + 'A'.repeat(11) + '_\t' + 'B'.repeat(42);

      expect((await service.authenticateKey(spaceKey, VALID_CLIENT_IP)).valid).toBe(false);
      expect((await service.authenticateKey(tabKey, VALID_CLIENT_IP)).valid).toBe(false);
    });

    it('parses valid keys with underscores and hyphens in segments', async () => {
      const pool = createMockPool([validDbRow]);
      const service = new VirtualKeyAuthenticatorService({
        pool,
        rateLimiter: createMockRateLimiter(),
      });

      // Byte 0 = 0xFC (binary 11111100 -> base64url index 63 '_')
      // Byte 3 = 0xF8 (binary 11111000 -> base64url index 62 '-')
      const prefixBuf = Buffer.alloc(8, 0);
      prefixBuf[0] = 0xfc; // produces leading '_'
      prefixBuf[3] = 0xf8; // produces '-'
      const prefixStr = prefixBuf.toString('base64url');
      expect(prefixStr).toContain('_');
      expect(prefixStr).toContain('-');

      const secretBuf = Buffer.alloc(32, 0);
      secretBuf[0] = 0xfc; // produces leading '_'
      secretBuf[3] = 0xf8; // produces '-'
      const secretStr = secretBuf.toString('base64url');
      expect(secretStr).toContain('_');
      expect(secretStr).toContain('-');

      const specialCharKey = `gw_live_${prefixStr}_${secretStr}`;
      expect(specialCharKey.length).toBe(63);

      const res = await service.authenticateKey(specialCharKey, VALID_CLIENT_IP);
      expect(res.valid).toBe(true);
      expect(pool.query).toHaveBeenCalledTimes(1);
    });
  });

  describe('4. PostgreSQL Lookup & Result Handling', () => {
    it('returns valid: false (KEY_NOT_FOUND) when zero rows returned', async () => {
      const pool = createMockPool([]);
      const service = new VirtualKeyAuthenticatorService({
        pool,
        rateLimiter: createMockRateLimiter(),
      });

      const material = generateKeyMaterial();
      const res = await service.authenticateKey(material.rawKey, VALID_CLIENT_IP);

      expect(res.valid).toBe(false);
      expect(res.reason).toBe('KEY_NOT_FOUND');
      expect(res.principal).toBeUndefined();
    });

    it('returns valid: false (KEY_REVOKED) when key has non-null revoked_at', async () => {
      const revokedRow = {
        ...validDbRow,
        revoked_at: new Date('2026-11-20T12:00:00Z'),
      };
      const pool = createMockPool([revokedRow]);
      const service = new VirtualKeyAuthenticatorService({
        pool,
        rateLimiter: createMockRateLimiter(),
      });

      const material = generateKeyMaterial();
      const res = await service.authenticateKey(material.rawKey, VALID_CLIENT_IP);

      expect(res.valid).toBe(false);
      expect(res.reason).toBe('KEY_REVOKED');
      expect(res.principal).toBeUndefined();
    });

    it('throws INTEGRITY_ERROR when database returns multiple matching rows', async () => {
      const pool = createMockPool([validDbRow, { ...validDbRow, id: crypto.randomUUID() }]);
      const service = new VirtualKeyAuthenticatorService({
        pool,
        rateLimiter: createMockRateLimiter(),
      });

      const material = generateKeyMaterial();
      await expect(service.authenticateKey(material.rawKey, VALID_CLIENT_IP)).rejects.toThrow(
        VirtualKeyAuthError,
      );
      try {
        await service.authenticateKey(material.rawKey, VALID_CLIENT_IP);
      } catch (err) {
        expect((err as VirtualKeyAuthError).reason).toBe('INTEGRITY_ERROR');
      }
    });

    it('fails closed with SERVICE_UNAVAILABLE on database query errors', async () => {
      const pool = {
        query: vi.fn().mockRejectedValue(new Error('Connection terminated unexpectedly')),
      } as unknown as pg.Pool;
      const service = new VirtualKeyAuthenticatorService({
        pool,
        rateLimiter: createMockRateLimiter(),
      });

      const material = generateKeyMaterial();
      await expect(service.authenticateKey(material.rawKey, VALID_CLIENT_IP)).rejects.toThrow(
        VirtualKeyAuthError,
      );
      try {
        await service.authenticateKey(material.rawKey, VALID_CLIENT_IP);
      } catch (err) {
        expect((err as VirtualKeyAuthError).reason).toBe('SERVICE_UNAVAILABLE');
      }
    });
  });

  describe('5. Database Policy Integrity Validation', () => {
    it.each([
      ['missing id', { ...validDbRow, id: null }],
      ['malformed id (not UUID)', { ...validDbRow, id: 'not-a-uuid' }],
      ['missing org_id', { ...validDbRow, org_id: null }],
      ['malformed org_id (not UUID)', { ...validDbRow, org_id: 'bad-org' }],
      ['null allowed_models', { ...validDbRow, allowed_models: null }],
      ['non-array allowed_models', { ...validDbRow, allowed_models: 'not-an-array' }],
      ['array with non-string allowed_models', { ...validDbRow, allowed_models: [123] }],
      ['zero rpm_limit', { ...validDbRow, rpm_limit: 0 }],
      ['negative rpm_limit', { ...validDbRow, rpm_limit: -1 }],
      ['non-integer rpm_limit', { ...validDbRow, rpm_limit: 1.5 }],
      ['zero tpm_limit', { ...validDbRow, tpm_limit: 0 }],
      ['zero concurrent_stream_limit', { ...validDbRow, concurrent_stream_limit: 0 }],
      ['non-boolean exact_cache_enabled', { ...validDbRow, exact_cache_enabled: null }],
      ['non-boolean semantic_cache_enabled', { ...validDbRow, semantic_cache_enabled: 'false' }],
      ['non-boolean pii_redaction_enabled', { ...validDbRow, pii_redaction_enabled: undefined }],
      ['non-boolean store_payloads', { ...validDbRow, store_payloads: 1 }],
    ])('fails closed with INTEGRITY_ERROR on %s', async (_desc, corruptedRow) => {
      const pool = createMockPool([corruptedRow]);
      const service = new VirtualKeyAuthenticatorService({
        pool,
        rateLimiter: createMockRateLimiter(),
      });

      const material = generateKeyMaterial();
      await expect(service.authenticateKey(material.rawKey, VALID_CLIENT_IP)).rejects.toThrow(
        VirtualKeyAuthError,
      );
      try {
        await service.authenticateKey(material.rawKey, VALID_CLIENT_IP);
      } catch (err) {
        expect((err as VirtualKeyAuthError).reason).toBe('INTEGRITY_ERROR');
      }
    });
  });

  describe('6. Successful Principal Construction & Immutability', () => {
    it('returns trusted frozen principal with only authorized policy fields', async () => {
      const pool = createMockPool([validDbRow]);
      const service = new VirtualKeyAuthenticatorService({
        pool,
        rateLimiter: createMockRateLimiter(),
      });

      const material = generateKeyMaterial();
      const result = await service.authenticateKey(material.rawKey, VALID_CLIENT_IP);

      expect(result.valid).toBe(true);
      expect(result.principal).toBeDefined();

      const principal = result.principal!;
      expect(principal.type).toBe('virtual_key');
      expect(principal.keyId).toBe(TEST_KEY_ID);
      expect(principal.orgId).toBe(TEST_ORG_ID);

      // Principal must be frozen
      expect(Object.isFrozen(principal)).toBe(true);
      expect(Object.isFrozen(principal.keyPolicy)).toBe(true);

      const policy = principal.keyPolicy!;
      expect(policy.allowedModels).toEqual(['model-a', 'model-b']);
      expect(Object.isFrozen(policy.allowedModels)).toBe(true);
      expect(policy.rpmLimit).toBe(100);
      expect(policy.tpmLimit).toBe(10000);
      expect(policy.concurrentStreamLimit).toBe(10);
      expect(policy.exactCacheEnabled).toBe(true);
      expect(policy.semanticCacheEnabled).toBe(false);
      expect(policy.piiRedactionEnabled).toBe(true);
      expect(policy.storePayloads).toBe(false);

      // Sensitive fields must NOT be present
      expect('key_hash' in principal).toBe(false);
      expect('key_prefix' in principal).toBe(false);
      expect('rawKey' in principal).toBe(false);
      expect('secret' in principal).toBe(false);
      expect('role' in principal).toBe(false);
      expect('userId' in principal).toBe(false);
    });

    it('preserves empty allowed_models array without inventing permissive defaults', async () => {
      const emptyModelsRow = {
        ...validDbRow,
        allowed_models: [],
      };
      const pool = createMockPool([emptyModelsRow]);
      const service = new VirtualKeyAuthenticatorService({
        pool,
        rateLimiter: createMockRateLimiter(),
      });

      const material = generateKeyMaterial();
      const result = await service.authenticateKey(material.rawKey, VALID_CLIENT_IP);

      expect(result.valid).toBe(true);
      const principal = result.principal!;
      expect(principal.keyPolicy).toBeDefined();
      const policy = principal.keyPolicy as VirtualKeyPolicy;
      expect(policy.allowedModels).toEqual([]);
      expect(policy.allowedModels.length).toBe(0);
    });
  });
});
