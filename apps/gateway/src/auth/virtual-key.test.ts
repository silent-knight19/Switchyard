import crypto from 'node:crypto';
import type pg from 'pg';
import { describe, expect, it, vi } from 'vitest';
import {
  generateKeyMaterial,
  parseRawKey,
  VirtualKeyError,
  VirtualKeyService,
} from './virtual-key.js';

describe('SW-1.6.1: Virtual Key Issuance Unit Tests (Section 13)', () => {
  const VALID_ORG_ID = '11111111-1111-4111-8111-111111111111';
  const VALID_NAME = 'Production Virtual Key';

  describe('Key Material & Cryptographic Invariants (Tests 1–14)', () => {
    it('1. Secret contains exactly 32 random bytes', () => {
      const randomBytesSpy = vi.spyOn(crypto, 'randomBytes');
      generateKeyMaterial();

      // Check that crypto.randomBytes was called with 32 for the secret
      expect(randomBytesSpy).toHaveBeenCalledWith(32);
      randomBytesSpy.mockRestore();
    });

    it('2. Canonical secret is exactly 43 base64url characters', () => {
      const material = generateKeyMaterial();
      const parsed = parseRawKey(material.rawKey);
      expect(parsed).not.toBeNull();
      expect(parsed!.secret.length).toBe(43);
      expect(/^[A-Za-z0-9_-]{43}$/.test(parsed!.secret)).toBe(true);
    });

    it('3. Public prefix uses exactly 8 random bytes', () => {
      const randomBytesSpy = vi.spyOn(crypto, 'randomBytes');
      generateKeyMaterial();

      // Check that crypto.randomBytes was called with 8 for the prefix
      expect(randomBytesSpy).toHaveBeenCalledWith(8);
      randomBytesSpy.mockRestore();
    });

    it('4. Canonical public prefix is exactly 11 base64url characters', () => {
      const material = generateKeyMaterial();
      expect(material.publicPrefix.length).toBe(11);
      expect(/^[A-Za-z0-9_-]{11}$/.test(material.publicPrefix)).toBe(true);
      expect(material.keyPrefix).toBe(`gw_live_${material.publicPrefix}`);
    });

    it('5. Full raw key uses the exact approved format (gw_live_<11>_<43>)', () => {
      const material = generateKeyMaterial();
      const match = /^gw_live_([A-Za-z0-9_-]{11})_([A-Za-z0-9_-]{43})$/.exec(material.rawKey);
      expect(match).not.toBeNull();
      expect(match![1]).toBe(material.publicPrefix);
    });

    it('6. Full key is exactly 63 ASCII characters', () => {
      const material = generateKeyMaterial();
      expect(material.rawKey.length).toBe(63);
      // Verify all characters are strictly ASCII printable
      expect(/^[\x20-\x7E]+$/.test(material.rawKey)).toBe(true);
    });

    it('7. Secret and public prefix use independent randomness', () => {
      const randomBytesSpy = vi.spyOn(crypto, 'randomBytes');
      generateKeyMaterial();

      // Two distinct calls: 8 bytes for prefix, 32 bytes for secret
      const calls = randomBytesSpy.mock.calls.map((c) => c[0]);
      expect(calls).toContain(8);
      expect(calls).toContain(32);
      randomBytesSpy.mockRestore();
    });

    it('8. Different issuance calls produce independent secrets', () => {
      const mat1 = generateKeyMaterial();
      const mat2 = generateKeyMaterial();

      expect(mat1.rawKey).not.toBe(mat2.rawKey);
      expect(mat1.publicPrefix).not.toBe(mat2.publicPrefix);
      expect(mat1.keyHash.equals(mat2.keyHash)).toBe(false);
    });

    it('9. No padding or standard base64 characters are introduced', () => {
      for (let i = 0; i < 50; i++) {
        const material = generateKeyMaterial();
        expect(material.rawKey).not.toContain('=');
        expect(material.rawKey).not.toContain('+');
        expect(material.rawKey).not.toContain('/');
      }
    });

    it('10. SHA-256 verifier is exactly 32 bytes', () => {
      const material = generateKeyMaterial();
      expect(Buffer.isBuffer(material.keyHash)).toBe(true);
      expect(material.keyHash.length).toBe(32);
    });

    it('11. Verifier matches SHA-256 of the decoded secret bytes', () => {
      const material = generateKeyMaterial();
      const parsed = parseRawKey(material.rawKey);
      expect(parsed).not.toBeNull();
      const decodedSecretBytes = Buffer.from(parsed!.secret, 'base64url');
      expect(decodedSecretBytes.length).toBe(32);

      const expectedHash = crypto.createHash('sha256').update(decodedSecretBytes).digest();
      expect(material.keyHash.equals(expectedHash)).toBe(true);
    });

    it('12. Verifier is not computed from the printable full key', () => {
      const material = generateKeyMaterial();
      const fullKeyHash = crypto.createHash('sha256').update(material.rawKey, 'utf8').digest();
      expect(material.keyHash.equals(fullKeyHash)).toBe(false);
    });

    it('13. Verifier is not computed from the public prefix', () => {
      const material = generateKeyMaterial();
      const prefixHash = crypto.createHash('sha256').update(material.publicPrefix, 'utf8').digest();
      expect(material.keyHash.equals(prefixHash)).toBe(false);
    });

    it('14. No custom PRNG or predictable seed exists', () => {
      // Confirm that Node.js built-in crypto.randomBytes is the sole entropy source
      const randomBytesSpy = vi.spyOn(crypto, 'randomBytes');
      const mathRandomSpy = vi.spyOn(Math, 'random');

      generateKeyMaterial();

      expect(randomBytesSpy).toHaveBeenCalled();
      expect(mathRandomSpy).not.toHaveBeenCalled();

      randomBytesSpy.mockRestore();
      mathRandomSpy.mockRestore();
    });
  });

  describe('Input Validation (Tests 15–22)', () => {
    function createMockPool() {
      const client = {
        query: vi.fn(),
        release: vi.fn(),
        escapeIdentifier: (s: string) => `"${s}"`,
        escapeLiteral: (s: string) => `'${s}'`,
      };
      const pool = {
        connect: vi.fn().mockResolvedValue(client),
      } as unknown as pg.Pool;
      return { pool, client };
    }

    it('15. Valid UUID and name accepted', async () => {
      const { pool, client } = createMockPool();
      client.query.mockImplementation(
        async (sql: string | { text: string; values?: unknown[] }, values?: unknown[]) => {
          const text = typeof sql === 'string' ? sql : sql.text;
          const vals = typeof sql === 'object' && sql.values ? sql.values : values;
          if (text === 'BEGIN') return { command: 'BEGIN' };
          if (text.includes('set_config')) return { rows: [] };
          if (text.includes('INSERT INTO virtual_keys')) {
            return {
              rows: [
                {
                  id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                  org_id: VALID_ORG_ID,
                  name: VALID_NAME,
                  key_prefix: (vals?.[3] as string) ?? 'hint',
                  created_at: new Date(),
                },
              ],
            };
          }
          if (text === 'COMMIT') return { command: 'COMMIT' };
          if (text === 'RESET ALL' || text === 'DISCARD TEMP') return { rows: [] };
          if (text.includes('current_setting')) return { rows: [{ cur_org: null }] };
          return { rows: [] };
        },
      );

      const service = new VirtualKeyService(pool);
      const res = await service.createKey({ orgId: VALID_ORG_ID, name: VALID_NAME });
      expect(res.orgId).toBe(VALID_ORG_ID);
      expect(res.name).toBe(VALID_NAME);
      expect(res.rawKey).toMatch(/^gw_live_[A-Za-z0-9_-]{11}_[A-Za-z0-9_-]{43}$/);
    });

    it('16. Invalid UUID rejected', async () => {
      const { pool } = createMockPool();
      const service = new VirtualKeyService(pool);

      await expect(
        service.createKey({ orgId: 'not-a-uuid', name: VALID_NAME }),
      ).rejects.toMatchObject({
        name: 'VirtualKeyError',
        reason: 'INVALID_INPUT',
      });

      await expect(service.createKey({ orgId: '', name: VALID_NAME })).rejects.toMatchObject({
        name: 'VirtualKeyError',
        reason: 'INVALID_INPUT',
      });
    });

    it('17. Empty name rejected', async () => {
      const { pool } = createMockPool();
      const service = new VirtualKeyService(pool);

      await expect(service.createKey({ orgId: VALID_ORG_ID, name: '' })).rejects.toMatchObject({
        name: 'VirtualKeyError',
        reason: 'INVALID_INPUT',
      });
    });

    it('18. Whitespace-only name rejected', async () => {
      const { pool } = createMockPool();
      const service = new VirtualKeyService(pool);

      await expect(
        service.createKey({ orgId: VALID_ORG_ID, name: '   \t  \n  ' }),
      ).rejects.toMatchObject({
        name: 'VirtualKeyError',
        reason: 'INVALID_INPUT',
      });
    });

    it('19. Oversized name rejected (> 255 UTF-8 bytes)', async () => {
      const { pool } = createMockPool();
      const service = new VirtualKeyService(pool);
      const oversized = 'a'.repeat(256);

      await expect(
        service.createKey({ orgId: VALID_ORG_ID, name: oversized }),
      ).rejects.toMatchObject({
        name: 'VirtualKeyError',
        reason: 'INVALID_INPUT',
      });

      // Also verify multi-byte UTF-8 boundary (e.g. 128 characters of 2-byte 'é' = 256 bytes)
      const multiByteOversized = 'é'.repeat(128); // 128 * 2 = 256 bytes
      await expect(
        service.createKey({ orgId: VALID_ORG_ID, name: multiByteOversized }),
      ).rejects.toMatchObject({
        name: 'VirtualKeyError',
        reason: 'INVALID_INPUT',
      });
    });

    it('20. Control-character name rejected (NUL, C0, C1)', async () => {
      const { pool } = createMockPool();
      const service = new VirtualKeyService(pool);

      const controlSamples = [
        'Key\0Name', // NUL
        'Key\x07Name', // Bell (C0)
        'Key\rName', // CR (C0)
        'Key\nName', // LF (C0)
        'Key\tName', // TAB (C0)
        'Key\x7FName', // DEL
        'Key\u0080Name', // C1
        'Key\u0085Name', // Next line (C1)
        'Key\u009FName', // C1
      ];

      for (const sample of controlSamples) {
        await expect(
          service.createKey({ orgId: VALID_ORG_ID, name: sample }),
        ).rejects.toMatchObject({
          name: 'VirtualKeyError',
          reason: 'INVALID_INPUT',
        });
      }
    });

    it('21. Non-string name rejected', async () => {
      const { pool } = createMockPool();
      const service = new VirtualKeyService(pool);

      await expect(
        service.createKey({ orgId: VALID_ORG_ID, name: 123 as unknown as string }),
      ).rejects.toMatchObject({
        name: 'VirtualKeyError',
        reason: 'INVALID_INPUT',
      });

      await expect(
        service.createKey({ orgId: VALID_ORG_ID, name: null as unknown as string }),
      ).rejects.toMatchObject({
        name: 'VirtualKeyError',
        reason: 'INVALID_INPUT',
      });
    });

    it('22. Valid name is not silently truncated', async () => {
      const { pool, client } = createMockPool();
      let insertedName: string | undefined;

      client.query.mockImplementation(
        async (sql: string | { text: string; values?: unknown[] }, values?: unknown[]) => {
          const text = typeof sql === 'string' ? sql : sql.text;
          const vals = typeof sql === 'object' && sql.values ? sql.values : values;
          if (text === 'BEGIN') return { command: 'BEGIN' };
          if (text.includes('set_config')) return { rows: [] };
          if (text.includes('INSERT INTO virtual_keys')) {
            insertedName = vals?.[2] as string;
            return {
              rows: [
                {
                  id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                  org_id: VALID_ORG_ID,
                  name: insertedName,
                  key_prefix: (vals?.[3] as string) ?? 'hint',
                  created_at: new Date(),
                },
              ],
            };
          }
          if (text === 'COMMIT') return { command: 'COMMIT' };
          if (text === 'RESET ALL' || text === 'DISCARD TEMP') return { rows: [] };
          if (text.includes('current_setting')) return { rows: [{ cur_org: null }] };
          return { rows: [] };
        },
      );

      const service = new VirtualKeyService(pool);
      // Exactly 255 bytes
      const exact255 = 'x'.repeat(255);
      const res = await service.createKey({ orgId: VALID_ORG_ID, name: exact255 });
      expect(insertedName).toBe(exact255);
      expect(res.name).toBe(exact255);
      expect(res.name.length).toBe(255);
    });
  });

  describe('Failure Behavior & Collision Handling (Tests 23–30)', () => {
    function createMockPool() {
      const client = {
        query: vi.fn(),
        release: vi.fn(),
        escapeIdentifier: (s: string) => `"${s}"`,
        escapeLiteral: (s: string) => `'${s}'`,
      };
      const pool = {
        connect: vi.fn().mockResolvedValue(client),
      } as unknown as pg.Pool;
      return { pool, client };
    }

    it('23. Known unique key-hash violation triggers regeneration', async () => {
      const { pool, client } = createMockPool();
      let insertAttempts = 0;

      client.query.mockImplementation(
        async (sql: string | { text: string; values?: unknown[] }, values?: unknown[]) => {
          const text = typeof sql === 'string' ? sql : sql.text;
          const vals = typeof sql === 'object' && sql.values ? sql.values : values;
          if (text === 'BEGIN') return { command: 'BEGIN' };
          if (text.includes('set_config')) return { rows: [] };
          if (text.includes('INSERT INTO virtual_keys')) {
            insertAttempts++;
            if (insertAttempts === 1) {
              const err = new Error('duplicate key value violates unique constraint') as Error & {
                code: string;
                constraint: string;
              };
              err.code = '23505';
              err.constraint = 'virtual_keys_key_hash_key';
              throw err;
            }
            return {
              rows: [
                {
                  id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
                  org_id: VALID_ORG_ID,
                  name: VALID_NAME,
                  key_prefix: (vals?.[3] as string) ?? 'hint',
                  created_at: new Date(),
                },
              ],
            };
          }
          if (text === 'ROLLBACK') return { command: 'ROLLBACK' };
          if (text === 'COMMIT') return { command: 'COMMIT' };
          if (text === 'RESET ALL' || text === 'DISCARD TEMP') return { rows: [] };
          if (text.includes('current_setting')) return { rows: [{ cur_org: null }] };
          return { rows: [] };
        },
      );

      const service = new VirtualKeyService(pool);
      const res = await service.createKey({ orgId: VALID_ORG_ID, name: VALID_NAME });
      expect(insertAttempts).toBe(2);
      expect(res.id).toBe('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
    });

    it('24. New material differs after a simulated collision', async () => {
      const { pool, client } = createMockPool();
      const generatedRawKeys: string[] = [];

      client.query.mockImplementation(
        async (sql: string | { text: string; values?: unknown[] }, values?: unknown[]) => {
          const text = typeof sql === 'string' ? sql : sql.text;
          const vals = typeof sql === 'object' && sql.values ? sql.values : values;
          if (text === 'BEGIN') return { command: 'BEGIN' };
          if (text.includes('set_config')) return { rows: [] };
          if (text.includes('INSERT INTO virtual_keys')) {
            const prefix = vals?.[3] as string;
            generatedRawKeys.push(prefix);

            if (generatedRawKeys.length === 1) {
              const err = new Error('collision') as Error & { code: string; constraint: string };
              err.code = '23505';
              err.constraint = 'virtual_keys_key_hash_key';
              throw err;
            }

            return {
              rows: [
                {
                  id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
                  org_id: VALID_ORG_ID,
                  name: VALID_NAME,
                  key_prefix: prefix,
                  created_at: new Date(),
                },
              ],
            };
          }
          if (text === 'ROLLBACK') return { command: 'ROLLBACK' };
          if (text === 'COMMIT') return { command: 'COMMIT' };
          if (text === 'RESET ALL' || text === 'DISCARD TEMP') return { rows: [] };
          if (text.includes('current_setting')) return { rows: [{ cur_org: null }] };
          return { rows: [] };
        },
      );

      const service = new VirtualKeyService(pool);
      const res = await service.createKey({ orgId: VALID_ORG_ID, name: VALID_NAME });

      expect(generatedRawKeys.length).toBe(2);
      expect(generatedRawKeys[0]).not.toBe(generatedRawKeys[1]);
      expect(res.keyPrefix).toBe(generatedRawKeys[1]);
    });

    it('25. Three consecutive hash collisions exhaust retries (KEY_COLLISION_EXHAUSTED)', async () => {
      const { pool, client } = createMockPool();
      let insertAttempts = 0;

      client.query.mockImplementation(async (sql: string | { text: string }) => {
        const text = typeof sql === 'string' ? sql : sql.text;
        if (text === 'BEGIN') return { command: 'BEGIN' };
        if (text.includes('set_config')) return { rows: [] };
        if (text.includes('INSERT INTO virtual_keys')) {
          insertAttempts++;
          const err = new Error('duplicate key') as Error & { code: string; constraint: string };
          err.code = '23505';
          err.constraint = 'virtual_keys_key_hash_key';
          throw err;
        }
        if (text === 'ROLLBACK') return { command: 'ROLLBACK' };
        if (text === 'RESET ALL' || text === 'DISCARD TEMP') return { rows: [] };
        if (text.includes('current_setting')) return { rows: [{ cur_org: null }] };
        return { rows: [] };
      });

      const service = new VirtualKeyService(pool);
      await expect(
        service.createKey({ orgId: VALID_ORG_ID, name: VALID_NAME }),
      ).rejects.toMatchObject({
        name: 'VirtualKeyError',
        reason: 'KEY_COLLISION_EXHAUSTED',
      });

      expect(insertAttempts).toBe(3);
    });

    it('26. Non-unique-constraint errors do not retry', async () => {
      const { pool, client } = createMockPool();
      let insertAttempts = 0;

      client.query.mockImplementation(async (sql: string | { text: string }) => {
        const text = typeof sql === 'string' ? sql : sql.text;
        if (text === 'BEGIN') return { command: 'BEGIN' };
        if (text.includes('set_config')) return { rows: [] };
        if (text.includes('INSERT INTO virtual_keys')) {
          insertAttempts++;
          const err = new Error('foreign key violation') as Error & { code: string };
          err.code = '23503';
          throw err;
        }
        if (text === 'ROLLBACK') return { command: 'ROLLBACK' };
        if (text === 'RESET ALL' || text === 'DISCARD TEMP') return { rows: [] };
        if (text.includes('current_setting')) return { rows: [{ cur_org: null }] };
        return { rows: [] };
      });

      const service = new VirtualKeyService(pool);
      await expect(
        service.createKey({ orgId: VALID_ORG_ID, name: VALID_NAME }),
      ).rejects.toMatchObject({
        name: 'VirtualKeyError',
        reason: 'DATABASE_CONFLICT',
      });

      expect(insertAttempts).toBe(1);
    });

    it('27. RLS/permission errors do not retry', async () => {
      const { pool, client } = createMockPool();
      let insertAttempts = 0;

      client.query.mockImplementation(async (sql: string | { text: string }) => {
        const text = typeof sql === 'string' ? sql : sql.text;
        if (text === 'BEGIN') return { command: 'BEGIN' };
        if (text.includes('set_config')) return { rows: [] };
        if (text.includes('INSERT INTO virtual_keys')) {
          insertAttempts++;
          const err = new Error('permission denied for table virtual_keys') as Error & {
            code: string;
          };
          err.code = '42501';
          throw err;
        }
        if (text === 'ROLLBACK') return { command: 'ROLLBACK' };
        if (text === 'RESET ALL' || text === 'DISCARD TEMP') return { rows: [] };
        if (text.includes('current_setting')) return { rows: [{ cur_org: null }] };
        return { rows: [] };
      });

      const service = new VirtualKeyService(pool);
      await expect(
        service.createKey({ orgId: VALID_ORG_ID, name: VALID_NAME }),
      ).rejects.toMatchObject({
        name: 'VirtualKeyError',
        reason: 'DATABASE_ERROR',
      });

      expect(insertAttempts).toBe(1);
    });

    it('28. Database errors do not return plaintext', async () => {
      const { pool, client } = createMockPool();

      client.query.mockImplementation(async (sql: string | { text: string }) => {
        const text = typeof sql === 'string' ? sql : sql.text;
        if (text === 'BEGIN') return { command: 'BEGIN' };
        if (text.includes('set_config')) return { rows: [] };
        if (text.includes('INSERT INTO virtual_keys')) {
          throw new Error('connection reset by peer');
        }
        if (text === 'ROLLBACK') return { command: 'ROLLBACK' };
        if (text === 'RESET ALL' || text === 'DISCARD TEMP') return { rows: [] };
        if (text.includes('current_setting')) return { rows: [{ cur_org: null }] };
        return { rows: [] };
      });

      const service = new VirtualKeyService(pool);
      let capturedError: unknown;
      try {
        await service.createKey({ orgId: VALID_ORG_ID, name: VALID_NAME });
      } catch (err) {
        capturedError = err;
      }

      expect(capturedError).toBeInstanceOf(VirtualKeyError);
      const vError = capturedError as VirtualKeyError;
      expect(vError.message).not.toContain('gw_live_');
    });

    it('29. Failed inserts do not claim successful issuance', async () => {
      const { pool, client } = createMockPool();

      client.query.mockImplementation(async (sql: string | { text: string }) => {
        const text = typeof sql === 'string' ? sql : sql.text;
        if (text === 'BEGIN') return { command: 'BEGIN' };
        if (text.includes('set_config')) return { rows: [] };
        if (text.includes('INSERT INTO virtual_keys')) {
          return { rows: [] }; // no rows returned
        }
        if (text === 'COMMIT') return { command: 'COMMIT' };
        if (text === 'RESET ALL' || text === 'DISCARD TEMP') return { rows: [] };
        if (text.includes('current_setting')) return { rows: [{ cur_org: null }] };
        return { rows: [] };
      });

      const service = new VirtualKeyService(pool);
      await expect(
        service.createKey({ orgId: VALID_ORG_ID, name: VALID_NAME }),
      ).rejects.toMatchObject({
        name: 'VirtualKeyError',
        reason: 'DATABASE_ERROR',
      });
    });

    it('30. No unbounded retry loop exists', async () => {
      const { pool, client } = createMockPool();
      let queryCallCount = 0;

      client.query.mockImplementation(async (sql: string | { text: string }) => {
        queryCallCount++;
        const text = typeof sql === 'string' ? sql : sql.text;
        if (text === 'BEGIN') return { command: 'BEGIN' };
        if (text.includes('set_config')) return { rows: [] };
        if (text.includes('INSERT INTO virtual_keys')) {
          const err = new Error('collision') as Error & { code: string; constraint: string };
          err.code = '23505';
          err.constraint = 'virtual_keys_key_hash_key';
          throw err;
        }
        if (text === 'ROLLBACK') return { command: 'ROLLBACK' };
        if (text === 'RESET ALL' || text === 'DISCARD TEMP') return { rows: [] };
        if (text.includes('current_setting')) return { rows: [{ cur_org: null }] };
        return { rows: [] };
      });

      const service = new VirtualKeyService(pool);
      await expect(
        service.createKey({ orgId: VALID_ORG_ID, name: VALID_NAME }),
      ).rejects.toMatchObject({
        name: 'VirtualKeyError',
        reason: 'KEY_COLLISION_EXHAUSTED',
      });

      // Max 3 transaction attempts (each has BEGIN, set_config, INSERT, ROLLBACK, RESET ALL, DISCARD TEMP, current_setting)
      // Assert that it definitely terminated and did not loop unbounded
      expect(queryCallCount).toBeLessThan(30);
    });
  });
});
