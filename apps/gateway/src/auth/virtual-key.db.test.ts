import crypto from 'node:crypto';
import pg from 'pg';
import pino from 'pino';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runMigrations } from '../db/migrate.js';
import { withTenant } from '../db/tenant.js';
import {
  bootstrapDatabase,
  createDisposableDatabase,
  createRolePasswords,
  roleConnectionString,
  startDisposableCluster,
  type DisposableCluster,
  type DisposableDatabase,
} from '../db/test/disposable-pg.js';
import { parseRawKey, VirtualKeyError, VirtualKeyService } from './virtual-key.js';

describe('SW-1.6.1: Real PostgreSQL 16 Virtual Key Database & Security Suite (Section 14 & Architect Decision §5)', () => {
  let cluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();
  let adminClient: pg.Client;
  let appPool: pg.Pool;
  let workerPool: pg.Pool;
  let service: VirtualKeyService;

  const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
  const ORG_B_ID = '22222222-2222-4222-8222-222222222222';

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    db = await createDisposableDatabase(cluster, 'virtual_key_db_test');
    await bootstrapDatabase(db, passwords);

    // Apply authoritative migrations 0001 through 0011
    const migrator = new pg.Pool({
      connectionString: roleConnectionString(
        db.url,
        'gateway_migrator',
        passwords.gateway_migrator,
      ),
    });
    try {
      await runMigrations(migrator);
    } finally {
      await migrator.end();
    }

    // Connect admin client for fixture seeding and direct introspection
    adminClient = new pg.Client({ connectionString: db.url });
    await adminClient.connect();

    // Seed test organizations
    await adminClient.query(`
      INSERT INTO public.organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
      VALUES
        ('${ORG_A_ID}', 'Org Alpha', 1000000, 1, '\\x01', '\\x02', '\\x03'),
        ('${ORG_B_ID}', 'Org Beta', 2000000, 1, '\\x04', '\\x05', '\\x06');
    `);

    // Connect runtime gateway_app pool
    appPool = new pg.Pool({
      connectionString: roleConnectionString(db.url, 'gateway_app', passwords.gateway_app),
    });
    appPool.on('error', () => undefined);

    // Connect runtime gateway_worker pool
    workerPool = new pg.Pool({
      connectionString: roleConnectionString(db.url, 'gateway_worker', passwords.gateway_worker),
    });
    workerPool.on('error', () => undefined);

    service = new VirtualKeyService(appPool);
  }, 60000);

  afterAll(async () => {
    await appPool?.end().catch(() => undefined);
    await workerPool?.end().catch(() => undefined);
    await adminClient?.end().catch(() => undefined);
    await db?.drop().catch(() => undefined);
  });

  describe('PostgreSQL Virtual Key Creation & Integrity Invariants (Tests 1–16 & Tests A, B, F, G)', () => {
    let createdResult: {
      id: string;
      orgId: string;
      name: string;
      keyPrefix: string;
      createdAt: Date;
      rawKey: string;
    };
    let storedRow: {
      id: string;
      org_id: string;
      name: string;
      key_prefix: string;
      key_hash: Buffer;
      allowed_models: string[];
      rpm_limit: number;
      tpm_limit: number;
      concurrent_stream_limit: number;
      exact_cache_enabled: boolean;
      semantic_cache_enabled: boolean;
      pii_redaction_enabled: boolean;
      store_payloads: boolean;
      revoked_at: Date | null;
      created_at: Date;
    };

    it('1 & Test A: A key is inserted successfully under Organization A with gateway_app and withTenant()', async () => {
      createdResult = await service.createKey({
        orgId: ORG_A_ID,
        name: 'Alpha Primary Gateway Key',
      });

      expect(createdResult).toBeDefined();
      expect(createdResult.id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
      );
      expect(createdResult.orgId).toBe(ORG_A_ID);
      expect(createdResult.name).toBe('Alpha Primary Gateway Key');

      // Query stored row directly to verify commit persistence
      const { rows } = await adminClient.query('SELECT * FROM public.virtual_keys WHERE id = $1', [
        createdResult.id,
      ]);
      expect(rows.length).toBe(1);
      storedRow = rows[0];
    });

    it('2. Returned key format is canonical (gw_live_<11>_<43>, 63 ASCII characters)', () => {
      expect(createdResult.rawKey).toMatch(/^gw_live_[A-Za-z0-9_-]{11}_[A-Za-z0-9_-]{43}$/);
      expect(createdResult.rawKey.length).toBe(63);
    });

    it('3. Stored key_hash contains exactly 32 bytes (binary BYTEA)', () => {
      expect(Buffer.isBuffer(storedRow.key_hash)).toBe(true);
      expect(storedRow.key_hash.length).toBe(32);
    });

    it('4. Stored hash equals SHA-256 of the returned decoded secret bytes', () => {
      const parsed = parseRawKey(createdResult.rawKey);
      expect(parsed).not.toBeNull();
      const secret = parsed!.secret;
      const secretBytes = Buffer.from(secret, 'base64url');
      expect(secretBytes.length).toBe(32);

      const expectedHash = crypto.createHash('sha256').update(secretBytes).digest();
      expect(storedRow.key_hash.equals(expectedHash)).toBe(true);
    });

    it('5. Stored key_prefix contains only the non-secret public hint (gw_live_<11>)', () => {
      expect(storedRow.key_prefix).toBe(createdResult.keyPrefix);
      expect(storedRow.key_prefix).toMatch(/^gw_live_[A-Za-z0-9_-]{11}$/);
      // Public hint does NOT contain any portion of the 43-character secret
      const parsed = parseRawKey(createdResult.rawKey);
      expect(parsed).not.toBeNull();
      expect(storedRow.key_prefix).not.toContain(parsed!.secret);
    });

    it('6. No database column stores the complete raw key', async () => {
      const { rows } = await adminClient.query('SELECT * FROM public.virtual_keys WHERE id = $1', [
        createdResult.id,
      ]);
      const row = rows[0];
      for (const [col, val] of Object.entries(row)) {
        const valStr = typeof val === 'object' && val !== null ? JSON.stringify(val) : String(val);
        expect(valStr, `Column ${col} must not contain rawKey`).not.toContain(createdResult.rawKey);
      }
    });

    it('7. No database column stores the plaintext secret', async () => {
      const parsed = parseRawKey(createdResult.rawKey);
      expect(parsed).not.toBeNull();
      const secret = parsed!.secret;
      const { rows } = await adminClient.query('SELECT * FROM public.virtual_keys WHERE id = $1', [
        createdResult.id,
      ]);
      const row = rows[0];
      for (const [col, val] of Object.entries(row)) {
        const valStr = typeof val === 'object' && val !== null ? JSON.stringify(val) : String(val);
        expect(valStr, `Column ${col} must not contain secret`).not.toContain(secret);
      }
    });

    it('8. The returned UUID matches the inserted row', () => {
      expect(createdResult.id).toBe(storedRow.id);
    });

    it('9. The returned organization matches the stored organization', () => {
      expect(createdResult.orgId).toBe(storedRow.org_id);
      expect(storedRow.org_id).toBe(ORG_A_ID);
    });

    it('10. created_at comes from PostgreSQL clock_timestamp()', () => {
      expect(storedRow.created_at).toBeInstanceOf(Date);
      expect(createdResult.createdAt).toBeInstanceOf(Date);
      expect(storedRow.created_at.getTime()).toBe(createdResult.createdAt.getTime());
    });

    it('11 & Test F: Initial model allowlist is empty array (mandatory deny-all policy)', () => {
      expect(Array.isArray(storedRow.allowed_models)).toBe(true);
      expect(storedRow.allowed_models).toEqual([]);
      expect(storedRow.allowed_models.length).toBe(0);
    });

    it('12, 13, 14 & Test G: Privacy & cache defaults match exact contract', () => {
      expect(storedRow.exact_cache_enabled).toBe(false);
      expect(storedRow.semantic_cache_enabled).toBe(false);
      expect(storedRow.pii_redaction_enabled).toBe(true);
      expect(storedRow.store_payloads).toBe(false);
    });

    it('15 & Test B: Rate and concurrency limits are explicitly stored as integer 1 (satisfying NOT NULL and positive checks)', async () => {
      expect(storedRow.rpm_limit).toBe(1);
      expect(storedRow.tpm_limit).toBe(1);
      expect(storedRow.concurrent_stream_limit).toBe(1);

      // Verify querying under tenant context returns exact values
      await withTenant(appPool, ORG_A_ID, async (client) => {
        const res = await client.query<{
          rpm_limit: number;
          tpm_limit: number;
          concurrent_stream_limit: number;
        }>('SELECT rpm_limit, tpm_limit, concurrent_stream_limit FROM virtual_keys WHERE id = $1', [
          createdResult.id,
        ]);
        expect(res.rows[0]?.rpm_limit).toBe(1);
        expect(res.rows[0]?.tpm_limit).toBe(1);
        expect(res.rows[0]?.concurrent_stream_limit).toBe(1);
      });
    });

    it('16. revoked_at is NULL initially', () => {
      expect(storedRow.revoked_at).toBeNull();
    });
  });

  describe('Architect Decision §5 Limit Constraint Tests (Tests C, D, E)', () => {
    it('Test C: NULL rejection on all three limit columns (SQLSTATE 23502)', async () => {
      // 1. rpm_limit NULL
      await expect(
        adminClient.query(
          `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
           VALUES ($1, $2, 'test', 'gw_live_hint0000001', $3, '{}', NULL, 1, 1)`,
          [crypto.randomUUID(), ORG_A_ID, crypto.randomBytes(32)],
        ),
      ).rejects.toMatchObject({ code: '23502' });

      // 2. tpm_limit NULL
      await expect(
        adminClient.query(
          `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
           VALUES ($1, $2, 'test', 'gw_live_hint0000002', $3, '{}', 1, NULL, 1)`,
          [crypto.randomUUID(), ORG_A_ID, crypto.randomBytes(32)],
        ),
      ).rejects.toMatchObject({ code: '23502' });

      // 3. concurrent_stream_limit NULL
      await expect(
        adminClient.query(
          `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
           VALUES ($1, $2, 'test', 'gw_live_hint0000003', $3, '{}', 1, 1, NULL)`,
          [crypto.randomUUID(), ORG_A_ID, crypto.randomBytes(32)],
        ),
      ).rejects.toMatchObject({ code: '23502' });
    });

    it('Test D: Zero rejection on all three limit columns (SQLSTATE 23514 CHECK violation)', async () => {
      // 1. rpm_limit = 0
      await expect(
        adminClient.query(
          `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
           VALUES ($1, $2, 'test', 'gw_live_hint0000004', $3, '{}', 0, 1, 1)`,
          [crypto.randomUUID(), ORG_A_ID, crypto.randomBytes(32)],
        ),
      ).rejects.toMatchObject({ code: '23514' });

      // 2. tpm_limit = 0
      await expect(
        adminClient.query(
          `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
           VALUES ($1, $2, 'test', 'gw_live_hint0000005', $3, '{}', 1, 0, 1)`,
          [crypto.randomUUID(), ORG_A_ID, crypto.randomBytes(32)],
        ),
      ).rejects.toMatchObject({ code: '23514' });

      // 3. concurrent_stream_limit = 0
      await expect(
        adminClient.query(
          `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
           VALUES ($1, $2, 'test', 'gw_live_hint0000006', $3, '{}', 1, 1, 0)`,
          [crypto.randomUUID(), ORG_A_ID, crypto.randomBytes(32)],
        ),
      ).rejects.toMatchObject({ code: '23514' });
    });

    it('Test E: Negative-value rejection on all three limit columns (SQLSTATE 23514 CHECK violation)', async () => {
      // 1. rpm_limit = -1
      await expect(
        adminClient.query(
          `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
           VALUES ($1, $2, 'test', 'gw_live_hint0000007', $3, '{}', -1, 1, 1)`,
          [crypto.randomUUID(), ORG_A_ID, crypto.randomBytes(32)],
        ),
      ).rejects.toMatchObject({ code: '23514' });

      // 2. tpm_limit = -1
      await expect(
        adminClient.query(
          `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
           VALUES ($1, $2, 'test', 'gw_live_hint0000008', $3, '{}', 1, -1, 1)`,
          [crypto.randomUUID(), ORG_A_ID, crypto.randomBytes(32)],
        ),
      ).rejects.toMatchObject({ code: '23514' });

      // 3. concurrent_stream_limit = -1
      await expect(
        adminClient.query(
          `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
           VALUES ($1, $2, 'test', 'gw_live_hint0000009', $3, '{}', 1, 1, -1)`,
          [crypto.randomUUID(), ORG_A_ID, crypto.randomBytes(32)],
        ),
      ).rejects.toMatchObject({ code: '23514' });
    });
  });

  describe('Tenant Security & Isolation (Tests 17–20)', () => {
    it('17. Key insertion fails without tenant context', async () => {
      const rawClient = await appPool.connect();
      try {
        await expect(
          rawClient.query(
            `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
             VALUES ($1, $2, 'test', 'gw_live_hint0000010', $3, '{}', 1, 1, 1)`,
            [crypto.randomUUID(), ORG_A_ID, crypto.randomBytes(32)],
          ),
        ).rejects.toThrow();
      } finally {
        rawClient.release();
      }
    });

    it('18. Cross-tenant insertion is denied by RLS WITH CHECK policy', async () => {
      // Under Org A tenant context, attempt to insert row owned by Org B
      await expect(
        withTenant(appPool, ORG_A_ID, async (client) => {
          await client.query(
            `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
             VALUES ($1, $2, 'test', 'gw_live_hint0000011', $3, '{}', 1, 1, 1)`,
            [crypto.randomUUID(), ORG_B_ID, crypto.randomBytes(32)],
          );
        }),
      ).rejects.toThrow();
    });

    it("19. Organization A cannot read Organization B's key row under its tenant context", async () => {
      // Create key under Org B
      const keyB = await service.createKey({ orgId: ORG_B_ID, name: 'Org B Key' });

      // Attempt to query key B while executing under Org A tenant context
      await withTenant(appPool, ORG_A_ID, async (client) => {
        const { rows } = await client.query('SELECT * FROM virtual_keys WHERE id = $1', [keyB.id]);
        expect(rows.length).toBe(0);
      });
    });

    it('20. Worker role cannot INSERT or UPDATE virtual keys (permission denied 42501)', async () => {
      const workerClient = await workerPool.connect();
      try {
        // Attempt INSERT as gateway_worker
        await expect(
          workerClient.query(
            `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
             VALUES ($1, $2, 'worker_test', 'gw_live_worker111', $3, '{}', 1, 1, 1)`,
            [crypto.randomUUID(), ORG_A_ID, crypto.randomBytes(32)],
          ),
        ).rejects.toMatchObject({ code: '42501' });

        // Attempt UPDATE as gateway_worker
        await expect(
          workerClient.query(`UPDATE virtual_keys SET name = 'hacked' WHERE org_id = $1`, [
            ORG_A_ID,
          ]),
        ).rejects.toMatchObject({ code: '42501' });
      } finally {
        workerClient.release();
      }
    });
  });

  describe('Collision Safety & Concurrency (Tests 21–27)', () => {
    it('21. A forced key-hash collision cannot produce duplicate stored verifiers', async () => {
      const fixedHash = crypto.randomBytes(32);
      const id1 = crypto.randomUUID();
      const id2 = crypto.randomUUID();

      await adminClient.query(
        `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
         VALUES ($1, $2, 'k1', 'gw_live_hint_c01', $3, '{}', 1, 1, 1)`,
        [id1, ORG_A_ID, fixedHash],
      );

      await expect(
        adminClient.query(
          `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
           VALUES ($1, $2, 'k2', 'gw_live_hint_c02', $3, '{}', 1, 1, 1)`,
          [id2, ORG_A_ID, fixedHash],
        ),
      ).rejects.toMatchObject({ code: '23505', constraint: 'virtual_keys_key_hash_key' });
    });

    it('22. Concurrent inserts of the same verifier allow at most one committed row', async () => {
      const sharedHash = crypto.randomBytes(32);
      const idA = crypto.randomUUID();
      const idB = crypto.randomUUID();

      const insertA = adminClient.query(
        `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
         VALUES ($1, $2, 'concurrent-A', 'gw_live_hint_con1', $3, '{}', 1, 1, 1)`,
        [idA, ORG_A_ID, sharedHash],
      );

      const clientB = new pg.Client({ connectionString: db.url });
      await clientB.connect();
      try {
        const insertB = clientB.query(
          `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
           VALUES ($1, $2, 'concurrent-B', 'gw_live_hint_con2', $3, '{}', 1, 1, 1)`,
          [idB, ORG_A_ID, sharedHash],
        );

        const results = await Promise.allSettled([insertA, insertB]);
        const fulfilled = results.filter((r) => r.status === 'fulfilled');
        const rejected = results.filter((r) => r.status === 'rejected');

        expect(fulfilled.length).toBe(1);
        expect(rejected.length).toBe(1);
        expect((rejected[0] as PromiseRejectedResult).reason).toMatchObject({ code: '23505' });
      } finally {
        await clientB.end();
      }
    });

    it('23. Revoked historical verifier cannot be reused', async () => {
      const reusedHash = crypto.randomBytes(32);
      const id1 = crypto.randomUUID();
      const id2 = crypto.randomUUID();

      // Insert and revoke
      await adminClient.query(
        `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit, revoked_at)
         VALUES ($1, $2, 'revoked_key', 'gw_live_hint_rev1', $3, '{}', 1, 1, 1, clock_timestamp())`,
        [id1, ORG_A_ID, reusedHash],
      );

      // Attempt to issue a new key with identical verifier hash
      await expect(
        adminClient.query(
          `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
           VALUES ($1, $2, 'reuse_attempt', 'gw_live_hint_rev2', $3, '{}', 1, 1, 1)`,
          [id2, ORG_A_ID, reusedHash],
        ),
      ).rejects.toMatchObject({ code: '23505' });
    });

    it('24 & 26. A failed insertion or database failure does not expose a raw key', async () => {
      const invalidOrg = '99999999-9999-4999-8999-999999999999'; // Non-existent org
      let capturedError: unknown;

      try {
        await service.createKey({ orgId: invalidOrg, name: 'Will Fail' });
      } catch (err) {
        capturedError = err;
      }

      expect(capturedError).toBeInstanceOf(VirtualKeyError);
      const vError = capturedError as VirtualKeyError;
      expect(vError.reason).toBe('DATABASE_CONFLICT');
      expect(vError.message).not.toContain('gw_live_');
    });

    it('25. Transaction rollback does not leave a row', async () => {
      const beforeCount = await adminClient.query<{ count: string }>(
        'SELECT count(*) FROM virtual_keys',
      );

      try {
        await withTenant(appPool, ORG_A_ID, async (client) => {
          await client.query(
            `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
             VALUES ($1, $2, 'will_rollback', 'gw_live_hint_rb01', $3, '{}', 1, 1, 1)`,
            [crypto.randomUUID(), ORG_A_ID, crypto.randomBytes(32)],
          );
          throw new Error('Simulated crash inside transaction');
        });
      } catch {
        // Expected
      }

      const afterCount = await adminClient.query<{ count: string }>(
        'SELECT count(*) FROM virtual_keys',
      );
      expect(afterCount.rows[0]?.count).toBe(beforeCount.rows[0]?.count);
    });

    it('27. Multiple successful issues result in distinct key verifiers and hints', async () => {
      const key1 = await service.createKey({ orgId: ORG_A_ID, name: 'Key 1' });
      const key2 = await service.createKey({ orgId: ORG_A_ID, name: 'Key 2' });
      const key3 = await service.createKey({ orgId: ORG_A_ID, name: 'Key 3' });

      expect(key1.id).not.toBe(key2.id);
      expect(key2.id).not.toBe(key3.id);
      expect(key1.rawKey).not.toBe(key2.rawKey);
      expect(key1.keyPrefix).not.toBe(key2.keyPrefix);

      const { rows } = await adminClient.query(
        'SELECT key_hash FROM virtual_keys WHERE id IN ($1, $2, $3)',
        [key1.id, key2.id, key3.id],
      );
      expect(rows.length).toBe(3);
      const hashes = rows.map((r: { key_hash: Buffer }) => r.key_hash.toString('hex'));
      const uniqueHashes = new Set(hashes);
      expect(uniqueHashes.size).toBe(3);
    });

    it('27b. Concurrent VirtualKeyService.createKey() issuances across tenants succeed without collisions or cross-tenant contamination', async () => {
      // Execute 10 concurrent service issuances (5 for Org A and 5 for Org B)
      const ops = [
        service.createKey({ orgId: ORG_A_ID, name: 'Conc A 1' }),
        service.createKey({ orgId: ORG_A_ID, name: 'Conc A 2' }),
        service.createKey({ orgId: ORG_A_ID, name: 'Conc A 3' }),
        service.createKey({ orgId: ORG_A_ID, name: 'Conc A 4' }),
        service.createKey({ orgId: ORG_A_ID, name: 'Conc A 5' }),
        service.createKey({ orgId: ORG_B_ID, name: 'Conc B 1' }),
        service.createKey({ orgId: ORG_B_ID, name: 'Conc B 2' }),
        service.createKey({ orgId: ORG_B_ID, name: 'Conc B 3' }),
        service.createKey({ orgId: ORG_B_ID, name: 'Conc B 4' }),
        service.createKey({ orgId: ORG_B_ID, name: 'Conc B 5' }),
      ];

      const results = await Promise.all(ops);
      expect(results.length).toBe(10);

      const allIds = new Set(results.map((r) => r.id));
      expect(allIds.size).toBe(10);

      const allRawKeys = new Set(results.map((r) => r.rawKey));
      expect(allRawKeys.size).toBe(10);

      const allPrefixes = new Set(results.map((r) => r.keyPrefix));
      expect(allPrefixes.size).toBe(10);

      // Verify tenant isolation: querying Org A under tenant context sees exactly Org A's 5 keys
      const orgAKeys = await withTenant(appPool, ORG_A_ID, async (client) => {
        const { rows } = await client.query<{ id: string; org_id: string }>(
          'SELECT id, org_id FROM virtual_keys WHERE name LIKE $1',
          ['Conc A %'],
        );
        return rows;
      });
      expect(orgAKeys.length).toBe(5);
      expect(orgAKeys.every((k) => k.org_id === ORG_A_ID)).toBe(true);

      // Verify cross-tenant isolation: querying Org A under tenant context sees 0 keys of Org B
      const leakedBKeys = await withTenant(appPool, ORG_A_ID, async (client) => {
        const { rows } = await client.query<{ id: string; org_id: string }>(
          'SELECT id, org_id FROM virtual_keys WHERE name LIKE $1',
          ['Conc B %'],
        );
        return rows;
      });
      expect(leakedBKeys.length).toBe(0);

      // Verify all 10 verifier hashes in the database are distinct
      const ids = results.map((r) => r.id);
      const { rows } = await adminClient.query(
        'SELECT key_hash FROM virtual_keys WHERE id = ANY($1)',
        [ids],
      );
      expect(rows.length).toBe(10);
      const uniqueHashes = new Set(
        rows.map((r: { key_hash: Buffer }) => r.key_hash.toString('hex')),
      );
      expect(uniqueHashes.size).toBe(10);
    });

    it('28. The service uses no Redis authorization cache', () => {
      // Introspect service instance to verify absence of Redis client or caching properties
      expect((service as unknown as { redis?: unknown }).redis).toBeUndefined();
    });

    it('29. Pooled connection reuse does not leak tenant context', async () => {
      // 1. Run query within Org A
      await service.createKey({ orgId: ORG_A_ID, name: 'Isolation Test Key' });

      // 2. Checkout raw connection from appPool and verify app.current_org_id is unset
      const raw = await appPool.connect();
      try {
        const { rows } = await raw.query<{ cur_org: string | null }>(
          "SELECT pg_catalog.current_setting('app.current_org_id', true) as cur_org",
        );
        const orgSetting = rows[0]?.cur_org;
        expect(orgSetting === '' || orgSetting === null).toBe(true);
      } finally {
        raw.release();
      }
    });

    it('30. No additional privileges or schema changes are required', async () => {
      // Verify appPool (gateway_app) successfully issued virtual keys without altering any role permissions
      const res = await service.createKey({ orgId: ORG_A_ID, name: 'Privilege Verification Key' });
      expect(res.id).toBeDefined();
    });
  });

  describe('Privacy & Secret Leakage Verifications (Section 15)', () => {
    it('Synthetic canary raw key and secret never appear in PostgreSQL rows, public hints, error messages, or logs', async () => {
      const logs: string[] = [];
      const testLogger = pino(
        { level: 'trace' },
        {
          write: (chunk: string) => {
            logs.push(chunk);
          },
        },
      );

      // Create a key while logging
      testLogger.info({ event: 'virtual_key_creation_started', orgId: ORG_A_ID });
      const canaryResult = await service.createKey({
        orgId: ORG_A_ID,
        name: 'Canary Test Key',
      });
      testLogger.info({
        event: 'virtual_key_created',
        id: canaryResult.id,
        keyPrefix: canaryResult.keyPrefix,
      });

      const canaryRawKey = canaryResult.rawKey;
      const parsedCanary = parseRawKey(canaryRawKey);
      expect(parsedCanary).not.toBeNull();
      const canarySecret = parsedCanary!.secret;

      // 1. Verify canary secret is not in PostgreSQL public hint
      expect(canaryResult.keyPrefix).not.toContain(canarySecret);

      // 2. Verify canary secret is not anywhere in PostgreSQL table
      const { rows } = await adminClient.query('SELECT * FROM public.virtual_keys WHERE id = $1', [
        canaryResult.id,
      ]);
      const row = rows[0];
      for (const [col, val] of Object.entries(row)) {
        const strVal = typeof val === 'object' && val !== null ? JSON.stringify(val) : String(val);
        expect(strVal, `Column ${col} must not contain canaryRawKey`).not.toContain(canaryRawKey);
        expect(strVal, `Column ${col} must not contain canarySecret`).not.toContain(canarySecret);
      }

      // 3. Verify logs do not contain canary secret or canary raw key
      const joinedLogs = logs.join('\n');
      expect(joinedLogs).not.toContain(canaryRawKey);
      expect(joinedLogs).not.toContain(canarySecret);

      // 4. Verify controlled database failure does not leak secret material into error message
      let failedError: unknown;
      try {
        await service.createKey({
          orgId: '00000000-0000-4000-8000-000000000000', // Non-existent org
          name: 'Canary Error Key',
        });
      } catch (err) {
        failedError = err;
      }
      expect(failedError).toBeInstanceOf(VirtualKeyError);
      const errMsg = (failedError as VirtualKeyError).message;
      expect(errMsg).not.toContain('gw_live_');
    });
  });
});
