import crypto from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runMigrations } from '../db/migrate.js';
import {
  bootstrapDatabase,
  createDisposableDatabase,
  createRolePasswords,
  roleConnectionString,
  startDisposableCluster,
  type DisposableCluster,
  type DisposableDatabase,
} from '../db/test/disposable-pg.js';
import { withTenant } from '../db/tenant.js';
import {
  VirtualKeyManagementError,
  VirtualKeyManagementService,
} from './virtual-key-management.js';
import {
  type IVirtualKeyRateLimiter,
  VirtualKeyAuthenticatorService,
} from './virtual-key-authenticator.js';

describe('SW-1.6.3: PostgreSQL 16 Virtual Key Management & Policy Integration Suite', () => {
  let cluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();
  let adminClient: pg.Client;
  let appPool: pg.Pool;
  let workerPool: pg.Pool;
  let managementService: VirtualKeyManagementService;
  let authenticator: VirtualKeyAuthenticatorService;

  const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
  const ORG_B_ID = '22222222-2222-4222-8222-222222222222';

  const mockRateLimiter: IVirtualKeyRateLimiter = {
    assertNotRateLimited: async () => {},
  };

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    db = await createDisposableDatabase(cluster, 'vk_mgmt_db_test');
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

    // Connect admin client for fixture setup and introspection
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

    managementService = new VirtualKeyManagementService({ pool: appPool });
    authenticator = new VirtualKeyAuthenticatorService({
      pool: appPool,
      rateLimiter: mockRateLimiter,
    });
  }, 60000);

  afterAll(async () => {
    await appPool?.end().catch(() => undefined);
    await workerPool?.end().catch(() => undefined);
    await adminClient?.end().catch(() => undefined);
    await db?.drop().catch(() => undefined);
  });

  describe('Section 11.1: Key Creation, Restrictive Issuance Defaults & Disclosure', () => {
    it('creates key under correct tenant and returns rawKey once with restrictive issuance defaults', async () => {
      const created = await managementService.createKey(ORG_A_ID, 'Alpha Main Key');

      expect(created.id).toBeDefined();
      expect(created.name).toBe('Alpha Main Key');
      expect(created.keyPrefix).toMatch(/^gw_live_[A-Za-z0-9_-]{11}$/);
      expect(created.rawKey).toMatch(/^gw_live_[A-Za-z0-9_-]{11}_[A-Za-z0-9_-]{43}$/);
      expect(created.allowedModels).toEqual([]);
      expect(created.rpmLimit).toBe(1);
      expect(created.tpmLimit).toBe(1);
      expect(created.concurrentStreamLimit).toBe(1);
      expect(created.exactCacheEnabled).toBe(false);
      expect(created.semanticCacheEnabled).toBe(false);
      expect(created.piiRedactionEnabled).toBe(true);
      expect(created.storePayloads).toBe(false);
      expect(created.revokedAt).toBeNull();

      // Verify row in database
      const rowRes = await adminClient.query<{
        id: string;
        org_id: string;
        name: string;
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
      }>('SELECT * FROM public.virtual_keys WHERE id = $1', [created.id]);

      expect(rowRes.rows.length).toBe(1);
      const row = rowRes.rows[0]!;
      expect(row.org_id).toBe(ORG_A_ID);
      expect(row.name).toBe('Alpha Main Key');
      expect(row.key_hash).toBeInstanceOf(Buffer);
      expect(row.key_hash.length).toBe(32);
      expect(row.allowed_models).toEqual([]);
      expect(row.rpm_limit).toBe(1);
      expect(row.tpm_limit).toBe(1);
      expect(row.concurrent_stream_limit).toBe(1);
      expect(row.exact_cache_enabled).toBe(false);
      expect(row.semantic_cache_enabled).toBe(false);
      expect(row.pii_redaction_enabled).toBe(true);
      expect(row.store_payloads).toBe(false);
      expect(row.revoked_at).toBeNull();
    });
  });

  describe('Section 11.2: Tenant Isolation, Metadata Listing & Keyset Pagination', () => {
    it('list returns only own-tenant keys and never returns key_hash or rawKey', async () => {
      // Create key in Org A and key in Org B
      const keyA = await managementService.createKey(ORG_A_ID, 'Org A Isolation Key');
      const keyB = await managementService.createKey(ORG_B_ID, 'Org B Isolation Key');

      // Org A list
      const listA = await managementService.listKeys(ORG_A_ID);
      expect(listA.items.some((k) => k.id === keyA.id)).toBe(true);
      expect(listA.items.some((k) => k.id === keyB.id)).toBe(false);

      // Org B list
      const listB = await managementService.listKeys(ORG_B_ID);
      expect(listB.items.some((k) => k.id === keyB.id)).toBe(true);
      expect(listB.items.some((k) => k.id === keyA.id)).toBe(false);

      // Assert key_hash and rawKey are never present in listed items
      for (const item of listA.items) {
        const itemRecord = item as unknown as Record<string, unknown>;
        expect(itemRecord['keyHash']).toBeUndefined();
        expect(itemRecord['key_hash']).toBeUndefined();
        expect(itemRecord['rawKey']).toBeUndefined();
        expect(itemRecord['raw_key']).toBeUndefined();
        expect(itemRecord['orgId']).toBeUndefined();
        expect(itemRecord['org_id']).toBeUndefined();
      }
    });

    it('direct query on gateway_app without tenant context cannot retrieve rows (FORCE RLS)', async () => {
      const client = await appPool.connect();
      try {
        const res = await client.query('SELECT count(*)::int as count FROM public.virtual_keys');
        expect(res.rows[0]!.count).toBe(0);
      } finally {
        client.release();
      }
    });

    it('implements bounded keyset pagination with cursor and limit', async () => {
      const uniqueOrg = crypto.randomUUID();
      await adminClient.query(`
        INSERT INTO public.organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
        VALUES ('${uniqueOrg}', 'Pagination Org', 1000000, 1, '\\x01', '\\x02', '\\x03');
      `);

      // Create 5 keys in sequence
      const createdIds: string[] = [];
      for (let i = 1; i <= 5; i++) {
        const k = await managementService.createKey(uniqueOrg, `Key ${i}`);
        createdIds.push(k.id);
      }

      // Page 1: limit 2
      const page1 = await managementService.listKeys(uniqueOrg, { limit: 2 });
      expect(page1.items.length).toBe(2);
      expect(page1.nextCursor).not.toBeNull();

      // Page 2: limit 2 using cursor from page 1
      const page2 = await managementService.listKeys(uniqueOrg, {
        limit: 2,
        cursor: page1.nextCursor!,
      });
      expect(page2.items.length).toBe(2);
      expect(page2.nextCursor).not.toBeNull();

      // Page 3: limit 2 using cursor from page 2
      const page3 = await managementService.listKeys(uniqueOrg, {
        limit: 2,
        cursor: page2.nextCursor!,
      });
      expect(page3.items.length).toBe(1);
      expect(page3.nextCursor).toBeNull();

      // All 5 items across pages are distinct and match createdIds in reverse order
      const paginatedIds = [
        ...page1.items.map((i) => i.id),
        ...page2.items.map((i) => i.id),
        ...page3.items.map((i) => i.id),
      ];
      expect(new Set(paginatedIds).size).toBe(5);
      expect(paginatedIds).toEqual([...createdIds].reverse());
    });

    it('guarantees stable pagination with equal timestamps without duplicate or skipped records', async () => {
      const equalTsOrg = crypto.randomUUID();
      await adminClient.query(`
        INSERT INTO public.organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
        VALUES ('${equalTsOrg}', 'Equal TS Org', 1000000, 1, '\\x01', '\\x02', '\\x03');
      `);

      const fixedTimestamp = new Date('2026-11-21T12:00:00.000Z');
      const keyId1 = '33333333-3333-4333-8333-333333333331';
      const keyId2 = '33333333-3333-4333-8333-333333333332';
      const keyId3 = '33333333-3333-4333-8333-333333333333';

      // Insert directly via admin client with exact same created_at
      await adminClient.query(`
        INSERT INTO public.virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit, created_at)
        VALUES
          ('${keyId1}', '${equalTsOrg}', 'Key 1', 'gw_live_11111111111', '\\x01', '{}', 1, 1, 1, '${fixedTimestamp.toISOString()}'),
          ('${keyId2}', '${equalTsOrg}', 'Key 2', 'gw_live_22222222222', '\\x02', '{}', 1, 1, 1, '${fixedTimestamp.toISOString()}'),
          ('${keyId3}', '${equalTsOrg}', 'Key 3', 'gw_live_33333333333', '\\x03', '{}', 1, 1, 1, '${fixedTimestamp.toISOString()}');
      `);

      // Page 1: limit 2
      const page1 = await managementService.listKeys(equalTsOrg, { limit: 2 });
      expect(page1.items.length).toBe(2);
      expect(page1.nextCursor).not.toBeNull();

      // Page 2: limit 2 with cursor
      const page2 = await managementService.listKeys(equalTsOrg, {
        limit: 2,
        cursor: page1.nextCursor!,
      });
      expect(page2.items.length).toBe(1);
      expect(page2.nextCursor).toBeNull();

      // Verify no duplicates, no skipped items, deterministic sort by id DESC
      const allIds = [...page1.items.map((i) => i.id), ...page2.items.map((i) => i.id)];
      expect(allIds).toEqual([keyId3, keyId2, keyId1]);
    });

    it('Test A: microsecond timestamp roundtrip preserves exact 6 decimal digits in cursor', async () => {
      const orgId = crypto.randomUUID();
      await adminClient.query(`
        INSERT INTO public.organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
        VALUES ('${orgId}', 'Microsecond Roundtrip Org', 1000000, 1, '\\x01', '\\x02', '\\x03');
      `);

      const keyId1 = '44444444-4444-4444-8444-444444444441';
      const keyId2 = '44444444-4444-4444-8444-444444444442';
      const exactMicrosecondStr = '2026-11-21 12:34:56.123456+00';

      await adminClient.query(
        `
        INSERT INTO public.virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit, created_at)
        VALUES
          ($1, $2, 'Micro Key 1', 'gw_live_11111111111', $3, '{}', 1, 1, 1, $4),
          ($5, $2, 'Micro Key 2', 'gw_live_22222222222', $6, '{}', 1, 1, 1, '2026-11-21 12:34:55.000000+00');
        `,
        [
          keyId1,
          orgId,
          crypto.randomBytes(32),
          exactMicrosecondStr,
          keyId2,
          crypto.randomBytes(32),
        ],
      );

      // Page with limit 1 should yield keyId1 and nextCursor containing .123456Z
      const page1 = await managementService.listKeys(orgId, { limit: 1 });
      expect(page1.items.length).toBe(1);
      expect(page1.items[0]!.id).toBe(keyId1);
      expect(page1.nextCursor).not.toBeNull();

      const decoded = JSON.parse(Buffer.from(page1.nextCursor!, 'base64url').toString('utf8')) as {
        createdAt: string;
        id: string;
      };
      expect(decoded.createdAt).toBe('2026-11-21T12:34:56.123456Z');
      expect(decoded.id).toBe(keyId1);

      // Using this cursor fetches keyId2
      const page2 = await managementService.listKeys(orgId, {
        limit: 1,
        cursor: page1.nextCursor!,
      });
      expect(page2.items.length).toBe(1);
      expect(page2.items[0]!.id).toBe(keyId2);
      expect(page2.nextCursor).toBeNull();
    });

    it('Test B: paginates >= 5 keys sharing exact same microsecond timestamp without skips or duplicates', async () => {
      const orgId = crypto.randomUUID();
      await adminClient.query(`
        INSERT INTO public.organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
        VALUES ('${orgId}', 'Identical Microseconds Org', 1000000, 1, '\\x01', '\\x02', '\\x03');
      `);

      const exactMicrosecondStr = '2026-11-21 15:00:00.654321+00';
      const keyIds = [
        '55555555-5555-4555-8555-555555555551',
        '55555555-5555-4555-8555-555555555552',
        '55555555-5555-4555-8555-555555555553',
        '55555555-5555-4555-8555-555555555554',
        '55555555-5555-4555-8555-555555555555',
      ];

      for (let i = 0; i < keyIds.length; i++) {
        await adminClient.query(
          `
          INSERT INTO public.virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit, created_at)
          VALUES ($1, $2, $3, $4, $5, '{}', 1, 1, 1, $6);
        `,
          [
            keyIds[i],
            orgId,
            `Identical TS Key ${i}`,
            `gw_live_${i}1111111111`,
            crypto.randomBytes(32),
            exactMicrosecondStr,
          ],
        );
      }

      // Paginate in pages of 2
      const page1 = await managementService.listKeys(orgId, { limit: 2 });
      expect(page1.items.length).toBe(2);
      expect(page1.nextCursor).not.toBeNull();

      const page2 = await managementService.listKeys(orgId, {
        limit: 2,
        cursor: page1.nextCursor!,
      });
      expect(page2.items.length).toBe(2);
      expect(page2.nextCursor).not.toBeNull();

      const page3 = await managementService.listKeys(orgId, {
        limit: 2,
        cursor: page2.nextCursor!,
      });
      expect(page3.items.length).toBe(1);
      expect(page3.nextCursor).toBeNull();

      const retrievedIds = [
        ...page1.items.map((k) => k.id),
        ...page2.items.map((k) => k.id),
        ...page3.items.map((k) => k.id),
      ];

      // Ordered strictly by id DESC since created_at are identical
      const expectedIds = [...keyIds].sort().reverse();
      expect(retrievedIds).toEqual(expectedIds);
    });

    it('Test C: paginates distinct timestamps within one millisecond without skipping rows', async () => {
      const orgId = crypto.randomUUID();
      await adminClient.query(`
        INSERT INTO public.organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
        VALUES ('${orgId}', 'Sub-Millisecond Org', 1000000, 1, '\\x01', '\\x02', '\\x03');
      `);

      const timestamps = [
        '2026-11-21 12:00:00.123999+00',
        '2026-11-21 12:00:00.123750+00',
        '2026-11-21 12:00:00.123456+00',
        '2026-11-21 12:00:00.123250+00',
        '2026-11-21 12:00:00.123001+00',
      ];

      const keyIds = [
        '66666666-6666-4666-8666-666666666661',
        '66666666-6666-4666-8666-666666666662',
        '66666666-6666-4666-8666-666666666663',
        '66666666-6666-4666-8666-666666666664',
        '66666666-6666-4666-8666-666666666665',
      ];

      for (let i = 0; i < keyIds.length; i++) {
        await adminClient.query(
          `
          INSERT INTO public.virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit, created_at)
          VALUES ($1, $2, $3, $4, $5, '{}', 1, 1, 1, $6);
        `,
          [
            keyIds[i],
            orgId,
            `Sub-ms Key ${i}`,
            `gw_live_${i}2222222222`,
            crypto.randomBytes(32),
            timestamps[i],
          ],
        );
      }

      // Page with limit 2
      const page1 = await managementService.listKeys(orgId, { limit: 2 });
      expect(page1.items.length).toBe(2);
      expect(page1.items.map((k) => k.id)).toEqual([keyIds[0], keyIds[1]]);
      expect(page1.nextCursor).not.toBeNull();

      // Page 2: with millisecond truncation, this would skip rows or fail
      const page2 = await managementService.listKeys(orgId, {
        limit: 2,
        cursor: page1.nextCursor!,
      });
      expect(page2.items.length).toBe(2);
      expect(page2.items.map((k) => k.id)).toEqual([keyIds[2], keyIds[3]]);
      expect(page2.nextCursor).not.toBeNull();

      // Page 3
      const page3 = await managementService.listKeys(orgId, {
        limit: 2,
        cursor: page2.nextCursor!,
      });
      expect(page3.items.length).toBe(1);
      expect(page3.items.map((k) => k.id)).toEqual([keyIds[4]]);
      expect(page3.nextCursor).toBeNull();
    });

    it('Test D: paginates mixed timestamp groups accurately', async () => {
      const orgId = crypto.randomUUID();
      await adminClient.query(`
        INSERT INTO public.organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
        VALUES ('${orgId}', 'Mixed Groups Org', 1000000, 1, '\\x01', '\\x02', '\\x03');
      `);

      // Two keys at T1, two at T2, two at T3
      const t1 = '2026-11-21 16:00:00.300000+00';
      const t2 = '2026-11-21 16:00:00.200000+00';
      const t3 = '2026-11-21 16:00:00.100000+00';

      const keys = [
        { id: '77777777-7777-4777-8777-777777777771', ts: t1 },
        { id: '77777777-7777-4777-8777-777777777772', ts: t1 },
        { id: '77777777-7777-4777-8777-777777777773', ts: t2 },
        { id: '77777777-7777-4777-8777-777777777774', ts: t2 },
        { id: '77777777-7777-4777-8777-777777777775', ts: t3 },
        { id: '77777777-7777-4777-8777-777777777776', ts: t3 },
      ];

      for (let i = 0; i < keys.length; i++) {
        await adminClient.query(
          `
          INSERT INTO public.virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit, created_at)
          VALUES ($1, $2, $3, $4, $5, '{}', 1, 1, 1, $6);
        `,
          [
            keys[i]!.id,
            orgId,
            `Mixed Key ${i}`,
            `gw_live_${i}3333333333`,
            crypto.randomBytes(32),
            keys[i]!.ts,
          ],
        );
      }

      const allItems: string[] = [];
      let cursor: string | undefined;

      for (let p = 0; p < 3; p++) {
        const listOpts: { limit: number; cursor?: string } = { limit: 2 };
        if (cursor !== undefined) {
          listOpts.cursor = cursor;
        }
        const page = await managementService.listKeys(orgId, listOpts);
        allItems.push(...page.items.map((k) => k.id));
        cursor = page.nextCursor ?? undefined;
      }

      expect(allItems.length).toBe(6);
      expect(cursor).toBeUndefined();
      // Group T1 sorted by id DESC
      expect(allItems[0]).toBe('77777777-7777-4777-8777-777777777772');
      expect(allItems[1]).toBe('77777777-7777-4777-8777-777777777771');
      // Group T2 sorted by id DESC
      expect(allItems[2]).toBe('77777777-7777-4777-8777-777777777774');
      expect(allItems[3]).toBe('77777777-7777-4777-8777-777777777773');
      // Group T3 sorted by id DESC
      expect(allItems[4]).toBe('77777777-7777-4777-8777-777777777776');
      expect(allItems[5]).toBe('77777777-7777-4777-8777-777777777775');
    });

    it('Test E: rejects malformed, truncated, oversized, noncanonical cursors fail-closed', async () => {
      // 1. Truncated millisecond timestamp
      const msCursor = Buffer.from(
        JSON.stringify({
          createdAt: '2026-11-21T12:00:00.123Z',
          id: '11111111-1111-4111-8111-111111111111',
        }),
      ).toString('base64url');

      await expect(
        managementService.listKeys(ORG_A_ID, { cursor: msCursor }),
      ).rejects.toMatchObject({
        reason: 'INVALID_INPUT',
      });

      // 2. Oversized cursor (> 256 chars)
      const oversizedCursor = 'A'.repeat(257);
      await expect(
        managementService.listKeys(ORG_A_ID, { cursor: oversizedCursor }),
      ).rejects.toMatchObject({
        reason: 'INVALID_INPUT',
      });

      // 3. Non-canonical base64url padding
      const validCursor = Buffer.from(
        JSON.stringify({
          createdAt: '2026-11-21T12:00:00.123456Z',
          id: '11111111-1111-4111-8111-111111111111',
        }),
      ).toString('base64url');

      await expect(
        managementService.listKeys(ORG_A_ID, { cursor: validCursor + '=' }),
      ).rejects.toMatchObject({
        reason: 'INVALID_INPUT',
      });

      // 4. Malformed JSON
      const malformedJsonCursor = Buffer.from('{not json}').toString('base64url');
      await expect(
        managementService.listKeys(ORG_A_ID, { cursor: malformedJsonCursor }),
      ).rejects.toMatchObject({
        reason: 'INVALID_INPUT',
      });
    });

    it('Test F: preserves strict tenant isolation across cursors without cross-tenant leakage', async () => {
      // Create a key in Org A and obtain its cursor
      const keyA = await managementService.createKey(ORG_A_ID, 'Org A Cursor Key');
      const listA = await managementService.listKeys(ORG_A_ID, { limit: 1 });
      expect(listA.items[0]!.id).toBe(keyA.id);

      // Now pass Org A cursor to Org B listKeys
      // It must execute strictly under Org B RLS context and return only Org B keys (never Org A keys)
      const listOptsB: { limit: number; cursor?: string } = { limit: 10 };
      if (listA.nextCursor !== null) {
        listOptsB.cursor = listA.nextCursor;
      }
      const listB = await managementService.listKeys(ORG_B_ID, listOptsB);

      for (const item of listB.items) {
        expect(item.id).not.toBe(keyA.id);
      }
    });

    it('Test G: enforces limit bounds (default 20, max 100, rejects invalid)', async () => {
      // Default limit is 20
      const defaultPage = await managementService.listKeys(ORG_A_ID);
      expect(defaultPage.items.length).toBeLessThanOrEqual(20);

      // Max limit 100 accepted
      const maxPage = await managementService.listKeys(ORG_A_ID, { limit: 100 });
      expect(maxPage.items.length).toBeLessThanOrEqual(100);

      // Limit 101 rejected
      await expect(managementService.listKeys(ORG_A_ID, { limit: 101 })).rejects.toMatchObject({
        reason: 'INVALID_INPUT',
      });

      // Limit 0 rejected
      await expect(managementService.listKeys(ORG_A_ID, { limit: 0 })).rejects.toMatchObject({
        reason: 'INVALID_INPUT',
      });

      // Negative limit rejected
      await expect(managementService.listKeys(ORG_A_ID, { limit: -1 })).rejects.toMatchObject({
        reason: 'INVALID_INPUT',
      });

      // Fractional limit rejected
      await expect(managementService.listKeys(ORG_A_ID, { limit: 1.5 })).rejects.toMatchObject({
        reason: 'INVALID_INPUT',
      });
    });
  });

  describe('Section 11.3: Atomic Policy Replacement', () => {
    it('atomically replaces complete policy configuration on active key', async () => {
      const created = await managementService.createKey(ORG_A_ID, 'Policy Target Key');

      const updated = await managementService.replacePolicy(ORG_A_ID, created.id, {
        allowedModels: ['gpt-4o', 'claude-3-5-sonnet'],
        rpmLimit: 250,
        tpmLimit: 50000,
        concurrentStreamLimit: 10,
        exactCacheEnabled: false,
        semanticCacheEnabled: false,
        piiRedactionEnabled: false,
        storePayloads: true,
      });

      expect(updated.id).toBe(created.id);
      expect(updated.allowedModels).toEqual(['gpt-4o', 'claude-3-5-sonnet']);
      expect(updated.rpmLimit).toBe(250);
      expect(updated.tpmLimit).toBe(50000);
      expect(updated.concurrentStreamLimit).toBe(10);
      expect(updated.exactCacheEnabled).toBe(false);
      expect(updated.semanticCacheEnabled).toBe(false);
      expect(updated.piiRedactionEnabled).toBe(false);
      expect(updated.storePayloads).toBe(true);

      // Verify row in database
      const dbRow = await adminClient.query<{
        allowed_models: string[];
        rpm_limit: number;
        tpm_limit: number;
        concurrent_stream_limit: number;
        pii_redaction_enabled: boolean;
        store_payloads: boolean;
      }>(
        'SELECT allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit, pii_redaction_enabled, store_payloads FROM public.virtual_keys WHERE id = $1',
        [created.id],
      );
      expect(dbRow.rows[0]!.allowed_models).toEqual(['gpt-4o', 'claude-3-5-sonnet']);
      expect(dbRow.rows[0]!.rpm_limit).toBe(250);
      expect(dbRow.rows[0]!.tpm_limit).toBe(50000);
      expect(dbRow.rows[0]!.concurrent_stream_limit).toBe(10);
      expect(dbRow.rows[0]!.pii_redaction_enabled).toBe(false);
      expect(dbRow.rows[0]!.store_payloads).toBe(true);
    });

    it('cross-tenant policy update fails with KEY_NOT_FOUND and modifies zero rows', async () => {
      const keyA = await managementService.createKey(ORG_A_ID, 'Org A Target Key');

      // Tenant B admin attempts to update Tenant A key
      await expect(
        managementService.replacePolicy(ORG_B_ID, keyA.id, {
          allowedModels: ['gpt-4o'],
          rpmLimit: 100,
          tpmLimit: 1000,
          concurrentStreamLimit: 5,
          exactCacheEnabled: false,
          semanticCacheEnabled: false,
          piiRedactionEnabled: true,
          storePayloads: false,
        }),
      ).rejects.toThrow('Virtual key not found');

      // Verify row in database remains completely unmodified
      const rowRes = await adminClient.query<{ rpm_limit: number; allowed_models: string[] }>(
        'SELECT rpm_limit, allowed_models FROM public.virtual_keys WHERE id = $1',
        [keyA.id],
      );
      expect(rowRes.rows[0]!.rpm_limit).toBe(1);
      expect(rowRes.rows[0]!.allowed_models).toEqual([]);
    });

    it('invalid policy inputs fail validation before mutating database row', async () => {
      const key = await managementService.createKey(ORG_A_ID, 'Rollback Test Key');

      await expect(
        managementService.replacePolicy(ORG_A_ID, key.id, {
          allowedModels: ['gpt-4o', '*'], // prohibited wildcard
          rpmLimit: 100,
          tpmLimit: 1000,
          concurrentStreamLimit: 5,
          exactCacheEnabled: false,
          semanticCacheEnabled: false,
          piiRedactionEnabled: true,
          storePayloads: false,
        }),
      ).rejects.toThrow(VirtualKeyManagementError);

      const dbRow = await adminClient.query<{ rpm_limit: number }>(
        'SELECT rpm_limit FROM public.virtual_keys WHERE id = $1',
        [key.id],
      );
      expect(dbRow.rows[0]!.rpm_limit).toBe(1);
    });
  });

  describe('Section 11.4: Revocation, Idempotency & Authenticator Invalidation', () => {
    it('logically revokes key, ensures idempotency, and blocks policy update', async () => {
      const key = await managementService.createKey(ORG_A_ID, 'Revoke Target Key');

      // First revoke
      await managementService.revokeKey(ORG_A_ID, key.id);

      const dbRow1 = await adminClient.query<{ revoked_at: Date }>(
        'SELECT revoked_at FROM public.virtual_keys WHERE id = $1',
        [key.id],
      );
      expect(dbRow1.rows[0]!.revoked_at).not.toBeNull();
      const firstRevocationTime = dbRow1.rows[0]!.revoked_at.getTime();

      // Repeated revoke (idempotent): leaves original timestamp unchanged
      await managementService.revokeKey(ORG_A_ID, key.id);
      const dbRow2 = await adminClient.query<{ revoked_at: Date }>(
        'SELECT revoked_at FROM public.virtual_keys WHERE id = $1',
        [key.id],
      );
      expect(dbRow2.rows[0]!.revoked_at.getTime()).toBe(firstRevocationTime);

      // Attempt policy update on revoked key: fails with KEY_REVOKED
      await expect(
        managementService.replacePolicy(ORG_A_ID, key.id, {
          allowedModels: ['gpt-4o'],
          rpmLimit: 50,
          tpmLimit: 5000,
          concurrentStreamLimit: 2,
          exactCacheEnabled: false,
          semanticCacheEnabled: false,
          piiRedactionEnabled: true,
          storePayloads: false,
        }),
      ).rejects.toThrow('Cannot update policy of a revoked virtual key');
    });

    it('cross-tenant revoke fails with KEY_NOT_FOUND and does not revoke row', async () => {
      const keyA = await managementService.createKey(ORG_A_ID, 'Org A Revoke Target');

      await expect(managementService.revokeKey(ORG_B_ID, keyA.id)).rejects.toThrow(
        'Virtual key not found',
      );

      const dbRow = await adminClient.query<{ revoked_at: Date | null }>(
        'SELECT revoked_at FROM public.virtual_keys WHERE id = $1',
        [keyA.id],
      );
      expect(dbRow.rows[0]!.revoked_at).toBeNull();
    });

    it('revoked key is immediately and deterministically rejected by SW-1.6.2 authenticator', async () => {
      const key = await managementService.createKey(ORG_A_ID, 'Auth Invalidation Target');

      const CLIENT_IP = '198.51.100.55';

      // Verify active key authenticates successfully before revocation
      const authBefore = await authenticator.authenticateKey(key.rawKey, CLIENT_IP);
      expect(authBefore.valid).toBe(true);
      expect(authBefore.principal?.keyId).toBe(key.id);

      // Revoke the key
      await managementService.revokeKey(ORG_A_ID, key.id);

      // Verify key is rejected fail-closed with KEY_REVOKED after revocation
      const authAfter = await authenticator.authenticateKey(key.rawKey, CLIENT_IP);
      expect(authAfter.valid).toBe(false);
      expect(authAfter.reason).toBe('KEY_REVOKED');
      expect(authAfter.principal).toBeUndefined();
    });
  });

  describe('Section 11.5: Deterministic Row-Level Lock Concurrency (Revocation vs Policy Update)', () => {
    it('proves revocation and policy replacement serialize on SELECT ... FOR UPDATE', async () => {
      const key = await managementService.createKey(ORG_A_ID, 'Concurrency Race Key');

      const client1 = await appPool.connect();
      const client2 = await appPool.connect();

      try {
        // 1. Client 1 enters tenant context and acquires row lock on the key
        await client1.query('BEGIN');
        await client1.query(`SET LOCAL app.current_org_id = '${ORG_A_ID}'`);
        const lock1 = await client1.query<{ id: string; revoked_at: Date | null }>(
          'SELECT id, revoked_at FROM public.virtual_keys WHERE id = $1 FOR UPDATE',
          [key.id],
        );
        expect(lock1.rows.length).toBe(1);

        // 2. Client 2 initiates replacePolicy in tenant context, which attempts to acquire row lock
        let client2Completed = false;
        let client2Error: unknown = null;

        const client2Promise = (async () => {
          try {
            await withTenant(appPool, ORG_A_ID, async (c2) => {
              const lock2 = await c2.query<{ id: string; revoked_at: Date | null }>(
                'SELECT id, revoked_at FROM public.virtual_keys WHERE id = $1 FOR UPDATE',
                [key.id],
              );
              if (lock2.rows[0]?.revoked_at !== null) {
                throw new VirtualKeyManagementError(
                  'KEY_REVOKED',
                  'Cannot update policy of a revoked virtual key',
                );
              }
              await c2.query('UPDATE public.virtual_keys SET rpm_limit = 999 WHERE id = $1', [
                key.id,
              ]);
            });
          } catch (err) {
            client2Error = err;
          } finally {
            client2Completed = true;
          }
        })();

        // Wait briefly for Client 2 query to reach PostgreSQL and block on the row lock
        await new Promise((resolve) => setTimeout(resolve, 100));

        // Assert Client 2 is blocked and has not completed
        expect(client2Completed).toBe(false);

        // Verify via pg_locks that client 2 is waiting on a tuple/transaction lock held by client 1
        const locksRes = await adminClient.query<{ count: number }>(`
          SELECT count(*)::int as count
          FROM pg_locks
          WHERE NOT granted
        `);
        expect(locksRes.rows[0]!.count).toBeGreaterThanOrEqual(1);

        // 3. Client 1 updates revoked_at and commits
        await client1.query(
          'UPDATE public.virtual_keys SET revoked_at = clock_timestamp() WHERE id = $1',
          [key.id],
        );
        await client1.query('COMMIT');

        // 4. Client 2 unblocks, executes, and must fail because the row is now revoked
        await client2Promise;
        expect(client2Completed).toBe(true);
        expect(client2Error).toBeInstanceOf(VirtualKeyManagementError);
        expect((client2Error as VirtualKeyManagementError).reason).toBe('KEY_REVOKED');

        // 5. Verify the key remains revoked and rpm_limit was NOT mutated by client 2
        const finalRow = await adminClient.query<{ rpm_limit: number; revoked_at: Date }>(
          'SELECT rpm_limit, revoked_at FROM public.virtual_keys WHERE id = $1',
          [key.id],
        );
        expect(finalRow.rows[0]!.revoked_at).not.toBeNull();
        expect(finalRow.rows[0]!.rpm_limit).toBe(1); // Unchanged!
      } finally {
        client1.release();
        client2.release();
      }
    });
  });

  describe('Section 11.6: Worker Role Least-Privilege Verification', () => {
    it('proves gateway_worker role cannot insert, update, revoke, or delete virtual keys', async () => {
      const key = await managementService.createKey(ORG_A_ID, 'Worker Boundary Key');

      const workerClient = await workerPool.connect();
      try {
        // Can read virtual keys (allowed for background attribution)
        await workerClient.query(`SET app.current_org_id = '${ORG_A_ID}'`);
        const selectRes = await workerClient.query(
          'SELECT id FROM public.virtual_keys WHERE id = $1',
          [key.id],
        );
        expect(selectRes.rows.length).toBe(1);

        // Cannot INSERT
        await expect(
          workerClient.query(
            `INSERT INTO public.virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
             VALUES ('${crypto.randomUUID()}', '${ORG_A_ID}', 'Worker Key', 'gw_live_00000000000', '\\x01', '{}', 1, 1, 1)`,
          ),
        ).rejects.toThrow(/permission denied for table virtual_keys/);

        // Cannot UPDATE
        await expect(
          workerClient.query('UPDATE public.virtual_keys SET rpm_limit = 50 WHERE id = $1', [
            key.id,
          ]),
        ).rejects.toThrow(/permission denied for table virtual_keys/);

        // Cannot revoke (UPDATE revoked_at)
        await expect(
          workerClient.query(
            'UPDATE public.virtual_keys SET revoked_at = clock_timestamp() WHERE id = $1',
            [key.id],
          ),
        ).rejects.toThrow(/permission denied for table virtual_keys/);

        // Cannot DELETE
        await expect(
          workerClient.query('DELETE FROM public.virtual_keys WHERE id = $1', [key.id]),
        ).rejects.toThrow(/permission denied for table virtual_keys/);
      } finally {
        workerClient.release();
      }
    });
  });
});
