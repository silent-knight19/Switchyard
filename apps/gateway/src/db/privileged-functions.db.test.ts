import crypto from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runMigrations } from './migrate.js';
import {
  bootstrapDatabase,
  createDisposableDatabase,
  createRolePasswords,
  roleConnectionString,
  startDisposableCluster,
  type DisposableCluster,
  type DisposableDatabase,
  type LoginRole,
} from './test/disposable-pg.js';

async function captureError(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => null,
    (error: unknown) => error,
  );
}

function errorCode(error: unknown): unknown {
  return typeof error === 'object' && error !== null
    ? (error as { code?: unknown }).code
    : undefined;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function expectSqlState(promise: Promise<unknown>, sqlState: string): Promise<unknown> {
  const error = await captureError(promise);
  expect(
    errorCode(error),
    `expected SQLSTATE ${sqlState}, got ${String(errorCode(error))}: ${errorMessage(error)}`,
  ).toBe(sqlState);
  return error;
}

function sha256(data: string | Buffer): Buffer {
  return crypto.createHash('sha256').update(data).digest();
}

describe('SW-1.4.3 & SW-1.4.4 Privileged Functions Integration Suite (real PostgreSQL 16)', () => {
  let cluster: DisposableCluster;
  const databases: DisposableDatabase[] = [];
  const passwords = createRolePasswords();
  let database: DisposableDatabase;
  const clients: pg.Client[] = [];

  // Fixed test IDs
  const orgAId = '11111111-1111-1111-1111-111111111111';
  const orgBId = '22222222-2222-2222-2222-222222222222';
  const userAId = '33333333-3333-3333-3333-333333333333';
  const userBId = '44444444-4444-4444-4444-444444444444';
  const keyActiveId = '55555555-5555-5555-5555-555555555555';
  const keyRevokedId = '66666666-6666-6666-6666-666666666666';

  const rawActiveSecret = 'active-virtual-key-secret-32bytes!';
  const activeKeyHash = sha256(rawActiveSecret);

  const rawRevokedSecret = 'revoked-virtual-key-secret-32byte';
  const revokedKeyHash = sha256(rawRevokedSecret);

  // Complete, known-good Argon2id PHC verifier fixtures (DB-39)
  const VALID_ARGON2ID_VERIFIER =
    '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90';
  const OWASP_ARGON2ID_VERIFIER =
    '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90';

  async function connectAs(role: LoginRole): Promise<pg.Client> {
    const client = new pg.Client({
      connectionString: roleConnectionString(database.url, role, passwords[role]),
    });
    await client.connect();
    clients.push(client);
    return client;
  }

  let adminClient: pg.Client;
  let appClient: pg.Client;
  let workerClient: pg.Client;
  let startupClient: pg.Client;

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    database = await createDisposableDatabase(cluster, 'priv_funcs');
    databases.push(database);
    await bootstrapDatabase(database, passwords);

    const migrator = new pg.Pool({
      connectionString: roleConnectionString(
        database.url,
        'gateway_migrator',
        passwords.gateway_migrator,
      ),
    });
    try {
      const applied = await runMigrations(migrator);
      expect(applied).toContain('0010');
    } finally {
      await migrator.end();
    }

    adminClient = new pg.Client({ connectionString: database.url });
    await adminClient.connect();
    clients.push(adminClient);

    appClient = await connectAs('gateway_app');
    workerClient = await connectAs('gateway_worker');
    startupClient = await connectAs('gateway_startup');

    // Seed test fixtures as superuser (bypassing RLS for fixture setup only)
    await adminClient.query(`
      INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
      VALUES
        ('${orgAId}', 'Org Alpha', 50000000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea),
        ('${orgBId}', 'Org Beta', 75000000, 1, '\\x04'::bytea, '\\x05'::bytea, '\\x06'::bytea);
    `);

    await adminClient.query(`
      INSERT INTO users (id, org_id, email_normalized, password_hash, role)
      VALUES
        ('${userAId}', '${orgAId}', 'admin@alpha.com', '${VALID_ARGON2ID_VERIFIER}', 'admin'),
        ('${userBId}', '${orgBId}', 'member@beta.com', '${OWASP_ARGON2ID_VERIFIER}', 'member');
    `);

    await adminClient.query(
      `
      INSERT INTO virtual_keys (
        id, org_id, name, key_prefix, key_hash, allowed_models,
        rpm_limit, tpm_limit, concurrent_stream_limit,
        exact_cache_enabled, semantic_cache_enabled, pii_redaction_enabled,
        store_payloads, revoked_at
      ) VALUES
        ('${keyActiveId}', '${orgAId}', 'Alpha Key', 'gw_live_alpha', $1, ARRAY['gpt-4o', 'claude-3-5-sonnet'],
         60, 100000, 10, true, false, true, true, NULL),
        ('${keyRevokedId}', '${orgBId}', 'Beta Key', 'gw_live_beta', $2, ARRAY['gpt-4o-mini'],
         30, 50000, 5, false, false, false, false, clock_timestamp() - interval '1 hour');
    `,
      [activeKeyHash, revokedKeyHash],
    );
  });

  afterAll(async () => {
    for (const client of clients) {
      await client.end().catch(() => undefined);
    }
    await cluster.stop();
  });

  describe('PostgreSQL catalog & hardening invariants (Architecture §12.4)', () => {
    it('verifies all four functions exist with exact owners, prosecdef, and search_path', async () => {
      const { rows } = await adminClient.query<{
        proname: string;
        owner: string;
        prosecdef: boolean;
        provolatile: string;
        search_path: string;
      }>(`
        SELECT
          p.proname,
          r.rolname AS owner,
          p.prosecdef,
          p.provolatile,
          (SELECT string_agg(c, ', ') FROM unnest(p.proconfig) c) AS search_path
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_roles r ON r.oid = p.proowner
        WHERE n.nspname = 'app_private'
          AND p.proname IN (
            'lookup_virtual_key_by_hash',
            'lookup_user_for_login',
            'create_organization_with_admin',
            'list_active_org_ids'
          )
        ORDER BY p.proname;
      `);

      expect(rows).toHaveLength(4);

      const byName = new Map(rows.map((r) => [r.proname, r]));

      // 1. lookup_virtual_key_by_hash
      const vkFn = byName.get('lookup_virtual_key_by_hash');
      expect(vkFn?.owner).toBe('gateway_auth_executor');
      expect(vkFn?.prosecdef).toBe(true);
      expect(vkFn?.provolatile).toBe('s'); // STABLE
      expect(vkFn?.search_path).toBe('search_path=pg_catalog, app_private, pg_temp');

      // 2. lookup_user_for_login
      const userFn = byName.get('lookup_user_for_login');
      expect(userFn?.owner).toBe('gateway_auth_executor');
      expect(userFn?.prosecdef).toBe(true);
      expect(userFn?.provolatile).toBe('s'); // STABLE
      expect(userFn?.search_path).toBe('search_path=pg_catalog, app_private, pg_temp');

      // 3. create_organization_with_admin
      const orgFn = byName.get('create_organization_with_admin');
      expect(orgFn?.owner).toBe('gateway_auth_executor');
      expect(orgFn?.prosecdef).toBe(true);
      expect(orgFn?.provolatile).toBe('v'); // VOLATILE (inserts data)
      expect(orgFn?.search_path).toBe('search_path=pg_catalog, app_private, pg_temp');

      // 4. list_active_org_ids
      const opsFn = byName.get('list_active_org_ids');
      expect(opsFn?.owner).toBe('gateway_ops_executor');
      expect(opsFn?.prosecdef).toBe(true);
      expect(opsFn?.provolatile).toBe('s'); // STABLE
      expect(opsFn?.search_path).toBe('search_path=pg_catalog, app_private, pg_temp');
    });

    it('verifies executor roles are NOLOGIN, BYPASSRLS, and NOSUPERUSER', async () => {
      const { rows } = await adminClient.query<{
        rolname: string;
        rolcanlogin: boolean;
        rolbypassrls: boolean;
        rolsuper: boolean;
        rolcreaterole: boolean;
      }>(`
        SELECT rolname, rolcanlogin, rolbypassrls, rolsuper, rolcreaterole
        FROM pg_roles
        WHERE rolname IN ('gateway_auth_executor', 'gateway_ops_executor')
        ORDER BY rolname;
      `);

      expect(rows).toHaveLength(2);
      for (const row of rows) {
        expect(row.rolcanlogin).toBe(false);
        expect(row.rolbypassrls).toBe(true);
        expect(row.rolsuper).toBe(false);
        expect(row.rolcreaterole).toBe(false);
      }
    });

    it('verifies executor roles do NOT own any tenant tables', async () => {
      const { rows } = await adminClient.query<{ tablename: string; tableowner: string }>(`
        SELECT tablename, tableowner
        FROM pg_tables
        WHERE schemaname = 'public'
          AND tableowner IN ('gateway_auth_executor', 'gateway_ops_executor');
      `);
      expect(rows).toHaveLength(0);
    });

    it('verifies executor role memberships: only gateway_migrator holds membership with INHERIT FALSE', async () => {
      const { rows } = await adminClient.query<{
        role: string;
        member: string;
        admin_option: boolean;
        inherit_option: boolean;
      }>(`
        SELECT r.rolname AS role, m.rolname AS member, am.admin_option, am.inherit_option
        FROM pg_auth_members am
        JOIN pg_roles r ON r.oid = am.roleid
        JOIN pg_roles m ON m.oid = am.member
        WHERE r.rolname IN ('gateway_auth_executor', 'gateway_ops_executor')
        ORDER BY r.rolname;
      `);

      expect(rows).toHaveLength(2);
      expect(rows[0]?.role).toBe('gateway_auth_executor');
      expect(rows[0]?.member).toBe('gateway_migrator');
      expect(rows[0]?.admin_option).toBe(false);
      expect(rows[0]?.inherit_option).toBe(false);

      expect(rows[1]?.role).toBe('gateway_ops_executor');
      expect(rows[1]?.member).toBe('gateway_migrator');
      expect(rows[1]?.admin_option).toBe(false);
      expect(rows[1]?.inherit_option).toBe(false);
    });

    it('verifies no function overloading exists in app_private', async () => {
      const { rows } = await adminClient.query<{ proname: string; cnt: number }>(`
        SELECT p.proname, count(*)::int AS cnt
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'app_private'
        GROUP BY p.proname
        HAVING count(*) > 1;
      `);
      expect(rows).toHaveLength(0);
    });
  });

  describe('SW-1.4.3: Virtual API key lookup (app_private.lookup_virtual_key_by_hash)', () => {
    it('returns virtual key metadata for valid active key hash', async () => {
      const { rows } = await appClient.query<{
        id: string;
        org_id: string;
        revoked_at: string | null;
        allowed_models: string[];
        rpm_limit: number;
        tpm_limit: number;
        concurrent_stream_limit: number;
        exact_cache_enabled: boolean;
        semantic_cache_enabled: boolean;
        pii_redaction_enabled: boolean;
        store_payloads: boolean;
      }>('SELECT * FROM app_private.lookup_virtual_key_by_hash($1)', [activeKeyHash]);

      expect(rows).toHaveLength(1);
      const key = rows[0]!;
      expect(key.id).toBe(keyActiveId);
      expect(key.org_id).toBe(orgAId);
      expect(key.revoked_at).toBeNull();
      expect(key.allowed_models).toEqual(['gpt-4o', 'claude-3-5-sonnet']);
      expect(key.rpm_limit).toBe(60);
      expect(key.tpm_limit).toBe(100000);
      expect(key.concurrent_stream_limit).toBe(10);
      expect(key.exact_cache_enabled).toBe(true);
      expect(key.semantic_cache_enabled).toBe(false);
      expect(key.pii_redaction_enabled).toBe(true);
      expect(key.store_payloads).toBe(true);
    });

    it('preserves revocation information for revoked key lookup', async () => {
      const { rows } = await appClient.query<{
        id: string;
        org_id: string;
        revoked_at: string | null;
        allowed_models: string[];
      }>('SELECT * FROM app_private.lookup_virtual_key_by_hash($1)', [revokedKeyHash]);

      expect(rows).toHaveLength(1);
      const key = rows[0]!;
      expect(key.id).toBe(keyRevokedId);
      expect(key.org_id).toBe(orgBId);
      expect(key.revoked_at).not.toBeNull();
      expect(key.allowed_models).toEqual(['gpt-4o-mini']);
    });

    it('resolves keys across multiple tenants without requiring tenant context', async () => {
      // Lookup Key A (Org A)
      const resA = await appClient.query(
        'SELECT org_id FROM app_private.lookup_virtual_key_by_hash($1)',
        [activeKeyHash],
      );
      expect(resA.rows[0]?.org_id).toBe(orgAId);

      // Lookup Key B (Org B)
      const resB = await appClient.query(
        'SELECT org_id FROM app_private.lookup_virtual_key_by_hash($1)',
        [revokedKeyHash],
      );
      expect(resB.rows[0]?.org_id).toBe(orgBId);
    });

    it('returns empty result set for unknown valid 32-byte hash', async () => {
      const unknownHash = sha256('non-existent-secret-key-entropy');
      const { rows } = await appClient.query(
        'SELECT * FROM app_private.lookup_virtual_key_by_hash($1)',
        [unknownHash],
      );
      expect(rows).toHaveLength(0);
    });

    it('fails closed and returns 0 rows on NULL, empty, or wrong-length hash', async () => {
      // NULL
      const resNull = await appClient.query(
        'SELECT * FROM app_private.lookup_virtual_key_by_hash($1)',
        [null],
      );
      expect(resNull.rows).toHaveLength(0);

      // Empty bytea
      const resEmpty = await appClient.query(
        "SELECT * FROM app_private.lookup_virtual_key_by_hash('\\x'::bytea)",
      );
      expect(resEmpty.rows).toHaveLength(0);

      // 16 bytes (too short)
      const shortHash = Buffer.alloc(16, 0xaa);
      const resShort = await appClient.query(
        'SELECT * FROM app_private.lookup_virtual_key_by_hash($1)',
        [shortHash],
      );
      expect(resShort.rows).toHaveLength(0);

      // 33 bytes (too long)
      const longHash = Buffer.alloc(33, 0xbb);
      const resLong = await appClient.query(
        'SELECT * FROM app_private.lookup_virtual_key_by_hash($1)',
        [longHash],
      );
      expect(resLong.rows).toHaveLength(0);
    });

    it('confirms return contract exposes NO provider secrets, plaintext keys, or hash', async () => {
      const res = await appClient.query(
        'SELECT * FROM app_private.lookup_virtual_key_by_hash($1)',
        [activeKeyHash],
      );
      const fieldNames = res.fields.map((f) => f.name);
      expect(fieldNames).toEqual([
        'id',
        'org_id',
        'revoked_at',
        'allowed_models',
        'rpm_limit',
        'tpm_limit',
        'concurrent_stream_limit',
        'exact_cache_enabled',
        'semantic_cache_enabled',
        'pii_redaction_enabled',
        'store_payloads',
      ]);
      expect(fieldNames).not.toContain('key_hash');
      expect(fieldNames).not.toContain('key_prefix');
      expect(fieldNames).not.toContain('ciphertext');
      expect(fieldNames).not.toContain('wrapped_dek');
    });
  });

  describe('SW-1.4.3: User login lookup (app_private.lookup_user_for_login)', () => {
    it('returns user login credentials for existing normalized email', async () => {
      const { rows } = await appClient.query<{
        id: string;
        org_id: string;
        role: string;
        password_hash: string;
      }>('SELECT * FROM app_private.lookup_user_for_login($1)', ['admin@alpha.com']);

      expect(rows).toHaveLength(1);
      const user = rows[0]!;
      expect(user.id).toBe(userAId);
      expect(user.org_id).toBe(orgAId);
      expect(user.role).toBe('admin');
      expect(user.password_hash).toBe(VALID_ARGON2ID_VERIFIER);
    });

    it('returns empty result set for unknown email', async () => {
      const { rows } = await appClient.query(
        'SELECT * FROM app_private.lookup_user_for_login($1)',
        ['unknown@nowhere.com'],
      );
      expect(rows).toHaveLength(0);
    });

    it('does not match mixed-case input without normalized representation', async () => {
      const { rows } = await appClient.query(
        'SELECT * FROM app_private.lookup_user_for_login($1)',
        ['Admin@Alpha.com'],
      );
      expect(rows).toHaveLength(0);
    });

    it('fails closed and returns 0 rows on leading/trailing whitespace or malformed email (DB-36)', async () => {
      const resLeading = await appClient.query(
        'SELECT * FROM app_private.lookup_user_for_login($1)',
        [' admin@alpha.com'],
      );
      expect(resLeading.rows).toHaveLength(0);

      const resTrailing = await appClient.query(
        'SELECT * FROM app_private.lookup_user_for_login($1)',
        ['admin@alpha.com '],
      );
      expect(resTrailing.rows).toHaveLength(0);

      const resNoAt = await appClient.query('SELECT * FROM app_private.lookup_user_for_login($1)', [
        'adminalpha.com',
      ]);
      expect(resNoAt.rows).toHaveLength(0);
    });

    it('fails closed and returns 0 rows on NULL, empty, or oversized input', async () => {
      // NULL
      const resNull = await appClient.query('SELECT * FROM app_private.lookup_user_for_login($1)', [
        null,
      ]);
      expect(resNull.rows).toHaveLength(0);

      // Empty string
      const resEmpty = await appClient.query(
        'SELECT * FROM app_private.lookup_user_for_login($1)',
        [''],
      );
      expect(resEmpty.rows).toHaveLength(0);

      // Oversized (> 255 chars)
      const oversized = 'a'.repeat(250) + '@example.com'; // 262 chars
      const resOversized = await appClient.query(
        'SELECT * FROM app_private.lookup_user_for_login($1)',
        [oversized],
      );
      expect(resOversized.rows).toHaveLength(0);
    });

    it('handles SQL-injection shaped input safely as a literal search string', async () => {
      const malicious = "' OR '1'='1' --";
      const { rows } = await appClient.query(
        'SELECT * FROM app_private.lookup_user_for_login($1)',
        [malicious],
      );
      expect(rows).toHaveLength(0);
    });

    it('verifies exact return fields: id, org_id, role, password_hash only', async () => {
      const res = await appClient.query('SELECT * FROM app_private.lookup_user_for_login($1)', [
        'admin@alpha.com',
      ]);
      const fieldNames = res.fields.map((f) => f.name);
      expect(fieldNames).toEqual(['id', 'org_id', 'role', 'password_hash']);
      expect(fieldNames).not.toContain('email_normalized');
      expect(fieldNames).not.toContain('session_id_hash');
      expect(fieldNames).not.toContain('csrf_token_hash');
      expect(fieldNames).not.toContain('wrapped_dek');
    });
  });

  describe('SW-1.4.3: Atomic organization and admin bootstrap (app_private.create_organization_with_admin)', () => {
    const newOrgId = '77777777-7777-7777-7777-777777777777';
    const newAdminId = '88888888-8888-8888-8888-888888888888';

    it('creates organization and initial admin atomically and returns minimal confirmation', async () => {
      const { rows } = await appClient.query<{
        org_id: string;
        admin_user_id: string;
      }>(
        `
        SELECT * FROM app_private.create_organization_with_admin(
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
        )
      `,
        [
          newOrgId,
          'Bootstrap Org',
          25000000,
          1,
          Buffer.from('dek-wrapped-bytes-test'),
          Buffer.from('iv-12bytes-test!'),
          Buffer.from('auth-tag-16bytes'),
          newAdminId,
          'founder@bootstrap.com',
          VALID_ARGON2ID_VERIFIER,
        ],
      );

      expect(rows).toHaveLength(1);
      expect(rows[0]?.org_id).toBe(newOrgId);
      expect(rows[0]?.admin_user_id).toBe(newAdminId);

      // Verify the new organization can be verified via lookup_user_for_login
      const userRes = await appClient.query('SELECT * FROM app_private.lookup_user_for_login($1)', [
        'founder@bootstrap.com',
      ]);
      expect(userRes.rows).toHaveLength(1);
      expect(userRes.rows[0]?.id).toBe(newAdminId);
      expect(userRes.rows[0]?.org_id).toBe(newOrgId);
      expect(userRes.rows[0]?.role).toBe('admin');
    });

    it('rejects duplicate organization ID with SQLSTATE 23505 and creates no partial state', async () => {
      const freshAdminId = '88888888-8888-8888-8888-888888888889';
      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
          )
        `,
          [
            newOrgId, // duplicate org_id
            'Duplicate Org ID',
            1000000,
            1,
            Buffer.from('dek'),
            Buffer.from('iv'),
            Buffer.from('tag'),
            freshAdminId,
            'unique.email@test.com',
            VALID_ARGON2ID_VERIFIER,
          ],
        ),
        '23505',
      );

      // Verify freshAdminId was NOT persisted
      const checkUser = await adminClient.query('SELECT id FROM users WHERE id = $1', [
        freshAdminId,
      ]);
      expect(checkUser.rows).toHaveLength(0);
    });

    it('rejects duplicate admin email with SQLSTATE 23505 and completely rolls back the organization', async () => {
      const freshOrgId = '77777777-7777-7777-7777-777777777778';
      const freshAdminId = '88888888-8888-8888-8888-888888888890';

      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
          )
        `,
          [
            freshOrgId,
            'Orphan Attempt Org',
            1000000,
            1,
            Buffer.from('dek'),
            Buffer.from('iv'),
            Buffer.from('tag'),
            freshAdminId,
            'founder@bootstrap.com', // duplicate email!
            VALID_ARGON2ID_VERIFIER,
          ],
        ),
        '23505',
      );

      // Verify freshOrgId was NOT persisted (complete rollback!)
      const checkOrg = await adminClient.query('SELECT id FROM organizations WHERE id = $1', [
        freshOrgId,
      ]);
      expect(checkOrg.rows).toHaveLength(0);
    });

    it('rejects NULL org_id or admin_user_id with SQLSTATE 22004', async () => {
      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            NULL, 'Org', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            '99999999-9999-9999-9999-999999999999', 'a@b.com', $1
          )
        `,
          [VALID_ARGON2ID_VERIFIER],
        ),
        '22004',
      );

      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            '99999999-9999-9999-9999-999999999999', 'Org', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            NULL, 'a@b.com', $1
          )
        `,
          [VALID_ARGON2ID_VERIFIER],
        ),
        '22004',
      );
    });

    it('rejects invalid parameters with SQLSTATE 22023', async () => {
      const validOrg = '99999999-9999-9999-9999-999999999991';
      const validAdmin = '99999999-9999-9999-9999-999999999992';
      const validHash = VALID_ARGON2ID_VERIFIER;

      // Empty name
      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            $1, '   ', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            $2, 'test@test.com', $3
          )
        `,
          [validOrg, validAdmin, validHash],
        ),
        '22023',
      );

      // Negative budget
      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            $1, 'Org', -1, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            $2, 'test@test.com', $3
          )
        `,
          [validOrg, validAdmin, validHash],
        ),
        '22023',
      );

      // Budget > 10^15 (1_000_000_000_000_001)
      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            $1, 'Org', 1000000000000001, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            $2, 'test@test.com', $3
          )
        `,
          [validOrg, validAdmin, validHash],
        ),
        '22023',
      );

      // Invalid KEK version (0)
      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            $1, 'Org', 1000, 0, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            $2, 'test@test.com', $3
          )
        `,
          [validOrg, validAdmin, validHash],
        ),
        '22023',
      );

      // Empty DEK
      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            $1, 'Org', 1000, 1, '\\x'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            $2, 'test@test.com', $3
          )
        `,
          [validOrg, validAdmin, validHash],
        ),
        '22023',
      );

      // Empty email
      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            $1, 'Org', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            $2, '', $3
          )
        `,
          [validOrg, validAdmin, validHash],
        ),
        '22023',
      );

      // Empty password hash
      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            $1, 'Org', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            $2, 'test@test.com', ''
          )
        `,
          [validOrg, validAdmin],
        ),
        '22023',
      );
    });

    it('enforces canonical normalized email contract on bootstrap (DB-36)', async () => {
      const baseOrg = '99999999-9999-9999-9999-9999999999a0';
      const baseAdmin = '99999999-9999-9999-9999-9999999999a1';
      const validHash = VALID_ARGON2ID_VERIFIER;

      // 1. Mixed-case admin email rejected with 22023
      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            $1, 'Org Mixed', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            $2, 'Admin@Bootstrap.com', $3
          )
        `,
          [baseOrg, baseAdmin, validHash],
        ),
        '22023',
      );

      // Verify no orphan organization persisted after mixed-case rejection
      const orphan1 = await adminClient.query('SELECT id FROM organizations WHERE id = $1', [
        baseOrg,
      ]);
      expect(orphan1.rows).toHaveLength(0);

      // 2. Leading whitespace rejected with 22023
      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            $1, 'Org Lead Space', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            $2, ' admin@bootstrap.com', $3
          )
        `,
          [baseOrg, baseAdmin, validHash],
        ),
        '22023',
      );

      // 3. Trailing whitespace rejected with 22023
      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            $1, 'Org Trail Space', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            $2, 'admin@bootstrap.com ', $3
          )
        `,
          [baseOrg, baseAdmin, validHash],
        ),
        '22023',
      );

      // 4. Oversized email (> 255 chars) rejected with 22023
      const oversizedEmail = 'a'.repeat(250) + '@bootstrap.com';
      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            $1, 'Org Oversized', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            $2, $3, $4
          )
        `,
          [baseOrg, baseAdmin, oversizedEmail, validHash],
        ),
        '22023',
      );

      // 5. Canonical lowercase email accepted and immediately resolvable by lookup_user_for_login
      const canonicalOrgId = '99999999-9999-9999-9999-9999999999a2';
      const canonicalAdminId = '99999999-9999-9999-9999-9999999999a3';
      const canonicalEmail = 'canonical.admin@bootstrap.com';

      const createRes = await appClient.query<{ org_id: string; admin_user_id: string }>(
        `
        SELECT * FROM app_private.create_organization_with_admin(
          $1, 'Canonical Org', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
          $2, $3, $4
        )
      `,
        [canonicalOrgId, canonicalAdminId, canonicalEmail, validHash],
      );
      expect(createRes.rows).toHaveLength(1);
      expect(createRes.rows[0]?.org_id).toBe(canonicalOrgId);
      expect(createRes.rows[0]?.admin_user_id).toBe(canonicalAdminId);

      // Verify immediate resolution via lookup_user_for_login
      const lookupRes = await appClient.query<{
        id: string;
        org_id: string;
        role: string;
        password_hash: string;
      }>('SELECT * FROM app_private.lookup_user_for_login($1)', [canonicalEmail]);
      expect(lookupRes.rows).toHaveLength(1);
      expect(lookupRes.rows[0]?.id).toBe(canonicalAdminId);
      expect(lookupRes.rows[0]?.org_id).toBe(canonicalOrgId);
      expect(lookupRes.rows[0]?.role).toBe('admin');
      expect(lookupRes.rows[0]?.password_hash).toBe(validHash);

      // 6. Rejected input cannot create a second identity differing only in email capitalization
      const competingOrgId = '99999999-9999-9999-9999-9999999999a4';
      const competingAdminId = '99999999-9999-9999-9999-9999999999a5';
      await expectSqlState(
        appClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            $1, 'Competing Org', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            $2, 'Canonical.Admin@Bootstrap.com', $3
          )
        `,
          [competingOrgId, competingAdminId, validHash],
        ),
        '22023',
      );

      // Verify persistent state: only exactly 1 user exists with that email stem
      const countRes = await adminClient.query(
        'SELECT count(*)::int as count FROM users WHERE lower(email_normalized) = $1',
        [canonicalEmail],
      );
      expect(countRes.rows[0]?.count).toBe(1);
    });

    it('enforces complete Argon2id password verifier representation contract on bootstrap (DB-39)', async () => {
      // Helper to test invalid verifiers and verify rollback / zero persistent state
      const assertInvalidVerifier = async (malformedVerifier: string, label: string) => {
        const testOrgId = crypto.randomUUID();
        const testAdminId = crypto.randomUUID();
        await expectSqlState(
          appClient.query(
            `
            SELECT * FROM app_private.create_organization_with_admin(
              $1, 'Invalid Verifier Org', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
              $2, 'admin.invalid@test.com', $3
            )
          `,
            [testOrgId, testAdminId, malformedVerifier],
          ),
          '22023',
        );

        // Persistent-state: neither organization nor admin user must be created
        const orgCheck = await adminClient.query('SELECT id FROM organizations WHERE id = $1', [
          testOrgId,
        ]);
        expect(orgCheck.rows, `Expected no organization row for ${label}`).toHaveLength(0);
        const userCheck = await adminClient.query('SELECT id FROM users WHERE id = $1', [
          testAdminId,
        ]);
        expect(userCheck.rows, `Expected no user row for ${label}`).toHaveLength(0);
      };

      // 1. Missing derived-hash component (The exact DB-39 confirmed defect)
      await assertInvalidVerifier(
        '$argon2id$v=19$m=65536,t=3,p=4$onlysalt',
        'missing derived-hash component',
      );

      // 2. Missing salt component
      await assertInvalidVerifier('$argon2id$v=19$m=65536,t=3,p=4$', 'missing salt component');

      // 3. Empty salt
      await assertInvalidVerifier(
        '$argon2id$v=19$m=65536,t=3,p=4$$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'empty salt',
      );

      // 4. Empty derived hash
      await assertInvalidVerifier(
        '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$',
        'empty derived hash',
      );

      // 5. Missing required parameters
      await assertInvalidVerifier(
        '$argon2id$v=19$m=65536,t=3$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'missing parameter p',
      );
      await assertInvalidVerifier(
        '$argon2id$v=19$t=3,p=4$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'missing parameter m',
      );
      await assertInvalidVerifier(
        '$argon2id$v=19$m=65536,p=4$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'missing parameter t',
      );

      // 6. Duplicate parameter names
      await assertInvalidVerifier(
        '$argon2id$v=19$m=65536,t=3,m=65536$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'duplicate parameter m',
      );
      await assertInvalidVerifier(
        '$argon2id$v=19$m=65536,t=3,p=4,p=4$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'duplicate parameter p',
      );

      // 7. Non-numeric or zero values for required positive parameters
      await assertInvalidVerifier(
        '$argon2id$v=19$m=0,t=3,p=4$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'zero memory parameter',
      );
      await assertInvalidVerifier(
        '$argon2id$v=19$m=65536,t=0,p=4$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'zero iteration parameter',
      );
      await assertInvalidVerifier(
        '$argon2id$v=19$m=65536,t=3,p=0$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'zero parallelism parameter',
      );
      await assertInvalidVerifier(
        '$argon2id$v=19$m=abc,t=3,p=4$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'non-numeric memory parameter',
      );
      await assertInvalidVerifier(
        '$argon2id$v=19$m=-65536,t=3,p=4$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'negative memory parameter',
      );

      // 8. Unsupported version values
      await assertInvalidVerifier(
        '$argon2id$v=13$m=65536,t=3,p=4$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'unsupported version v=13',
      );
      await assertInvalidVerifier(
        '$argon2id$v=0$m=65536,t=3,p=4$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'unsupported version v=0',
      );
      await assertInvalidVerifier(
        '$argon2id$v=20$m=65536,t=3,p=4$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'unsupported version v=20',
      );

      // 9. Unexpected extra components
      await assertInvalidVerifier(
        '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90$extra',
        'unexpected extra field',
      );

      // 10. Invalid encoding characters
      await assertInvalidVerifier(
        '$argon2id$v=19$m=65536,t=3,p=4$invalid!@#salt$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90',
        'invalid character in salt',
      );
      await assertInvalidVerifier(
        '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$invalid!@#hash',
        'invalid character in derived hash',
      );

      // 11. Plaintext passwords
      for (const plaintext of ['hunter2', 'Password123!', 'plaintext', 'pass']) {
        await assertInvalidVerifier(plaintext, `plaintext password ${plaintext}`);
      }

      // 12. Non-Argon2 algorithms (Bcrypt / MD5)
      await assertInvalidVerifier(
        '$2a$12$R9h/cIPz0gi.URNNXRkh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW',
        'bcrypt algorithm',
      );
      await assertInvalidVerifier('$1$md5salt$md5hash', 'md5 algorithm');

      // 13. Valid verifier 1: Complete, known-good Argon2id PHC verifier
      const validOrgId = '99999999-9999-9999-9999-9999999999b4';
      const validAdminId = '99999999-9999-9999-9999-9999999999b5';
      const validEmail = 'complete.admin@bootstrap.com';

      const resValid = await appClient.query<{ org_id: string; admin_user_id: string }>(
        `
        SELECT * FROM app_private.create_organization_with_admin(
          $1, 'Complete Verifier Org', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
          $2, $3, $4
        )
      `,
        [validOrgId, validAdminId, validEmail, VALID_ARGON2ID_VERIFIER],
      );
      expect(resValid.rows).toHaveLength(1);
      expect(resValid.rows[0]?.org_id).toBe(validOrgId);
      expect(resValid.rows[0]?.admin_user_id).toBe(validAdminId);

      // Verify return fields remain strictly ['org_id', 'admin_user_id']
      expect(resValid.fields.map((f) => f.name)).toEqual(['org_id', 'admin_user_id']);

      // Verify persistent state in organizations
      const checkOrg = await adminClient.query('SELECT id, name FROM organizations WHERE id = $1', [
        validOrgId,
      ]);
      expect(checkOrg.rows).toHaveLength(1);
      expect(checkOrg.rows[0]?.name).toBe('Complete Verifier Org');

      // Verify persistent state in users: role equals 'admin' and password_hash stored unchanged
      const checkUser = await adminClient.query(
        'SELECT id, org_id, role, password_hash FROM users WHERE id = $1',
        [validAdminId],
      );
      expect(checkUser.rows).toHaveLength(1);
      expect(checkUser.rows[0]?.org_id).toBe(validOrgId);
      expect(checkUser.rows[0]?.role).toBe('admin');
      expect(checkUser.rows[0]?.password_hash).toBe(VALID_ARGON2ID_VERIFIER);

      // Verify user is immediately resolvable by lookup_user_for_login
      const lookupUser = await appClient.query<{
        id: string;
        org_id: string;
        role: string;
        password_hash: string;
      }>('SELECT * FROM app_private.lookup_user_for_login($1)', [validEmail]);
      expect(lookupUser.rows).toHaveLength(1);
      expect(lookupUser.rows[0]?.id).toBe(validAdminId);
      expect(lookupUser.rows[0]?.org_id).toBe(validOrgId);
      expect(lookupUser.rows[0]?.role).toBe('admin');
      expect(lookupUser.rows[0]?.password_hash).toBe(VALID_ARGON2ID_VERIFIER);

      // 14. Valid verifier 2: OWASP-recommended baseline verifier
      const owaspOrgId = '99999999-9999-9999-9999-9999999999b6';
      const owaspAdminId = '99999999-9999-9999-9999-9999999999b7';
      const owaspEmail = 'owasp.baseline@bootstrap.com';

      const resOwasp = await appClient.query<{ org_id: string; admin_user_id: string }>(
        `
        SELECT * FROM app_private.create_organization_with_admin(
          $1, 'OWASP Org', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
          $2, $3, $4
        )
      `,
        [owaspOrgId, owaspAdminId, owaspEmail, OWASP_ARGON2ID_VERIFIER],
      );
      expect(resOwasp.rows).toHaveLength(1);

      const checkOwasp = await adminClient.query('SELECT password_hash FROM users WHERE id = $1', [
        owaspAdminId,
      ]);
      expect(checkOwasp.rows[0]?.password_hash).toBe(OWASP_ARGON2ID_VERIFIER);

      // 15. Valid verifier 3: Permuted parameter ordering (t, m, p) accepted without overconstraining
      const permOrgId = '99999999-9999-9999-9999-9999999999b8';
      const permAdminId = '99999999-9999-9999-9999-9999999999b9';
      const permVerifier =
        '$argon2id$v=19$t=2,m=19456,p=1$c29tZXNhbHQ$9s/8SoWjpMIuoGun45BhAzSdhaQx+/KExluUdnoMr90';
      const permEmail = 'permuted.params@bootstrap.com';

      const resPerm = await appClient.query<{ org_id: string; admin_user_id: string }>(
        `
        SELECT * FROM app_private.create_organization_with_admin(
          $1, 'Permuted Org', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
          $2, $3, $4
        )
      `,
        [permOrgId, permAdminId, permEmail, permVerifier],
      );
      expect(resPerm.rows).toHaveLength(1);

      const checkPerm = await adminClient.query('SELECT password_hash FROM users WHERE id = $1', [
        permAdminId,
      ]);
      expect(checkPerm.rows[0]?.password_hash).toBe(permVerifier);
    });
  });

  describe('SW-1.4.4: Maintenance organization enumerator (app_private.list_active_org_ids)', () => {
    it('returns only org_id column and deterministic keyset pagination for gateway_worker', async () => {
      const res = await workerClient.query(
        'SELECT * FROM app_private.list_active_org_ids(NULL, 10)',
      );
      expect(res.fields.map((f) => f.name)).toEqual(['org_id']);
      expect(res.rows.length).toBeGreaterThanOrEqual(3);

      // Check strictly ascending UUID ordering
      for (let i = 1; i < res.rows.length; i += 1) {
        expect(res.rows[i]!.org_id > res.rows[i - 1]!.org_id).toBe(true);
      }
    });

    it('paginates deterministically using exclusive keyset cursor', async () => {
      // Fetch page 1 (limit 2)
      const page1 = await workerClient.query<{ org_id: string }>(
        'SELECT * FROM app_private.list_active_org_ids(NULL, 2)',
      );
      expect(page1.rows).toHaveLength(2);
      const cursor = page1.rows[1]!.org_id;

      // Fetch page 2 (after cursor, limit 2)
      const page2 = await workerClient.query<{ org_id: string }>(
        'SELECT * FROM app_private.list_active_org_ids($1, 2)',
        [cursor],
      );
      expect(page2.rows.length).toBeGreaterThanOrEqual(1);

      // Keyset cursor is strictly exclusive: page 2 does not include cursor
      expect(page2.rows.map((r) => r.org_id)).not.toContain(cursor);
      for (const row of page2.rows) {
        expect(row.org_id > cursor).toBe(true);
      }
    });

    it('returns empty result set when cursor is greater than all organization IDs', async () => {
      const maxCursor = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
      const { rows } = await workerClient.query(
        'SELECT * FROM app_private.list_active_org_ids($1, 10)',
        [maxCursor],
      );
      expect(rows).toHaveLength(0);
    });

    it('fails closed on invalid limit bounds with SQLSTATE 22023', async () => {
      // Limit 0
      await expectSqlState(
        workerClient.query('SELECT * FROM app_private.list_active_org_ids(NULL, 0)'),
        '22023',
      );

      // Negative limit
      await expectSqlState(
        workerClient.query('SELECT * FROM app_private.list_active_org_ids(NULL, -5)'),
        '22023',
      );

      // Limit > 100
      await expectSqlState(
        workerClient.query('SELECT * FROM app_private.list_active_org_ids(NULL, 101)'),
        '22023',
      );

      // NULL limit
      await expectSqlState(
        workerClient.query('SELECT * FROM app_private.list_active_org_ids(NULL, NULL)'),
        '22023',
      );
    });

    it('verifies boundary limits 1 and 100 succeed', async () => {
      const res1 = await workerClient.query(
        'SELECT * FROM app_private.list_active_org_ids(NULL, 1)',
      );
      expect(res1.rows).toHaveLength(1);

      const res100 = await workerClient.query(
        'SELECT * FROM app_private.list_active_org_ids(NULL, 100)',
      );
      expect(res100.rows.length).toBeGreaterThanOrEqual(1);
      expect(res100.rows.length).toBeLessThanOrEqual(100);
    });
  });

  describe('Strict EXECUTE Privilege Matrix across roles (Architecture §12.4)', () => {
    it('gateway_app: permitted on auth functions, DENIED on maintenance enumerator (42501)', async () => {
      // Positive: lookup_virtual_key_by_hash
      const vk = await appClient.query('SELECT * FROM app_private.lookup_virtual_key_by_hash($1)', [
        activeKeyHash,
      ]);
      expect(vk.rows).toHaveLength(1);

      // Positive: lookup_user_for_login
      const user = await appClient.query('SELECT * FROM app_private.lookup_user_for_login($1)', [
        'admin@alpha.com',
      ]);
      expect(user.rows).toHaveLength(1);

      // Negative: list_active_org_ids denied with 42501
      await expectSqlState(
        appClient.query('SELECT * FROM app_private.list_active_org_ids(NULL, 10)'),
        '42501',
      );
    });

    it('gateway_worker: permitted on maintenance enumerator, DENIED on auth functions (42501)', async () => {
      // Positive: list_active_org_ids
      const orgs = await workerClient.query(
        'SELECT * FROM app_private.list_active_org_ids(NULL, 10)',
      );
      expect(orgs.rows.length).toBeGreaterThanOrEqual(1);

      // Negative: lookup_virtual_key_by_hash denied with 42501
      await expectSqlState(
        workerClient.query('SELECT * FROM app_private.lookup_virtual_key_by_hash($1)', [
          activeKeyHash,
        ]),
        '42501',
      );

      // Negative: lookup_user_for_login denied with 42501
      await expectSqlState(
        workerClient.query('SELECT * FROM app_private.lookup_user_for_login($1)', [
          'admin@alpha.com',
        ]),
        '42501',
      );

      // Negative: create_organization_with_admin denied with 42501
      await expectSqlState(
        workerClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Org', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'a@b.com', $1
          )
        `,
          [VALID_ARGON2ID_VERIFIER],
        ),
        '42501',
      );
    });

    it('gateway_startup: DENIED on all four privileged functions (42501)', async () => {
      await expectSqlState(
        startupClient.query('SELECT * FROM app_private.lookup_virtual_key_by_hash($1)', [
          activeKeyHash,
        ]),
        '42501',
      );
      await expectSqlState(
        startupClient.query('SELECT * FROM app_private.lookup_user_for_login($1)', [
          'admin@alpha.com',
        ]),
        '42501',
      );
      await expectSqlState(
        startupClient.query(
          `
          SELECT * FROM app_private.create_organization_with_admin(
            'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Org', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
            'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'a@b.com', $1
          )
        `,
          [VALID_ARGON2ID_VERIFIER],
        ),
        '42501',
      );
      await expectSqlState(
        startupClient.query('SELECT * FROM app_private.list_active_org_ids(NULL, 10)'),
        '42501',
      );
    });

    it('unauthenticated/PUBLIC role: DENIED on all four functions (42501)', async () => {
      // Create a temporary unprivileged role to simulate public caller
      const publicRole = 'test_public_unprivileged';
      await adminClient.query(`
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${publicRole}') THEN
            CREATE ROLE ${publicRole} LOGIN PASSWORD 'public_pass';
          END IF;
        END $$;
        GRANT USAGE ON SCHEMA app_private TO ${publicRole};
      `);

      const publicUrl = new URL(database.url);
      publicUrl.username = publicRole;
      publicUrl.password = 'public_pass';
      const publicClient = new pg.Client({
        connectionString: publicUrl.toString(),
      });
      await publicClient.connect();
      try {
        await expectSqlState(
          publicClient.query('SELECT * FROM app_private.lookup_virtual_key_by_hash($1)', [
            activeKeyHash,
          ]),
          '42501',
        );
        await expectSqlState(
          publicClient.query('SELECT * FROM app_private.lookup_user_for_login($1)', [
            'admin@alpha.com',
          ]),
          '42501',
        );
        await expectSqlState(
          publicClient.query(
            `
            SELECT * FROM app_private.create_organization_with_admin(
              'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Org', 1000, 1, '\\x01'::bytea, '\\x02'::bytea, '\\x03'::bytea,
              'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'a@b.com', $1
            )
          `,
            [VALID_ARGON2ID_VERIFIER],
          ),
          '42501',
        );
        await expectSqlState(
          publicClient.query('SELECT * FROM app_private.list_active_org_ids(NULL, 10)'),
          '42501',
        );
      } finally {
        await publicClient.end();
        await adminClient.query(`REVOKE ALL ON SCHEMA app_private FROM ${publicRole}`);
        await adminClient.query(`DROP ROLE IF EXISTS ${publicRole}`);
      }
    });
  });

  describe('Adversarial security & hardening tests (Section 10)', () => {
    it('Search-path & pg_temp shadowing attack: malicious temporary objects do NOT affect function execution', async () => {
      // Create a temporary table shadowing 'virtual_keys' in appClient's session
      await appClient.query(`
        CREATE TEMPORARY TABLE virtual_keys (
          id UUID,
          org_id UUID,
          key_hash BYTEA,
          allowed_models TEXT[],
          rpm_limit INT,
          tpm_limit INT,
          concurrent_stream_limit INT,
          exact_cache_enabled BOOLEAN,
          semantic_cache_enabled BOOLEAN,
          pii_redaction_enabled BOOLEAN,
          store_payloads BOOLEAN,
          revoked_at TIMESTAMPTZ
        );
      `);
      await appClient.query(
        `INSERT INTO pg_temp.virtual_keys (id, org_id, key_hash, allowed_models)
         VALUES ('99999999-9999-9999-9999-999999999999', '99999999-9999-9999-9999-999999999999', $1, ARRAY['hacked-model'])`,
        [activeKeyHash],
      );

      // Set caller-controlled search_path prioritizing pg_temp
      await appClient.query('SET search_path = pg_temp, public, pg_catalog');

      // Invoke lookup_virtual_key_by_hash: must access public.virtual_keys, NOT pg_temp.virtual_keys
      const { rows } = await appClient.query<{
        id: string;
        allowed_models: string[];
      }>('SELECT id, allowed_models FROM app_private.lookup_virtual_key_by_hash($1)', [
        activeKeyHash,
      ]);

      expect(rows).toHaveLength(1);
      expect(rows[0]?.id).toBe(keyActiveId);
      expect(rows[0]?.allowed_models).toEqual(['gpt-4o', 'claude-3-5-sonnet']);

      // Clean up temp table and search_path
      await appClient.query('DROP TABLE IF EXISTS pg_temp.virtual_keys');
      await appClient.query('RESET search_path');
    });

    it('Search-path & pg_temp shadowing attack on users table', async () => {
      await appClient.query(`
        CREATE TEMPORARY TABLE users (
          id UUID,
          org_id UUID,
          email_normalized TEXT,
          password_hash TEXT,
          role TEXT
        );
        INSERT INTO pg_temp.users VALUES (
          '99999999-9999-9999-9999-999999999999',
          '99999999-9999-9999-9999-999999999999',
          'admin@alpha.com',
          'hacked_hash',
          'admin'
        );
      `);

      await appClient.query('SET search_path = pg_temp, public, pg_catalog');

      const { rows } = await appClient.query<{
        id: string;
        password_hash: string;
      }>('SELECT id, password_hash FROM app_private.lookup_user_for_login($1)', [
        'admin@alpha.com',
      ]);

      expect(rows).toHaveLength(1);
      expect(rows[0]?.id).toBe(userAId);
      expect(rows[0]?.password_hash).toBe(VALID_ARGON2ID_VERIFIER);

      await appClient.query('DROP TABLE IF EXISTS pg_temp.users');
      await appClient.query('RESET search_path');
    });

    it('Search-path & pg_temp shadowing attack on organizations table under worker session', async () => {
      await workerClient.query(`
        CREATE TEMPORARY TABLE organizations (
          id UUID
        );
        INSERT INTO pg_temp.organizations VALUES ('99999999-9999-9999-9999-999999999999');
      `);

      await workerClient.query('SET search_path = pg_temp, public, pg_catalog');

      const { rows } = await workerClient.query<{ org_id: string }>(
        'SELECT org_id FROM app_private.list_active_org_ids(NULL, 100)',
      );

      // Must NOT contain the fake temp ID
      expect(rows.map((r) => r.org_id)).not.toContain('99999999-9999-9999-9999-999999999999');

      await workerClient.query('DROP TABLE IF EXISTS pg_temp.organizations');
      await workerClient.query('RESET search_path');
    });

    it('Ownership escalation: runtime roles CANNOT SET ROLE to executor roles (42501)', async () => {
      await expectSqlState(appClient.query('SET ROLE gateway_auth_executor'), '42501');
      await expectSqlState(appClient.query('SET ROLE gateway_ops_executor'), '42501');
      await expectSqlState(workerClient.query('SET ROLE gateway_auth_executor'), '42501');
      await expectSqlState(workerClient.query('SET ROLE gateway_ops_executor'), '42501');
      await expectSqlState(startupClient.query('SET ROLE gateway_auth_executor'), '42501');
      await expectSqlState(startupClient.query('SET ROLE gateway_ops_executor'), '42501');
    });

    it('Ownership escalation: runtime roles CANNOT ALTER FUNCTION ownership (42501)', async () => {
      await expectSqlState(
        appClient.query(
          'ALTER FUNCTION app_private.lookup_virtual_key_by_hash(BYTEA) OWNER TO gateway_app',
        ),
        '42501',
      );
      await expectSqlState(
        workerClient.query(
          'ALTER FUNCTION app_private.list_active_org_ids(UUID, INT) OWNER TO gateway_worker',
        ),
        '42501',
      );
    });

    it('Schema protection: runtime roles CANNOT CREATE or REPLACE functions in app_private (42501)', async () => {
      await expectSqlState(
        appClient.query(`
          CREATE FUNCTION app_private.rogue_fn() RETURNS void LANGUAGE sql AS $$ SELECT 1; $$
        `),
        '42501',
      );
      await expectSqlState(
        workerClient.query(`
          CREATE FUNCTION app_private.rogue_fn() RETURNS void LANGUAGE sql AS $$ SELECT 1; $$
        `),
        '42501',
      );
    });

    it('Least privilege: gateway_worker CANNOT directly SELECT from users, web_sessions, or provider keys (42501)', async () => {
      await expectSqlState(workerClient.query('SELECT * FROM users'), '42501');
      await expectSqlState(workerClient.query('SELECT * FROM web_sessions'), '42501');
      await expectSqlState(workerClient.query('SELECT ciphertext FROM provider_keys'), '42501');
      await expectSqlState(workerClient.query('SELECT wrapped_dek FROM organizations'), '42501');
    });

    it('Least privilege: gateway_app direct query on virtual_keys or users without tenant context returns 0 rows under RLS', async () => {
      // Without withTenant context, RLS default deny applies
      const vk = await appClient.query('SELECT * FROM virtual_keys');
      expect(vk.rows).toHaveLength(0);

      const users = await appClient.query('SELECT * FROM users');
      expect(users.rows).toHaveLength(0);
    });
  });

  describe('Upgrade verification: 0009 database upgrades to 0010 seamlessly', () => {
    it('applies 0001-0009, seeds data, verifies failure without role grant, then reconciles and upgrades to 0010', async () => {
      const upgradeDb = await createDisposableDatabase(cluster, 'priv_upgrade');
      databases.push(upgradeDb);
      await bootstrapDatabase(upgradeDb, passwords);

      const migratorPool = new pg.Pool({
        connectionString: roleConnectionString(
          upgradeDb.url,
          'gateway_migrator',
          passwords.gateway_migrator,
        ),
      });

      // Revoke executor roles from gateway_migrator temporarily on upgradeDb to test fail-closed check in 0010
      const dbAdmin = new pg.Client({ connectionString: upgradeDb.url });
      await dbAdmin.connect();
      try {
        await dbAdmin.query(
          'REVOKE gateway_auth_executor, gateway_ops_executor FROM gateway_migrator',
        );

        // Apply migrations up to 0009 using custom runner or running 0001-0009
        // First run 0001-0009: We can run with an isolated migrationsDir containing 0001-0009
        const { loadMigrationFiles } = await import('./migrate.js');
        const fs = await import('node:fs');
        const path = await import('node:path');
        const os = await import('node:os');

        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'switchyard-mig-0009-'));
        try {
          const allFiles = loadMigrationFiles();
          for (const f of allFiles) {
            if (f.version <= '0009') {
              fs.writeFileSync(path.join(tempDir, `${f.name}.sql`), f.sql);
            }
          }

          // Apply 0001-0009
          const applied0009 = await runMigrations(migratorPool, { migrationsDir: tempDir });
          expect(applied0009).toHaveLength(9);

          // Now try to apply all migrations (including 0010) while gateway_migrator lacks executor membership:
          // Must fail closed with 42501 from migration 0010 pre-check!
          await expect(runMigrations(migratorPool)).rejects.toThrow();

          // Now perform operator reconciliation via provision-roles.sql grant:
          await dbAdmin.query(`
            GRANT gateway_auth_executor, gateway_ops_executor TO gateway_migrator
            WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;
          `);
          await dbAdmin.query(`
            GRANT USAGE, CREATE ON SCHEMA app_private TO gateway_owner, gateway_migrator,
              gateway_auth_executor, gateway_ops_executor;
          `);

          // Re-running migrations applies 0010 cleanly!
          const applied0010 = await runMigrations(migratorPool);
          expect(applied0010).toEqual(['0010']);

          // Re-running migrations again is a no-op
          const rerun = await runMigrations(migratorPool);
          expect(rerun).toEqual([]);
        } finally {
          fs.rmSync(tempDir, { recursive: true, force: true });
        }
      } finally {
        await migratorPool.end();
        await dbAdmin.end();
      }
    });
  });
});
