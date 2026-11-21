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
} from './test/disposable-pg.js';

describe('SW-1.5.2 / Migration 0011: Restricted Pre-Tenant Session Organization Lookup', () => {
  let cluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();
  let adminClient: pg.Client;
  let appClient: pg.Client;
  let workerClient: pg.Client;
  let startupClient: pg.Client;

  const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
  const ORG_B_ID = '22222222-2222-4222-8222-222222222222';
  const USER_A_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const USER_B_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

  // Session secrets and verifiers
  const RAW_SECRET_A = crypto.randomBytes(32);
  const HASH_SECRET_A = crypto.createHash('sha256').update(RAW_SECRET_A).digest();
  const CSRF_A = crypto.createHash('sha256').update('csrf-a').digest();

  const RAW_SECRET_B = crypto.randomBytes(32);
  const HASH_SECRET_B = crypto.createHash('sha256').update(RAW_SECRET_B).digest();
  const CSRF_B = crypto.createHash('sha256').update('csrf-b').digest();

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    db = await createDisposableDatabase(cluster, 'session_lookup_test');
    await bootstrapDatabase(db, passwords);

    // Run migrations as gateway_migrator
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

    // Connect admin/superuser client to inspect pg catalog and seed test records
    adminClient = new pg.Client({ connectionString: db.url });
    await adminClient.connect();

    // Seed test organizations and users
    await adminClient.query(`
      INSERT INTO public.organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
      VALUES
        ('${ORG_A_ID}', 'Org Alpha', 1000000, 1, '\\x0102', '\\x0304', '\\x0506'),
        ('${ORG_B_ID}', 'Org Beta', 2000000, 1, '\\x0102', '\\x0304', '\\x0506');

      INSERT INTO public.users (id, org_id, email_normalized, password_hash, role)
      VALUES
        ('${USER_A_ID}', '${ORG_A_ID}', 'admin@alpha.com', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$dGVzdGhhc2hkYXRh', 'admin'),
        ('${USER_B_ID}', '${ORG_B_ID}', 'admin@beta.com', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$dGVzdGhhc2hkYXRh', 'admin');
    `);

    // Seed test sessions
    await adminClient.query(
      `
      INSERT INTO public.web_sessions (session_id_hash, user_id, org_id, csrf_token_hash, last_seen_at, idle_expires_at, absolute_expires_at)
      VALUES
        ($1, $2, $3, $4, clock_timestamp(), clock_timestamp() + interval '2 hours', clock_timestamp() + interval '7 days'),
        ($5, $6, $7, $8, clock_timestamp(), clock_timestamp() + interval '2 hours', clock_timestamp() + interval '7 days');
    `,
      [HASH_SECRET_A, USER_A_ID, ORG_A_ID, CSRF_A, HASH_SECRET_B, USER_B_ID, ORG_B_ID, CSRF_B],
    );

    // Connect runtime role clients
    appClient = new pg.Client({
      connectionString: roleConnectionString(db.url, 'gateway_app', passwords.gateway_app),
    });
    await appClient.connect();

    workerClient = new pg.Client({
      connectionString: roleConnectionString(db.url, 'gateway_worker', passwords.gateway_worker),
    });
    await workerClient.connect();

    startupClient = new pg.Client({
      connectionString: roleConnectionString(db.url, 'gateway_startup', passwords.gateway_startup),
    });
    await startupClient.connect();
  }, 60000);

  afterAll(async () => {
    if (appClient) await appClient.end();
    if (workerClient) await workerClient.end();
    if (startupClient) await startupClient.end();
    if (adminClient) await adminClient.end();
    if (db) await db.drop();
    if (cluster) await cluster.stop();
  }, 30000);

  describe('1. Function Definition, Ownership & Search Path Security', () => {
    it('is defined with SECURITY DEFINER, STABLE volatility, and owned by gateway_auth_executor', async () => {
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
          AND p.proname = 'lookup_session_org_by_hash';
      `);

      expect(rows).toHaveLength(1);
      const fn = rows[0]!;
      expect(fn.owner).toBe('gateway_auth_executor');
      expect(fn.prosecdef).toBe(true);
      expect(fn.provolatile).toBe('s'); // STABLE
      expect(fn.search_path).toBe('search_path=pg_catalog, app_private, pg_temp');
    });

    it('returns exactly one column "org_id UUID" and zero or one row', async () => {
      const { rows, fields } = await appClient.query<{ org_id: string }>(
        'SELECT * FROM app_private.lookup_session_org_by_hash($1)',
        [HASH_SECRET_A],
      );

      expect(fields).toHaveLength(1);
      expect(fields[0]?.name).toBe('org_id');
      expect(rows).toHaveLength(1);
      expect(rows[0]?.org_id).toBe(ORG_A_ID);
    });

    it('prevents pg_temp object shadowing through search path hardening', async () => {
      // Create a shadowing table in pg_temp
      await appClient.query(`
        CREATE TEMPORARY TABLE web_sessions (
          session_id_hash BYTEA PRIMARY KEY,
          org_id UUID NOT NULL
        );
      `);
      await appClient.query(
        `
        INSERT INTO pg_temp.web_sessions (session_id_hash, org_id)
        VALUES ($1, '99999999-9999-4999-8999-999999999999');
      `,
        [HASH_SECRET_A],
      );

      try {
        const { rows } = await appClient.query<{ org_id: string }>(
          'SELECT * FROM app_private.lookup_session_org_by_hash($1)',
          [HASH_SECRET_A],
        );
        // Must return genuine Org A ID, not shadowed 99999999 ID
        expect(rows).toHaveLength(1);
        expect(rows[0]?.org_id).toBe(ORG_A_ID);
      } finally {
        await appClient.query('DROP TABLE pg_temp.web_sessions;');
      }
    });
  });

  describe('2. Privilege Boundary & Access Matrix', () => {
    it('grants EXECUTE strictly to gateway_app', async () => {
      const res = await appClient.query<{ org_id: string }>(
        'SELECT * FROM app_private.lookup_session_org_by_hash($1)',
        [HASH_SECRET_A],
      );
      expect(res.rows).toHaveLength(1);
      expect(res.rows[0]?.org_id).toBe(ORG_A_ID);
    });

    it('denies EXECUTE to gateway_worker with 42501 permission denied', async () => {
      await expect(
        workerClient.query('SELECT * FROM app_private.lookup_session_org_by_hash($1)', [
          HASH_SECRET_A,
        ]),
      ).rejects.toMatchObject({
        code: '42501',
      });
    });

    it('denies EXECUTE to gateway_startup with 42501 permission denied', async () => {
      await expect(
        startupClient.query('SELECT * FROM app_private.lookup_session_org_by_hash($1)', [
          HASH_SECRET_A,
        ]),
      ).rejects.toMatchObject({
        code: '42501',
      });
    });

    it('denies PUBLIC EXECUTE', async () => {
      const { rows } = await adminClient.query<{ grantee: string; privilege_type: string }>(`
        SELECT grantee, privilege_type
        FROM information_schema.routine_privileges
        WHERE routine_schema = 'app_private'
          AND routine_name = 'lookup_session_org_by_hash';
      `);

      const publicGrant = rows.find((r) => r.grantee === 'PUBLIC');
      expect(publicGrant).toBeUndefined();
    });

    it('grants gateway_auth_executor only minimal column SELECT on web_sessions', async () => {
      const { rows } = await adminClient.query<{ column_name: string }>(`
        SELECT column_name
        FROM information_schema.column_privileges
        WHERE table_schema = 'public'
          AND table_name = 'web_sessions'
          AND grantee = 'gateway_auth_executor'
          AND privilege_type = 'SELECT';
      `);

      const cols = rows.map((r) => r.column_name).sort();
      expect(cols).toEqual(['org_id', 'session_id_hash']);
    });
  });

  describe('3. Input Validation & Fail-Closed Behavior', () => {
    it('returns empty set for an unknown 32-byte hash', async () => {
      const unknownHash = crypto.createHash('sha256').update('nonexistent-session').digest();
      const { rows } = await appClient.query(
        'SELECT * FROM app_private.lookup_session_org_by_hash($1)',
        [unknownHash],
      );
      expect(rows).toHaveLength(0);
    });

    it('returns empty set for NULL input', async () => {
      const { rows } = await appClient.query(
        'SELECT * FROM app_private.lookup_session_org_by_hash($1)',
        [null],
      );
      expect(rows).toHaveLength(0);
    });

    it('returns empty set for empty BYTEA input', async () => {
      const { rows } = await appClient.query(
        'SELECT * FROM app_private.lookup_session_org_by_hash($1)',
        [Buffer.alloc(0)],
      );
      expect(rows).toHaveLength(0);
    });

    it('returns empty set for 16-byte input (too short)', async () => {
      const { rows } = await appClient.query(
        'SELECT * FROM app_private.lookup_session_org_by_hash($1)',
        [Buffer.alloc(16, 0xaa)],
      );
      expect(rows).toHaveLength(0);
    });

    it('returns empty set for 31-byte input (1 byte short)', async () => {
      const { rows } = await appClient.query(
        'SELECT * FROM app_private.lookup_session_org_by_hash($1)',
        [Buffer.alloc(31, 0xbb)],
      );
      expect(rows).toHaveLength(0);
    });

    it('returns empty set for 33-byte input (1 byte long)', async () => {
      const { rows } = await appClient.query(
        'SELECT * FROM app_private.lookup_session_org_by_hash($1)',
        [Buffer.alloc(33, 0xcc)],
      );
      expect(rows).toHaveLength(0);
    });

    it('returns empty set for 64-byte input (e.g. hex-encoded string passed as bytea)', async () => {
      const { rows } = await appClient.query(
        'SELECT * FROM app_private.lookup_session_org_by_hash($1)',
        [Buffer.from(HASH_SECRET_A.toString('hex'), 'utf8')],
      );
      expect(rows).toHaveLength(0);
    });
  });

  describe('4. Cross-Tenant Resolution Correctness', () => {
    it('correctly returns Org A UUID for Session A', async () => {
      const { rows } = await appClient.query<{ org_id: string }>(
        'SELECT * FROM app_private.lookup_session_org_by_hash($1)',
        [HASH_SECRET_A],
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]?.org_id).toBe(ORG_A_ID);
    });

    it('correctly returns Org B UUID for Session B', async () => {
      const { rows } = await appClient.query<{ org_id: string }>(
        'SELECT * FROM app_private.lookup_session_org_by_hash($1)',
        [HASH_SECRET_B],
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]?.org_id).toBe(ORG_B_ID);
    });
  });

  describe('5. Migration Lifecycle & Upgrade from 0010', () => {
    it('upgrades a database at 0010 to 0011 seamlessly and is idempotent on re-run', async () => {
      const upgradeDb = await createDisposableDatabase(cluster, 'upgrade_0010_0011');
      await bootstrapDatabase(upgradeDb, passwords);

      const migratorPool = new pg.Pool({
        connectionString: roleConnectionString(
          upgradeDb.url,
          'gateway_migrator',
          passwords.gateway_migrator,
        ),
      });

      try {
        // Run migrations
        const applied = await runMigrations(migratorPool);
        expect(applied).toContain('0011');

        // Re-run migrations: should be a no-op (up-to-date)
        const reRunApplied = await runMigrations(migratorPool);
        expect(reRunApplied).toHaveLength(0);
      } finally {
        await migratorPool.end();
        await upgradeDb.drop();
      }
    });
  });
});
