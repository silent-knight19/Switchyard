import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { runMigrations } from './migrate.js';
import { createPostgresClient } from '../infrastructure/postgres.js';
import type { GatewayConfig } from '../config/index.js';
import {
  bootstrapDatabase,
  createDisposableDatabase,
  createRolePasswords,
  roleConnectionString,
  schemaAclEntryForPublic,
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

/** Assert the exact SQLSTATE so a connection or syntax failure cannot satisfy a denial test. */
async function expectSqlState(promise: Promise<unknown>, sqlState: string): Promise<unknown> {
  const error = await captureError(promise);
  expect(
    errorCode(error),
    `expected SQLSTATE ${sqlState}, got ${String(errorCode(error))}: ${errorMessage(error)}`,
  ).toBe(sqlState);
  return error;
}

describe('SW-1.3.1 role privileges under real authenticated sessions', () => {
  let cluster: DisposableCluster;
  const databases: DisposableDatabase[] = [];
  const passwords = createRolePasswords();
  let database: DisposableDatabase;
  const clients: pg.Client[] = [];
  const executorPassword = 'executor-login-probe';

  async function connectAs(role: LoginRole): Promise<pg.Client> {
    const client = new pg.Client({
      connectionString: roleConnectionString(database.url, role, passwords[role]),
    });
    await client.connect();
    clients.push(client);
    return client;
  }

  async function connectWithPassword(role: LoginRole, password: string): Promise<pg.Client> {
    const client = new pg.Client({
      connectionString: roleConnectionString(database.url, role, password),
    });
    await client.connect();
    return client;
  }

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    database = await createDisposableDatabase(cluster, 'privileges');
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
      await runMigrations(migrator);
    } finally {
      await migrator.end();
    }

    const seeder = new pg.Client({ connectionString: database.url });
    await seeder.connect();
    try {
      await seeder.query(
        'INSERT INTO gateway_control (id, gateway_epoch, updated_at) VALUES (1, 0, clock_timestamp())',
      );
      // NOLOGIN is enforced after authentication, so give the executors a password and prove
      // that a *correctly authenticated* executor session is still refused (SQLSTATE 28000).
      await seeder.query(`ALTER ROLE gateway_auth_executor PASSWORD '${executorPassword}'`);
      await seeder.query(`ALTER ROLE gateway_ops_executor PASSWORD '${executorPassword}'`);
    } finally {
      await seeder.end();
    }
  });

  afterAll(async () => {
    for (const client of clients) await client.end().catch(() => undefined);
    for (const db of databases) await db.drop().catch(() => undefined);
    await cluster?.stop();
  });

  it('gateway_app reads gateway_control but cannot mutate it', async () => {
    const app = await connectAs('gateway_app');
    const { rows } = await app.query<{ id: number; gateway_epoch: string }>(
      'SELECT id, gateway_epoch FROM gateway_control',
    );
    expect(rows).toEqual([{ id: 1, gateway_epoch: '0' }]);

    await expectSqlState(
      app.query('UPDATE gateway_control SET gateway_epoch = 1 WHERE id = 1'),
      '42501',
    );
    await expectSqlState(
      app.query(
        'INSERT INTO gateway_control (id, gateway_epoch, updated_at) VALUES (1, 1, clock_timestamp())',
      ),
      '42501',
    );
    await expectSqlState(app.query('DELETE FROM gateway_control'), '42501');
  });

  it('gateway_startup updates only the epoch column', async () => {
    const startup = await connectAs('gateway_startup');
    const update = await startup.query('UPDATE gateway_control SET gateway_epoch = 7 WHERE id = 1');
    expect(update.rowCount).toBe(1);

    await expectSqlState(startup.query('UPDATE gateway_control SET id = 1 WHERE id = 1'), '42501');
    await expectSqlState(
      startup.query('UPDATE gateway_control SET updated_at = clock_timestamp()'),
      '42501',
    );
    await expectSqlState(
      startup.query(
        'INSERT INTO gateway_control (id, gateway_epoch, updated_at) VALUES (1, 9, clock_timestamp())',
      ),
      '42501',
    );
    await expectSqlState(startup.query('DELETE FROM gateway_control'), '42501');
  });

  it('gateway_worker has no gateway_control privilege', async () => {
    const worker = await connectAs('gateway_worker');
    await expectSqlState(worker.query('SELECT * FROM gateway_control'), '42501');
    await expectSqlState(worker.query('UPDATE gateway_control SET gateway_epoch = 3'), '42501');
  });

  it('enforces least-privilege table grants across runtime roles (Subphase 1.4 matrix)', async () => {
    const app = await connectAs('gateway_app');
    const worker = await connectAs('gateway_worker');
    const startup = await connectAs('gateway_startup');

    // 1. gateway_startup holds ZERO tenant-table privileges
    const tenantTables = [
      'organizations',
      'users',
      'web_sessions',
      'provider_keys',
      'virtual_keys',
      'gateway_requests',
      'provider_attempts',
      'provider_cost_adjustments',
      'trace_payloads',
    ];
    for (const table of tenantTables) {
      await expectSqlState(startup.query(`SELECT * FROM ${table}`), '42501');
    }

    // 2. gateway_worker has ZERO privileges on users and web_sessions (§12.1)
    await expectSqlState(worker.query('SELECT * FROM users'), '42501');
    await expectSqlState(worker.query('SELECT * FROM web_sessions'), '42501');

    // 3. gateway_worker is strictly denied provider/organization encryption secrets (§12.1, §19.4)
    await expectSqlState(worker.query('SELECT wrapped_dek FROM organizations'), '42501');
    await expectSqlState(worker.query('SELECT dek_iv FROM organizations'), '42501');
    await expectSqlState(worker.query('SELECT dek_auth_tag FROM organizations'), '42501');
    await expectSqlState(worker.query('SELECT ciphertext FROM provider_keys'), '42501');
    await expectSqlState(worker.query('SELECT iv FROM provider_keys'), '42501');
    await expectSqlState(worker.query('SELECT auth_tag FROM provider_keys'), '42501');

    // 4. Financial tables are protected against direct DELETE for both app and worker
    for (const client of [app, worker]) {
      await expectSqlState(client.query('DELETE FROM gateway_requests'), '42501');
      await expectSqlState(client.query('DELETE FROM provider_attempts'), '42501');
      await expectSqlState(client.query('DELETE FROM provider_cost_adjustments'), '42501');
      await expectSqlState(
        client.query('UPDATE provider_cost_adjustments SET delta_microdollars = 0'),
        '42501',
      );
    }

    // 5. Without tenant context, permitted SELECTs return zero rows due to RLS
    const { rows: appOrgs } = await app.query('SELECT * FROM organizations');
    expect(appOrgs).toHaveLength(0);
    const { rows: appUsers } = await app.query('SELECT * FROM users');
    expect(appUsers).toHaveLength(0);
    const { rows: workerVirtualKeys } = await worker.query('SELECT * FROM virtual_keys');
    expect(workerVirtualKeys).toHaveLength(0);
  });

  it('runtime roles cannot read or modify migration metadata', async () => {
    const app = await connectAs('gateway_app');
    const worker = await connectAs('gateway_worker');
    for (const client of [app, worker]) {
      await expectSqlState(client.query('SELECT * FROM gateway_migrations'), '42501');
      await expectSqlState(
        client.query(
          `INSERT INTO gateway_migrations (version, name, checksum) VALUES ('9999', 'x', 'y')`,
        ),
        '42501',
      );
      await expectSqlState(
        client.query(`UPDATE gateway_migrations SET name = 'tampered' WHERE version = '0001'`),
        '42501',
      );
      await expectSqlState(client.query('DELETE FROM gateway_migrations'), '42501');
    }
  });

  it('runtime roles cannot DDL or create shadow objects', async () => {
    const app = await connectAs('gateway_app');
    const worker = await connectAs('gateway_worker');
    const startup = await connectAs('gateway_startup');

    for (const [index, client] of [app, worker, startup].entries()) {
      await expectSqlState(
        client.query(`CREATE TABLE public.runtime_shadow_${String(index)} (id INT)`),
        '42501',
      );
      await expectSqlState(
        client.query(`CREATE TABLE app_private.private_shadow_${String(index)} (id INT)`),
        '42501',
      );
      await expectSqlState(client.query(`CREATE SCHEMA runtime_schema_${String(index)}`), '42501');
    }

    await expectSqlState(
      app.query(`CREATE FUNCTION public.shadow_fn() RETURNS INT LANGUAGE sql AS 'SELECT 1'`),
      '42501',
    );
  });

  it('runtime roles cannot assume the owner or executor roles', async () => {
    const app = await connectAs('gateway_app');
    const worker = await connectAs('gateway_worker');
    const startup = await connectAs('gateway_startup');

    for (const client of [app, worker, startup]) {
      await expectSqlState(client.query('SET ROLE gateway_owner'), '42501');
      await expectSqlState(client.query('SET ROLE gateway_auth_executor'), '42501');
      await expectSqlState(client.query('SET ROLE gateway_ops_executor'), '42501');
    }
  });

  it('gateway_migrator holds only authorized deployment assumptions and no CREATEROLE', async () => {
    const migrator = await connectAs('gateway_migrator');
    await migrator.query('SET ROLE gateway_owner');
    const { rows: ownerRows } = await migrator.query<{ current_user: string }>(
      'SELECT current_user',
    );
    expect(ownerRows[0]?.current_user).toBe('gateway_owner');
    await migrator.query('RESET ROLE');

    // Authorized deployment assumptions for executor roles during migration
    await migrator.query('SET ROLE gateway_auth_executor');
    const { rows: authRows } = await migrator.query<{ current_user: string }>(
      'SELECT current_user',
    );
    expect(authRows[0]?.current_user).toBe('gateway_auth_executor');
    await migrator.query('RESET ROLE');

    await migrator.query('SET ROLE gateway_ops_executor');
    const { rows: opsRows } = await migrator.query<{ current_user: string }>('SELECT current_user');
    expect(opsRows[0]?.current_user).toBe('gateway_ops_executor');
    await migrator.query('RESET ROLE');

    // Still no CREATEROLE or superuser escalation
    await expectSqlState(migrator.query('CREATE ROLE migrator_probe LOGIN'), '42501');
    await expectSqlState(migrator.query('ALTER ROLE gateway_app SUPERUSER'), '42501');
  });

  it('executor roles cannot log in (NOLOGIN)', async () => {
    for (const role of ['gateway_auth_executor', 'gateway_ops_executor'] as const) {
      const client = new pg.Client({
        connectionString: roleConnectionString(database.url, role as LoginRole, executorPassword),
      });
      const error = await captureError(
        client.connect().finally(() => client.end().catch(() => undefined)),
      );
      expect(errorCode(error), `${role} must not be allowed to log in`).toBe('28000');
      expect(errorMessage(error)).toMatch(/not permitted to log in/);
    }
  });

  it('a wrong password fails authentication with SQLSTATE 28P01', async () => {
    const error = await captureError(
      connectWithPassword('gateway_app', 'not-the-password').finally(() => undefined),
    );
    expect(errorCode(error)).toBe('28P01');
  });

  it('schema privileges: no PUBLIC CREATE, app_private protected, owner USAGE only', async () => {
    const inspector = new pg.Client({ connectionString: database.url });
    await inspector.connect();
    try {
      const { rows } = await inspector.query<{
        public_create: boolean;
        app_private_create: boolean;
        app_private_usage: boolean;
        migrator_public_create: boolean;
      }>(
        `SELECT
           has_schema_privilege('gateway_app', 'public', 'CREATE') AS public_create,
           has_schema_privilege('gateway_app', 'app_private', 'CREATE') AS app_private_create,
           has_schema_privilege('gateway_app', 'app_private', 'USAGE') AS app_private_usage,
           has_schema_privilege('gateway_migrator', 'public', 'CREATE') AS migrator_public_create`,
      );
      expect(rows[0]).toEqual({
        public_create: false,
        app_private_create: false,
        app_private_usage: true,
        migrator_public_create: true,
      });

      const { rows: acl } = await inspector.query<{ nspname: string; acl: string | null }>(
        `SELECT nspname, nspacl::text AS acl FROM pg_namespace
         WHERE nspname IN ('public', 'app_private') ORDER BY nspname`,
      );
      const publicEntry = schemaAclEntryForPublic(
        acl.find((row) => row.nspname === 'public')?.acl ?? null,
      );
      expect(publicEntry, 'PUBLIC must not hold CREATE on schema public').not.toContain('C');
      const appPrivateEntry = schemaAclEntryForPublic(
        acl.find((row) => row.nspname === 'app_private')?.acl ?? null,
      );
      expect(appPrivateEntry, 'PUBLIC must hold no privilege on app_private').toBe('');

      const { rows: publicTableGrants } = await inspector.query<{ count: number }>(
        `SELECT count(*)::int AS count
         FROM information_schema.table_privileges
         WHERE table_schema = 'public'
           AND table_name IN ('organizations', 'users', 'web_sessions', 'provider_keys',
                              'virtual_keys', 'gateway_control', 'gateway_migrations',
                              'gateway_requests', 'provider_attempts', 'provider_cost_adjustments',
                              'trace_payloads')
           AND grantee = 'PUBLIC'`,
      );
      expect(publicTableGrants[0]?.count).toBe(0);
    } finally {
      await inspector.end();
    }
  });

  it('distinguishes RLS denials from plain privilege denials', async () => {
    const owner = new pg.Client({ connectionString: database.url });
    await owner.connect();
    try {
      await owner.query('SET ROLE gateway_owner');
      const rlsError = await expectSqlState(
        owner.query(
          `INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
           VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'blocked', 1, 1, 'x', 'y', 'z')`,
        ),
        '42501',
      );
      expect(errorMessage(rlsError)).toMatch(/row-level security/i);
    } finally {
      await owner.query('RESET ROLE').catch(() => undefined);
      await owner.end();
    }

    const app = await connectAs('gateway_app');
    const privilegeError = await expectSqlState(app.query('DELETE FROM gateway_requests'), '42501');
    expect(errorMessage(privilegeError)).toMatch(/permission denied/i);
  });

  it('clean-clone bootstrap, migration, and Gateway startup succeed in documented order (DB-12)', async () => {
    // 1. Fresh empty database on clean cluster
    const freshDb = await createDisposableDatabase(cluster, 'clean_clone_order');
    databases.push(freshDb);

    // 2. Step 1 (Privileged): Superuser provisions roles and sets role passwords
    await bootstrapDatabase(freshDb, passwords);

    // 3. Step 2 (Unprivileged): Deployment role runs forward-only migrations
    const migrator = new pg.Pool({
      connectionString: roleConnectionString(
        freshDb.url,
        'gateway_migrator',
        passwords.gateway_migrator,
      ),
    });
    try {
      const applied = await runMigrations(migrator);
      expect(applied).toHaveLength(10);
    } finally {
      await migrator.end();
    }

    // 4. Step 3 (Gateway runtime): Fastify Gateway connects as restricted gateway_app
    const parsedUrl = new URL(freshDb.url);
    const gatewayPg = createPostgresClient({
      POSTGRES_HOST: parsedUrl.hostname,
      POSTGRES_PORT: Number(parsedUrl.port),
      POSTGRES_DB: parsedUrl.pathname.slice(1),
      POSTGRES_USER: 'gateway_app',
      POSTGRES_PASSWORD: passwords.gateway_app,
    } as unknown as GatewayConfig);

    try {
      const readiness = await gatewayPg.checkReadiness();
      expect(readiness.ok).toBe(true);

      const session = await gatewayPg.pool.query<{
        current_user: string;
        rolsuper: boolean;
        rolbypassrls: boolean;
      }>('SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user');
      expect(session.rows[0]?.current_user).toBe('gateway_app');
      expect(session.rows[0]?.rolsuper).toBe(false);
      expect(session.rows[0]?.rolbypassrls).toBe(false);

      // Verify Gateway runtime cannot perform DDL on tenant tables
      await expectSqlState(
        gatewayPg.pool.query('CREATE TABLE organizations_probe (id uuid PRIMARY KEY)'),
        '42501',
      );
      await expectSqlState(
        gatewayPg.pool.query('ALTER TABLE organizations ADD COLUMN probe text'),
        '42501',
      );
      await expectSqlState(gatewayPg.pool.query('DROP TABLE organizations'), '42501');

      // Verify Gateway runtime cannot assume owner or executor roles
      await expectSqlState(gatewayPg.pool.query('SET ROLE gateway_owner'), '42501');
      await expectSqlState(gatewayPg.pool.query('SET ROLE gateway_auth_executor'), '42501');
    } finally {
      await gatewayPg.close();
    }
  });
});
