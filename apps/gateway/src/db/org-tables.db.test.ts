import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { runMigrations } from './migrate.js';
import {
  bootstrapDatabase,
  copyMigrationsToTempDir,
  createDisposableDatabase,
  createRolePasswords,
  removeTempDir,
  roleConnectionString,
  startDisposableCluster,
  type DisposableCluster,
  type DisposableDatabase,
} from './test/disposable-pg.js';

const TENANT_TABLES = ['organizations', 'users', 'web_sessions', 'provider_keys', 'virtual_keys'];
const CORE_TABLES = [...TENANT_TABLES, 'gateway_control'];

const ORG_A = '11111111-1111-4111-8111-111111111111';
const ORG_B = '22222222-2222-4222-8222-222222222222';
const ORG_LEGACY = '33333333-3333-4333-8333-333333333333';
const USER_A = '44444444-4444-4444-8444-444444444444';
const USER_B = '55555555-5555-4555-8555-555555555555';
const UNKNOWN_ORG = '99999999-9999-4999-8999-999999999999';
const MAX_BUDGET = 1000000000000000;

const SESSION_A = Buffer.from('session-a-0123456789abcdef', 'utf8');
const SESSION_B = Buffer.from('session-b-0123456789abcdef', 'utf8');
const VIRTUAL_KEY_A_ID = '66666666-6666-4666-8666-666666666667';
const VIRTUAL_KEY_A = Buffer.from('virtual-key-a-0123456789', 'utf8');
const VIRTUAL_KEY_B = Buffer.from('virtual-key-b-0123456789', 'utf8');
const VIRTUAL_KEY_B_ID = '77777777-7777-4777-8777-777777777779';

type ColumnInfo = {
  column_name: string;
  data_type: string;
  is_nullable: string;
  column_default: string | null;
  udt_name: string;
};

async function captureError(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => null,
    (error: unknown) => error,
  );
}

/** Assert the exact PostgreSQL SQLSTATE so an unrelated failure cannot satisfy a negative test. */
async function expectSqlState(promise: Promise<unknown>, sqlState: string): Promise<void> {
  const error = await captureError(promise);
  const code =
    typeof error === 'object' && error !== null ? (error as { code?: unknown }).code : undefined;
  const detail = error instanceof Error ? error.message : String(error);
  expect(code, `expected SQLSTATE ${sqlState}, got ${String(code)}: ${detail}`).toBe(sqlState);
}

async function columnInfo(
  executor: pg.Pool | pg.Client,
  table: string,
): Promise<Map<string, ColumnInfo>> {
  const { rows } = await executor.query<ColumnInfo>(
    `SELECT column_name, data_type, is_nullable, column_default, udt_name
     FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1`,
    [table],
  );
  return new Map(rows.map((row) => [row.column_name, row]));
}

function expectNullable(columns: Map<string, ColumnInfo>, column: string): void {
  expect(columns.get(column)?.is_nullable, `column ${column} must be nullable`).toBe('YES');
}

describe('SW-1.3.2 tenant core tables: constraints, RLS posture, upgrade safety', () => {
  let cluster: DisposableCluster;
  const databases: DisposableDatabase[] = [];
  const passwords = createRolePasswords();

  let fresh: DisposableDatabase;
  let upgraded: DisposableDatabase;
  let pool: pg.Pool;

  async function createDatabase(label: string): Promise<DisposableDatabase> {
    const database = await createDisposableDatabase(cluster, label);
    await bootstrapDatabase(database, passwords);
    databases.push(database);
    return database;
  }

  async function migrate(database: DisposableDatabase, migrationsDir?: string): Promise<string[]> {
    const migrator = new pg.Pool({
      connectionString: roleConnectionString(
        database.url,
        'gateway_migrator',
        passwords.gateway_migrator,
      ),
    });
    try {
      return await runMigrations(migrator, migrationsDir === undefined ? {} : { migrationsDir });
    } finally {
      await migrator.end();
    }
  }

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    fresh = await createDatabase('core');
    await migrate(fresh);
    pool = new pg.Pool({ connectionString: fresh.url });

    // Simulated Batch A installation: 0001 + 0002 only, with existing tenant data.
    upgraded = await createDatabase('upgrade');
    const legacyDir = copyMigrationsToTempDir(['0001-roles.sql', '0002-org-tables.sql']);
    try {
      await migrate(upgraded, legacyDir);
    } finally {
      removeTempDir(legacyDir);
    }
    const legacyClient = new pg.Client({ connectionString: upgraded.url });
    await legacyClient.connect();
    try {
      await legacyClient.query(
        `INSERT INTO organizations
           (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
         VALUES ($1, 'Legacy Org', 1000000, 1, $2, $3, $4)`,
        [ORG_LEGACY, Buffer.from('dek'), Buffer.from('iv'), Buffer.from('tag')],
      );
    } finally {
      await legacyClient.end();
    }
    expect(await migrate(upgraded)).toEqual([
      '0003',
      '0004',
      '0005',
      '0006',
      '0007',
      '0008',
      '0009',
      '0010',
    ]);
  });

  afterAll(async () => {
    await pool?.end().catch(() => undefined);
    for (const database of databases) {
      await database.drop().catch(() => undefined);
    }
    await cluster?.stop();
  });

  it('creates the six required core tables owned by gateway_owner', async () => {
    const { rows } = await pool.query<{ relname: string; owner: string }>(
      `SELECT c.relname, pg_get_userbyid(c.relowner) AS owner
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname = ANY($1::text[])
       ORDER BY c.relname`,
      [CORE_TABLES],
    );
    expect(rows.map((row) => row.relname)).toEqual([...CORE_TABLES].sort());
    for (const row of rows) expect(row.owner).toBe('gateway_owner');
  });

  it('enables and forces RLS on tenant tables, keeps gateway_control global, and holds zero policies', async () => {
    const { rows } = await pool.query<{
      relname: string;
      rls: boolean;
      forced: boolean;
    }>(
      `SELECT relname, relrowsecurity AS rls, relforcerowsecurity AS forced
       FROM pg_class
       WHERE relname = ANY($1::text[])`,
      [CORE_TABLES],
    );
    const byName = new Map(rows.map((row) => [row.relname, row]));
    for (const table of TENANT_TABLES) {
      expect(byName.get(table)?.rls, `${table} RLS enabled`).toBe(true);
      expect(byName.get(table)?.forced, `${table} RLS forced`).toBe(true);
    }
    expect(byName.get('gateway_control')?.rls).toBe(false);
    expect(byName.get('gateway_control')?.forced).toBe(false);

    const { rows: policies } = await pool.query<{ tablename: string; policyname: string }>(
      `SELECT tablename, policyname FROM pg_policies WHERE schemaname = 'public' ORDER BY tablename`,
    );
    // Subphase 1.4 (SW-1.4.2) defines exactly one unified tenant isolation policy per tenant table.
    expect(policies).toEqual([
      { tablename: 'gateway_requests', policyname: 'gateway_requests_tenant_isolation' },
      { tablename: 'organizations', policyname: 'organizations_tenant_isolation' },
      { tablename: 'provider_attempts', policyname: 'provider_attempts_tenant_isolation' },
      {
        tablename: 'provider_cost_adjustments',
        policyname: 'provider_cost_adjustments_tenant_isolation',
      },
      { tablename: 'provider_keys', policyname: 'provider_keys_tenant_isolation' },
      { tablename: 'trace_payloads', policyname: 'trace_payloads_tenant_isolation' },
      { tablename: 'users', policyname: 'users_tenant_isolation' },
      { tablename: 'virtual_keys', policyname: 'virtual_keys_tenant_isolation' },
      { tablename: 'web_sessions', policyname: 'web_sessions_tenant_isolation' },
    ]);
  });

  it('default-deny is effective for a non-superuser table owner without tenant context and on mismatched org', async () => {
    const client = await pool.connect();
    try {
      await client.query('SET ROLE gateway_owner');
      const { rows: withoutContext } = await client.query<{ count: number }>(
        'SELECT count(*)::int AS count FROM users',
      );
      expect(withoutContext[0]?.count).toBe(0);

      // Attempting to insert without tenant context is rejected by RLS (42501)
      await expectSqlState(
        client.query(
          `INSERT INTO users (id, org_id, email_normalized, password_hash, role)
           VALUES ($1, $2, 'rls-probe@example.com', 'hash', 'member')`,
          [USER_B, ORG_A],
        ),
        '42501',
      );

      // Attempting to insert with mismatched tenant context (Org B context inserting Org A row) is rejected by RLS (42501)
      await client.query(`SELECT set_config('app.current_org_id', $1, false)`, [ORG_B]);
      await expectSqlState(
        client.query(
          `INSERT INTO users (id, org_id, email_normalized, password_hash, role)
           VALUES ($1, $2, 'rls-probe@example.com', 'hash', 'member')`,
          [USER_B, ORG_A],
        ),
        '42501',
      );
    } finally {
      await client.query('RESET ROLE').catch(() => undefined);
      client.release();
    }
  });

  it('declares the required columns, types, and defaults', async () => {
    const organizations = await columnInfo(pool, 'organizations');
    for (const [column, type] of Object.entries({
      id: 'uuid',
      name: 'text',
      monthly_budget_microdollars: 'bigint',
      kek_version: 'integer',
      wrapped_dek: 'bytea',
      dek_iv: 'bytea',
      dek_auth_tag: 'bytea',
      created_at: 'timestamp with time zone',
    })) {
      expect(organizations.get(column)?.data_type, `organizations.${column}`).toBe(type);
      expect(organizations.get(column)?.is_nullable).toBe('NO');
    }
    expect(organizations.get('created_at')?.column_default).toMatch(/clock_timestamp/);

    const control = await columnInfo(pool, 'gateway_control');
    expect(control.get('id')?.data_type).toBe('smallint');
    expect(control.get('gateway_epoch')?.data_type).toBe('bigint');
    expect(control.get('updated_at')?.data_type).toBe('timestamp with time zone');
    for (const column of ['id', 'gateway_epoch', 'updated_at']) {
      expect(control.get(column)?.is_nullable).toBe('NO');
    }

    const users = await columnInfo(pool, 'users');
    for (const column of [
      'id',
      'org_id',
      'email_normalized',
      'password_hash',
      'role',
      'created_at',
    ]) {
      expect(users.get(column)?.is_nullable, `users.${column}`).toBe('NO');
    }

    const sessions = await columnInfo(pool, 'web_sessions');
    expect(sessions.get('session_id_hash')?.udt_name).toBe('bytea');
    expect(sessions.get('csrf_token_hash')?.udt_name).toBe('bytea');
    for (const column of [
      'session_id_hash',
      'user_id',
      'org_id',
      'csrf_token_hash',
      'created_at',
      'last_seen_at',
      'idle_expires_at',
      'absolute_expires_at',
    ]) {
      expect(sessions.get(column)?.is_nullable, `web_sessions.${column}`).toBe('NO');
    }
    expectNullable(sessions, 'revoked_at');

    const providerKeys = await columnInfo(pool, 'provider_keys');
    for (const column of ['ciphertext', 'iv', 'auth_tag']) {
      expect(providerKeys.get(column)?.udt_name, `provider_keys.${column}`).toBe('bytea');
      expect(providerKeys.get(column)?.is_nullable).toBe('NO');
    }

    const virtualKeys = await columnInfo(pool, 'virtual_keys');
    expect(virtualKeys.get('key_hash')?.udt_name).toBe('bytea');
    expect(virtualKeys.get('allowed_models')?.data_type).toBe('ARRAY');
    for (const column of [
      'key_hash',
      'allowed_models',
      'rpm_limit',
      'tpm_limit',
      'concurrent_stream_limit',
      'exact_cache_enabled',
      'semantic_cache_enabled',
      'pii_redaction_enabled',
      'store_payloads',
    ]) {
      expect(virtualKeys.get(column)?.is_nullable, `virtual_keys.${column}`).toBe('NO');
    }
    expect(virtualKeys.get('exact_cache_enabled')?.column_default).toMatch(/false/i);
    expect(virtualKeys.get('semantic_cache_enabled')?.column_default).toMatch(/false/i);
    expect(virtualKeys.get('pii_redaction_enabled')?.column_default).toMatch(/false/i);
    expect(virtualKeys.get('store_payloads')?.column_default).toMatch(/true/i);
  });

  it('declares the required primary, unique, check, and composite foreign keys', async () => {
    const { rows } = await pool.query<{ conname: string; contype: string; def: string }>(
      `SELECT conname, contype, pg_get_constraintdef(oid) AS def
       FROM pg_constraint
       WHERE conrelid = ANY($1::regclass[])
       ORDER BY conname`,
      [CORE_TABLES],
    );
    const defs = new Map(rows.map((row) => [row.conname, row.def]));
    const kinds = new Map(rows.map((row) => [row.conname, row.contype]));

    expect(kinds.get('organizations_pkey')).toBe('p');
    expect(defs.get('organizations_monthly_budget_microdollars_check')).toContain(
      'monthly_budget_microdollars >= 0',
    );
    expect(defs.get('organizations_monthly_budget_microdollars_check')).toContain(
      '1000000000000000',
    );
    expect(kinds.get('gateway_control_pkey')).toBe('p');
    expect(defs.get('gateway_control_id_check')).toContain('id = 1');
    expect(kinds.get('users_email_normalized_key')).toBe('u');
    expect(defs.get('users_role_check')).toContain("'admin'");
    expect(defs.get('users_role_check')).toContain("'member'");
    expect(defs.get('web_sessions_user_id_org_id_fkey')).toContain(
      'FOREIGN KEY (user_id, org_id) REFERENCES users(id, org_id)',
    );
    expect(defs.get('provider_keys_provider_check')).toContain("'openai'");
    expect(defs.get('virtual_keys_rpm_limit_check')).toContain('rpm_limit > 0');
    expect(defs.get('virtual_keys_tpm_limit_check')).toContain('tpm_limit > 0');
    expect(defs.get('virtual_keys_concurrent_stream_limit_check')).toContain(
      'concurrent_stream_limit > 0',
    );
    expect(kinds.get('virtual_keys_key_hash_key')).toBe('u');
  });

  it('accepts valid rows for every core table', async () => {
    await pool.query(
      `INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
       VALUES ($1, 'Org A', 5000000, 1, $2, $3, $4)`,
      [ORG_A, Buffer.from('dek-a'), Buffer.from('iv-a'), Buffer.from('tag-a')],
    );
    await pool.query(
      `INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
       VALUES ($1, 'Org B', 0, 1, $2, $3, $4)`,
      [ORG_B, Buffer.from('dek-b'), Buffer.from('iv-b'), Buffer.from('tag-b')],
    );
    await pool.query(
      `INSERT INTO users (id, org_id, email_normalized, password_hash, role)
       VALUES ($1, $2, 'owner@example.com', 'argon2-hash', 'admin')`,
      [USER_A, ORG_A],
    );
    await pool.query(
      `INSERT INTO web_sessions (session_id_hash, user_id, org_id, csrf_token_hash, last_seen_at, idle_expires_at, absolute_expires_at)
       VALUES ($1, $2, $3, $4, clock_timestamp(), clock_timestamp() + interval '1 hour', clock_timestamp() + interval '24 hours')`,
      [SESSION_A, USER_A, ORG_A, Buffer.from('csrf-a')],
    );
    await pool.query(
      `INSERT INTO provider_keys (id, org_id, provider, label, key_hint, ciphertext, iv, auth_tag, is_active)
       VALUES ($1, $2, 'openai', 'primary', '1234', $3, $4, $5, true)`,
      [
        '66666666-6666-4666-8666-666666666666',
        ORG_A,
        Buffer.from('cipher'),
        Buffer.from('iv'),
        Buffer.from('tag'),
      ],
    );
    await pool.query(
      `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
       VALUES ($1, $2, 'vk-1', 'gw_live_', $3, $4, 60, 60000, 4)`,
      [VIRTUAL_KEY_A_ID, ORG_A, VIRTUAL_KEY_A, ['openai']],
    );
    await pool.query(
      `INSERT INTO gateway_control (id, gateway_epoch, updated_at) VALUES (1, 0, clock_timestamp())`,
    );

    const { rows } = await pool.query<{ count: number }>(
      'SELECT count(*)::int AS count FROM organizations',
    );
    expect(rows[0]?.count).toBe(2);
  });

  it('rejects duplicate, orphaned, and invalid rows with exact SQLSTATEs', async () => {
    const insertOrganization = (id: string, name: string, budget: number) =>
      pool.query(
        `INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
         VALUES ($1, $2, $3, 1, $4, $5, $6)`,
        [id, name, budget, Buffer.from('dek'), Buffer.from('iv'), Buffer.from('tag')],
      );
    const insertUser = (id: string, orgId: string, email: string, role = 'member') =>
      pool.query(
        `INSERT INTO users (id, org_id, email_normalized, password_hash, role)
         VALUES ($1, $2, $3, 'hash', $4)`,
        [id, orgId, email, role],
      );
    const insertSession = (hash: Buffer, userId: string, orgId: string) =>
      pool.query(
        `INSERT INTO web_sessions (session_id_hash, user_id, org_id, csrf_token_hash, last_seen_at, idle_expires_at, absolute_expires_at)
         VALUES ($1, $2, $3, $4, clock_timestamp(), clock_timestamp() + interval '1 hour', clock_timestamp() + interval '24 hours')`,
        [hash, userId, orgId, Buffer.from('csrf')],
      );
    const insertProviderKey = (
      id: string,
      orgId: string,
      provider: string,
      ciphertext: Buffer | null,
    ) =>
      pool.query(
        `INSERT INTO provider_keys (id, org_id, provider, label, key_hint, ciphertext, iv, auth_tag, is_active)
         VALUES ($1, $2, $3, 'label', '1234', $4, $5, $6, true)`,
        [id, orgId, provider, ciphertext, Buffer.from('iv'), Buffer.from('tag')],
      );
    const insertVirtualKey = (
      id: string,
      orgId: string,
      keyHash: Buffer | null,
      rpm: number | null,
      models: string[] = ['openai'],
    ) =>
      pool.query(
        `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
         VALUES ($1, $2, 'vk', 'gw_live_', $3, $4, $5, 60000, 4)`,
        [id, orgId, keyHash, models, rpm],
      );

    // organizations: primary key, budget bounds.
    await expectSqlState(insertOrganization(ORG_A, 'duplicate', 1), '23505');
    await expectSqlState(
      insertOrganization('77777777-7777-4777-8777-777777777771', 'negative', -1),
      '23514',
    );
    await expectSqlState(
      insertOrganization('77777777-7777-4777-8777-777777777772', 'too-big', MAX_BUDGET + 1),
      '23514',
    );
    await expect(
      insertOrganization('77777777-7777-4777-8777-777777777773', 'min', 0),
    ).resolves.toBeDefined();
    await expect(
      insertOrganization('77777777-7777-4777-8777-777777777774', 'max', MAX_BUDGET),
    ).resolves.toBeDefined();

    // users: global email uniqueness, tenant FK, role allowlist.
    await expectSqlState(insertUser(USER_B, ORG_A, 'owner@example.com'), '23505');
    await expectSqlState(insertUser(USER_B, UNKNOWN_ORG, 'new@example.com'), '23503');
    await expectSqlState(insertUser(USER_B, ORG_A, 'new@example.com', 'owner'), '23514');
    await expect(insertUser(USER_B, ORG_B, 'second@example.com')).resolves.toBeDefined();

    // web_sessions: hashed-session primary key and composite tenant FK.
    await expectSqlState(insertSession(SESSION_A, USER_A, ORG_A), '23505');
    await expectSqlState(insertSession(SESSION_B, USER_A, ORG_B), '23503');
    await expect(insertSession(SESSION_B, USER_A, ORG_A)).resolves.toBeDefined();

    // provider_keys: allowlisted provider, composite uniqueness, tenant FK, required ciphertext.
    await expectSqlState(
      insertProviderKey('88888888-8888-4888-8888-888888888881', ORG_A, 'mock', Buffer.from('c')),
      '23514',
    );
    await expectSqlState(
      insertProviderKey('66666666-6666-4666-8666-666666666666', ORG_A, 'openai', Buffer.from('c')),
      '23505',
    );
    await expectSqlState(
      insertProviderKey(
        '88888888-8888-4888-8888-888888888882',
        UNKNOWN_ORG,
        'openai',
        Buffer.from('c'),
      ),
      '23503',
    );
    await expectSqlState(
      insertProviderKey('88888888-8888-4888-8888-888888888883', ORG_A, 'openai', null),
      '23502',
    );

    // virtual_keys: required verifier and positive, present limits.
    await expectSqlState(insertVirtualKey(VIRTUAL_KEY_B_ID, ORG_A, VIRTUAL_KEY_A, 60), '23505');
    await expectSqlState(insertVirtualKey(VIRTUAL_KEY_B_ID, ORG_A, null, 60), '23502');
    await expectSqlState(insertVirtualKey(VIRTUAL_KEY_B_ID, ORG_A, VIRTUAL_KEY_B, null), '23502');
    await expectSqlState(insertVirtualKey(VIRTUAL_KEY_B_ID, ORG_A, VIRTUAL_KEY_B, 0), '23514');
    await expectSqlState(insertVirtualKey(VIRTUAL_KEY_B_ID, ORG_A, VIRTUAL_KEY_B, -5), '23514');
    await expectSqlState(
      insertVirtualKey(VIRTUAL_KEY_B_ID, UNKNOWN_ORG, VIRTUAL_KEY_B, 60),
      '23503',
    );

    // gateway_control: singleton constraint.
    await expectSqlState(
      pool.query(
        'INSERT INTO gateway_control (id, gateway_epoch, updated_at) VALUES (2, 0, clock_timestamp())',
      ),
      '23514',
    );
    await expectSqlState(
      pool.query(
        'INSERT INTO gateway_control (id, gateway_epoch, updated_at) VALUES (1, 0, clock_timestamp())',
      ),
      '23505',
    );
  });

  it('preserves deny-all empty allowed_models and default-disabled privacy flags', async () => {
    const { rows } = await pool.query<{
      allowed_models: string[];
      exact_cache_enabled: boolean;
      semantic_cache_enabled: boolean;
      pii_redaction_enabled: boolean;
      store_payloads: boolean;
    }>(
      `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
       VALUES ($1, $2, 'deny-all', 'gw_live_', $3, '{}', 1, 1, 1)
       RETURNING allowed_models, exact_cache_enabled, semantic_cache_enabled,
                 pii_redaction_enabled, store_payloads`,
      ['99999999-9999-4999-8999-999999999991', ORG_B, Buffer.from('deny-all-key-0123456789')],
    );
    const row = rows[0];
    expect(row?.allowed_models).toEqual([]);
    expect(row?.exact_cache_enabled).toBe(false);
    expect(row?.semantic_cache_enabled).toBe(false);
    expect(row?.pii_redaction_enabled).toBe(false);
    expect(row?.store_payloads).toBe(true);
  });

  it('upgrades a Batch A installation without data loss and converges with a fresh install', async () => {
    const upgradedClient = new pg.Client({ connectionString: upgraded.url });
    await upgradedClient.connect();
    try {
      const { rows: preserved } = await upgradedClient.query<{ id: string; name: string }>(
        'SELECT id, name FROM organizations',
      );
      expect(preserved).toEqual([{ id: ORG_LEGACY, name: 'Legacy Org' }]);

      const freshSnapshot = await schemaSnapshot(pool);
      const upgradedSnapshot = await schemaSnapshot(upgradedClient);
      expect(upgradedSnapshot).toEqual(freshSnapshot);
    } finally {
      await upgradedClient.end();
    }
  });
});

interface SchemaSnapshot {
  policies: number;
  rls: Array<{ relname: string; rls: boolean; forced: boolean }>;
  columns: Array<{ table_name: string; column_name: string; is_nullable: string }>;
  constraints: Array<{ conname: string; def: string }>;
  controlTableGrants: Array<{ grantee: string; privilege_type: string }>;
  controlColumnGrants: Array<{ grantee: string; privilege_type: string; column_name: string }>;
}

async function schemaSnapshot(executor: pg.Pool | pg.Client): Promise<SchemaSnapshot> {
  const { rows: policies } = await executor.query<{ count: number }>(
    `SELECT count(*)::int AS count FROM pg_policies WHERE schemaname = 'public'`,
  );
  const { rows: rls } = await executor.query<SchemaSnapshot['rls'][number]>(
    `SELECT relname, relrowsecurity AS rls, relforcerowsecurity AS forced
     FROM pg_class
     WHERE relname = ANY($1::text[])
     ORDER BY relname`,
    [CORE_TABLES],
  );
  const { rows: columns } = await executor.query<SchemaSnapshot['columns'][number]>(
    `SELECT table_name, column_name, is_nullable
     FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = ANY($1::text[])
     ORDER BY table_name, column_name`,
    [CORE_TABLES],
  );
  const { rows: constraints } = await executor.query<SchemaSnapshot['constraints'][number]>(
    `SELECT conname, pg_get_constraintdef(oid) AS def
     FROM pg_constraint
     WHERE conrelid = ANY($1::regclass[])
     ORDER BY conname`,
    [CORE_TABLES],
  );
  const { rows: controlTableGrants } = await executor.query<
    SchemaSnapshot['controlTableGrants'][number]
  >(
    `SELECT grantee, privilege_type
     FROM information_schema.table_privileges
     WHERE table_schema = 'public' AND table_name = 'gateway_control'
     ORDER BY grantee, privilege_type`,
  );
  const { rows: controlColumnGrants } = await executor.query<
    SchemaSnapshot['controlColumnGrants'][number]
  >(
    `SELECT grantee, privilege_type, column_name
     FROM information_schema.column_privileges
     WHERE table_schema = 'public' AND table_name = 'gateway_control'
     ORDER BY grantee, privilege_type, column_name`,
  );
  return {
    policies: policies[0]?.count ?? -1,
    rls,
    columns,
    constraints,
    controlTableGrants,
    controlColumnGrants,
  };
}
