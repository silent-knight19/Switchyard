import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import net from 'node:net';
import pg from 'pg';
import { MIGRATION_LEDGER_TABLE, runMigrations } from './migrate.js';

const REQUIRE_INTEGRATION =
  process.env.INTEGRATION_TESTS === 'true' ||
  process.env.INTEGRATION_TESTS === 'required' ||
  process.env.REQUIRE_INTEGRATION === 'true';

async function isPortReachable(
  port: number,
  host = '127.0.0.1',
  timeoutMs = 500,
): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const socket = net.createConnection({ host, port });
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
  });
}

const TEST_POOL_OPTIONS = {
  host: '127.0.0.1',
  port: 5432,
  database: 'switchyard',
  user: 'switchyard',
  password: 'switchyard_dev_password',
};

const ORG_A = '11111111-1111-1111-1111-111111111111';
const ORG_B = '22222222-2222-2222-2222-222222222222';
const USER_A = '33333333-3333-3333-3333-333333333333';
const USER_B = '44444444-4444-4444-4444-444444444444';
const UNKNOWN_ORG = '99999999-9999-9999-9999-999999999999';
const BIG_ORG = '55555555-5555-4555-8555-555555555555';
const SESSION_A = Buffer.from('a'.repeat(16));
const SESSION_B = Buffer.from('b'.repeat(16));
const PROVIDER_KEY_A = Buffer.from('cipher-a'.repeat(4).slice(0, 16));
const PROVIDER_KEY_B = Buffer.from('cipher-b'.repeat(4).slice(0, 16));
const VIRTUAL_KEY_A = Buffer.from('hash-vk-a'.repeat(4).slice(0, 16));
const VIRTUAL_KEY_B = Buffer.from('hash-vk-b'.repeat(4).slice(0, 16));
const VIRTUAL_KEY_C = Buffer.from('hash-vk-c'.repeat(4).slice(0, 16));

const TENANT_TABLES = ['organizations', 'users', 'web_sessions', 'provider_keys', 'virtual_keys'];

type ColumnInfo = {
  column_name: string;
  data_type: string;
  is_nullable: string;
  column_default: string | null;
  udt_name: string;
};

async function columnInfo(pool: pg.Pool, table: string): Promise<Map<string, ColumnInfo>> {
  const { rows } = await pool.query<ColumnInfo>(
    `SELECT column_name, data_type, is_nullable, column_default, udt_name
     FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1`,
    [table],
  );
  return new Map(rows.map((row) => [row.column_name, row]));
}

function expectColumns(columns: Map<string, ColumnInfo>, expected: Record<string, string>): void {
  for (const [column, dataType] of Object.entries(expected)) {
    const info = columns.get(column);
    expect(info, `column ${column} exists`).toBeDefined();
    if (dataType) {
      expect(info?.data_type).toBe(dataType);
    }
  }
}

function expectNullable(columns: Map<string, ColumnInfo>, column: string): void {
  expect(columns.get(column)?.is_nullable).toBe('YES');
}

function expectNotNullable(columns: Map<string, ColumnInfo>, column: string): void {
  expect(columns.get(column)?.is_nullable).toBe('NO');
}

describe('SW-1.3.2 tenant core tables (real PostgreSQL)', () => {
  let pool: pg.Pool;
  let appliedDuringSetup: string[] = [];

  beforeAll(async () => {
    if (!(await isPortReachable(5432))) {
      if (REQUIRE_INTEGRATION) {
        expect.fail(
          'PostgreSQL integration test failed: service is not reachable on 127.0.0.1:5432 while INTEGRATION_TESTS is required',
        );
      }
      console.warn(
        'PostgreSQL service not reachable on 127.0.0.1:5432; skipping live org-tables tests',
      );
      return;
    }
    pool = new pg.Pool({ ...TEST_POOL_OPTIONS });
    // Fresh application: drop the tenant tables and ledger row, then re-run the migrations.
    await pool.query(
      'DROP TABLE IF EXISTS organizations, gateway_control, users, web_sessions, provider_keys, virtual_keys',
    );
    await pool.query(`DELETE FROM ${MIGRATION_LEDGER_TABLE} WHERE version = '0002'`);
    appliedDuringSetup = await runMigrations(pool);
  });

  afterAll(async () => {
    if (pool) await pool.end();
  });

  it('applies migration 0002-org-tables to the empty database and records it', async () => {
    if (!pool) return;
    expect(appliedDuringSetup).toEqual(['0002']);
    const { rows } = await pool.query<{ version: string; name: string }>(
      `SELECT version, name FROM ${MIGRATION_LEDGER_TABLE} WHERE version = '0002'`,
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]?.name).toBe('0002-org-tables');
  });

  it('grants gateway_migrator membership in gateway_owner (§12.1)', async () => {
    if (!pool) return;
    const { rows } = await pool.query<{ member: string }>(
      `SELECT am.member::regrole::text AS member
       FROM pg_auth_members am
       JOIN pg_roles m ON m.oid = am.roleid
       JOIN pg_roles mem ON mem.oid = am.member
       WHERE m.rolname = 'gateway_owner' AND mem.rolname = 'gateway_migrator'`,
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]?.member).toBe('gateway_migrator');
  });

  it('creates tenant tables owned by gateway_owner', async () => {
    if (!pool) return;
    const { rows } = await pool.query<{ relname: string; tableowner: string }>(
      `SELECT c.relname AS relname, r.rolname AS tableowner
       FROM pg_class c
       JOIN pg_roles r ON r.oid = c.relowner
       WHERE c.relname IN ('organizations', 'gateway_control', 'users', 'web_sessions',
                           'provider_keys', 'virtual_keys')`,
    );
    expect(rows).toHaveLength(6);
    for (const row of rows) {
      expect(row.tableowner).toBe('gateway_owner');
    }
  });

  it('enables and forces RLS on tenant tables and keeps gateway_control global', async () => {
    if (!pool) return;
    const { rows } = await pool.query<{ relname: string; rls: boolean; force: boolean }>(
      `SELECT relname, relrowsecurity AS rls, relforcerowsecurity AS force
       FROM pg_class
       WHERE relname IN ('organizations', 'users', 'web_sessions', 'provider_keys', 'virtual_keys',
                         'gateway_control')`,
    );
    const byName = new Map(rows.map((row) => [row.relname, row]));
    for (const table of TENANT_TABLES) {
      expect(byName.get(table)?.rls).toBe(true);
      expect(byName.get(table)?.force).toBe(true);
    }
    expect(byName.get('gateway_control')?.rls).toBe(false);
    expect(byName.get('gateway_control')?.force).toBe(false);
  });

  it('validates expected columns and defaults (§11)', async () => {
    if (!pool) return;
    expectColumns(await columnInfo(pool, 'organizations'), {
      id: 'uuid',
      name: 'text',
      monthly_budget_microdollars: 'bigint',
      kek_version: 'integer',
      wrapped_dek: 'bytea',
      dek_iv: 'bytea',
      dek_auth_tag: 'bytea',
      created_at: 'timestamp with time zone',
    });
    const organizations = await columnInfo(pool, 'organizations');
    for (const col of [
      'id',
      'name',
      'monthly_budget_microdollars',
      'kek_version',
      'wrapped_dek',
      'dek_iv',
      'dek_auth_tag',
      'created_at',
    ]) {
      expectNotNullable(organizations, col);
    }
    expect(organizations.get('created_at')?.column_default).toMatch(/clock_timestamp/);

    expectColumns(await columnInfo(pool, 'gateway_control'), {
      id: 'smallint',
      gateway_epoch: 'bigint',
      updated_at: 'timestamp with time zone',
    });

    expectColumns(await columnInfo(pool, 'users'), {
      id: 'uuid',
      org_id: 'uuid',
      email_normalized: 'text',
      password_hash: 'text',
      role: 'text',
      created_at: 'timestamp with time zone',
    });
    const users = await columnInfo(pool, 'users');
    for (const col of ['id', 'org_id', 'email_normalized', 'password_hash', 'role', 'created_at']) {
      expectNotNullable(users, col);
    }
    expect(users.get('created_at')?.column_default).toMatch(/clock_timestamp/);

    expectColumns(await columnInfo(pool, 'web_sessions'), {
      session_id_hash: 'bytea',
      user_id: 'uuid',
      org_id: 'uuid',
      csrf_token_hash: 'bytea',
      created_at: 'timestamp with time zone',
      last_seen_at: 'timestamp with time zone',
      idle_expires_at: 'timestamp with time zone',
      absolute_expires_at: 'timestamp with time zone',
      revoked_at: 'timestamp with time zone',
    });
    const webSessions = await columnInfo(pool, 'web_sessions');
    for (const col of [
      'session_id_hash',
      'user_id',
      'org_id',
      'csrf_token_hash',
      'created_at',
      'last_seen_at',
      'idle_expires_at',
      'absolute_expires_at',
    ]) {
      expectNotNullable(webSessions, col);
    }
    expectNullable(webSessions, 'revoked_at');

    expectColumns(await columnInfo(pool, 'provider_keys'), {
      id: 'uuid',
      org_id: 'uuid',
      provider: 'text',
      label: 'text',
      key_hint: 'text',
      ciphertext: 'bytea',
      iv: 'bytea',
      auth_tag: 'bytea',
      is_active: 'boolean',
      created_at: 'timestamp with time zone',
    });
    const providerKeys = await columnInfo(pool, 'provider_keys');
    for (const col of [
      'id',
      'org_id',
      'provider',
      'label',
      'key_hint',
      'ciphertext',
      'iv',
      'auth_tag',
      'is_active',
      'created_at',
    ]) {
      expectNotNullable(providerKeys, col);
    }

    expectColumns(await columnInfo(pool, 'virtual_keys'), {
      id: 'uuid',
      org_id: 'uuid',
      key_hash: 'bytea',
      name: 'text',
      key_prefix: 'text',
      allowed_models: 'ARRAY',
      rpm_limit: 'integer',
      tpm_limit: 'integer',
      concurrent_stream_limit: 'integer',
      exact_cache_enabled: 'boolean',
      semantic_cache_enabled: 'boolean',
      pii_redaction_enabled: 'boolean',
      store_payloads: 'boolean',
      revoked_at: 'timestamp with time zone',
      created_at: 'timestamp with time zone',
    });
    const virtualKeys = await columnInfo(pool, 'virtual_keys');
    expectNotNullable(virtualKeys, 'id');
    expectNotNullable(virtualKeys, 'org_id');
    expectNotNullable(virtualKeys, 'name');
    expectNotNullable(virtualKeys, 'key_prefix');
    expectNotNullable(virtualKeys, 'allowed_models');
    expectNotNullable(virtualKeys, 'exact_cache_enabled');
    expectNotNullable(virtualKeys, 'semantic_cache_enabled');
    expectNotNullable(virtualKeys, 'pii_redaction_enabled');
    expectNotNullable(virtualKeys, 'store_payloads');
    expectNotNullable(virtualKeys, 'created_at');
    expectNullable(virtualKeys, 'rpm_limit');
    expectNullable(virtualKeys, 'tpm_limit');
    expectNullable(virtualKeys, 'concurrent_stream_limit');
    expectNullable(virtualKeys, 'revoked_at');
  });

  it('validates schema defaults (§11)', async () => {
    if (!pool) return;
    const virtualKeys = await columnInfo(pool, 'virtual_keys');
    expect(virtualKeys.get('exact_cache_enabled')?.column_default).toMatch(/false/i);
    expect(virtualKeys.get('semantic_cache_enabled')?.column_default).toMatch(/false/i);
    expect(virtualKeys.get('pii_redaction_enabled')?.column_default).toMatch(/false/i);
    expect(virtualKeys.get('store_payloads')?.column_default).toMatch(/true/i);
    expect(virtualKeys.get('created_at')?.column_default).toMatch(/clock_timestamp/);
    const organizations = await columnInfo(pool, 'organizations');
    expect(organizations.get('monthly_budget_microdollars')?.column_default ?? '').toBe('');
    expect(organizations.get('created_at')?.column_default).toMatch(/clock_timestamp/);
  });

  it('enforces uniqueness constraints (§11)', async () => {
    if (!pool) return;
    const buffer = (text: string) => Buffer.from(text.repeat(4).slice(0, 16));
    await pool.query(
      `INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
       VALUES ($1, 'Org A', 1000000, 1, $2, $3, $4)`,
      [ORG_A, buffer('a'), buffer('b'), buffer('c')],
    );
    await pool.query(
      `INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
       VALUES ($1, 'Org B', 0, 1, $2, $3, $4)`,
      [ORG_B, buffer('d'), buffer('e'), buffer('f')],
    );

    // Organizations: PK and monthly budget bounds.
    await expect(
      pool.query(
        `INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
         VALUES ($1, 'dup', 0, 1, $2, $3, $4)`,
        [ORG_A, buffer('a'), buffer('b'), buffer('c')],
      ),
    ).rejects.toThrow();
    await expect(
      pool.query(
        `INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
         VALUES ($1, 'neg', -1, 1, $2, $3, $4)`,
        ['55555555-5555-4555-8555-555555555551', buffer('a'), buffer('b'), buffer('c')],
      ),
    ).rejects.toThrow();
    await expect(
      pool.query(
        `INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
         VALUES ($1, 'big', 1000000000000001, 1, $2, $3, $4)`,
        [BIG_ORG, buffer('a'), buffer('b'), buffer('c')],
      ),
    ).rejects.toThrow();

    // Users: PK, unique (id, org_id), email_normalized unique, org FK.
    await pool.query(
      `INSERT INTO users (id, org_id, email_normalized, password_hash, role) VALUES ($1, $2, $3, $4, 'member')`,
      [USER_A, ORG_A, 'a@example.com', 'hash-a'],
    );
    await expect(
      pool.query(
        `INSERT INTO users (id, org_id, email_normalized, password_hash, role) VALUES ($1, $2, $3, $4, 'member')`,
        [USER_A, ORG_A, 'a-dup@example.com', 'hash'],
      ),
    ).rejects.toThrow();
    await expect(
      pool.query(
        `INSERT INTO users (id, org_id, email_normalized, password_hash, role) VALUES ($1, $2, $3, $4, 'member')`,
        [USER_B, ORG_A, 'a@example.com', 'hash-b'],
      ),
    ).rejects.toThrow();
    await expect(
      pool.query(
        `INSERT INTO users (id, org_id, email_normalized, password_hash, role) VALUES ($1, $2, $3, $4, 'member')`,
        [USER_B, UNKNOWN_ORG, 'b@example.com', 'hash-b'],
      ),
    ).rejects.toThrow();

    // Web sessions: session_id_hash PK, composite FK (user_id, org_id) to users.
    await pool.query(
      `INSERT INTO web_sessions (session_id_hash, user_id, org_id, csrf_token_hash, last_seen_at, idle_expires_at, absolute_expires_at)
       VALUES ($1, $2, $3, $4, clock_timestamp(), clock_timestamp() + interval '1 hour', clock_timestamp() + interval '24 hours')`,
      [SESSION_A, USER_A, ORG_A, buffer('csrf-a')],
    );
    await expect(
      pool.query(
        `INSERT INTO web_sessions (session_id_hash, user_id, org_id, csrf_token_hash, last_seen_at, idle_expires_at, absolute_expires_at)
         VALUES ($1, $2, $3, $4, clock_timestamp(), clock_timestamp() + interval '1 hour', clock_timestamp() + interval '24 hours')`,
        [SESSION_A, USER_A, ORG_A, buffer('csrf-dup')],
      ),
    ).rejects.toThrow();
    await expect(
      pool.query(
        `INSERT INTO web_sessions (session_id_hash, user_id, org_id, csrf_token_hash, last_seen_at, idle_expires_at, absolute_expires_at)
         VALUES ($1, $2, $3, $4, clock_timestamp(), clock_timestamp() + interval '1 hour', clock_timestamp() + interval '24 hours')`,
        [SESSION_B, USER_A, ORG_B, buffer('csrf-b')],
      ),
    ).rejects.toThrow();

    // Provider keys: allowlisted provider, UNIQUE (id, org_id), FK to organizations.
    await pool.query(
      `INSERT INTO provider_keys (id, org_id, provider, label, key_hint, ciphertext, iv, auth_tag, is_active)
       VALUES ($1, $2, 'openai', 'My OpenAI key', '1234', $3, $4, $5, true)`,
      [PROVIDER_KEY_A, ORG_A, buffer('cipher-a'), buffer('iv-a'), buffer('tag-a')],
    );
    await expect(
      pool.query(
        `INSERT INTO provider_keys (id, org_id, provider, label, key_hint, ciphertext, iv, auth_tag, is_active)
         VALUES ($1, $2, 'mock', 'Bad provider', '1234', $3, $4, $5, true)`,
        [PROVIDER_KEY_B, ORG_A, buffer('cipher-b'), buffer('iv-b'), buffer('tag-b')],
      ),
    ).rejects.toThrow();
    await expect(
      pool.query(
        `INSERT INTO provider_keys (id, org_id, provider, label, key_hint, ciphertext, iv, auth_tag, is_active)
         VALUES ($1, $2, 'openai', 'Dup', '1234', $3, $4, $5, true)`,
        [PROVIDER_KEY_A, ORG_A, buffer('cipher-a'), buffer('iv-a'), buffer('tag-a')],
      ),
    ).rejects.toThrow();
    await expect(
      pool.query(
        `INSERT INTO provider_keys (id, org_id, provider, label, key_hint, ciphertext, iv, auth_tag, is_active)
         VALUES ($1, $2, 'openai', 'Bad org', '1234', $3, $4, $5, true)`,
        [PROVIDER_KEY_B, UNKNOWN_ORG, buffer('cipher-b'), buffer('iv-b'), buffer('tag-b')],
      ),
    ).rejects.toThrow();

    // Virtual keys: UNIQUE key_hash, UNIQUE (id, org_id), positive-value rate/concurrency checks,
    // FK to organizations.
    await pool.query(
      `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models)
       VALUES ($1, $2, 'vk-1', 'gw_live_', $3, $4)`,
      [VIRTUAL_KEY_A, ORG_A, buffer('hash-vk'), ['openai']],
    );
    await expect(
      pool.query(
        `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models)
         VALUES ($1, $2, 'vk-hashdup', 'gw_live_', $3, $4)`,
        [VIRTUAL_KEY_C, ORG_A, buffer('hash-vk'), ['openai']],
      ),
    ).rejects.toThrow();
    await expect(
      pool.query(
        `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models)
         VALUES ($1, $2, 'vk-dup', 'gw_live_', $3, $4)`,
        [VIRTUAL_KEY_A, ORG_A, buffer('hash-vk'), ['openai']],
      ),
    ).rejects.toThrow();
    await expect(
      pool.query(
        `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit)
         VALUES ($1, $2, 'vk-bad', 'gw_live_', $3, $4, 0)`,
        [VIRTUAL_KEY_B, ORG_A, buffer('hash-vk-b'), ['openai']],
      ),
    ).rejects.toThrow();
    await expect(
      pool.query(
        `INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models)
         VALUES ($1, $2, 'vk-bad', 'gw_live_', $3, $4)`,
        [VIRTUAL_KEY_B, UNKNOWN_ORG, buffer('hash-vk-b'), ['openai']],
      ),
    ).rejects.toThrow();

    // Gateway control: singleton row with CHECK (id = 1).
    await pool.query(
      'INSERT INTO gateway_control (id, gateway_epoch, updated_at) VALUES (1, 0, clock_timestamp())',
    );
    await expect(
      pool.query(
        'INSERT INTO gateway_control (id, gateway_epoch, updated_at) VALUES (2, 0, clock_timestamp())',
      ),
    ).rejects.toThrow();
  });

  it('is repeatable: a second runMigrations applies nothing new', async () => {
    if (!pool) return;
    expect(await runMigrations(pool)).toEqual([]);
  });
});
