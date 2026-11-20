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

const ROLE_NAMES = [
  'gateway_owner',
  'gateway_migrator',
  'gateway_startup',
  'gateway_app',
  'gateway_worker',
  'gateway_auth_executor',
  'gateway_ops_executor',
] as const;

const EXECUTOR_NAMES = new Set(['gateway_auth_executor', 'gateway_ops_executor']);

function createSwitchyardPool(): pg.Pool {
  return new pg.Pool({ ...TEST_POOL_OPTIONS });
}

describe('SW-1.3.1 migration process and role security (real PostgreSQL)', () => {
  let pool: pg.Pool;

  beforeAll(async () => {
    if (!(await isPortReachable(5432))) {
      if (REQUIRE_INTEGRATION) {
        expect.fail(
          'PostgreSQL integration test failed: service is not reachable on 127.0.0.1:5432 while INTEGRATION_TESTS is required',
        );
      }
      console.warn(
        'PostgreSQL service not reachable on 127.0.0.1:5432; skipping live migration and role tests',
      );
      return;
    }
    pool = createSwitchyardPool();
    const applied = await runMigrations(pool);
    if (applied.length > 0) {
      console.log(`migrations applied during test setup: ${applied.join(', ')}`);
    }
  });

  afterAll(async () => {
    if (pool) await pool.end();
  });

  it('records migration 0001-roles in the versioned ledger', async () => {
    if (!pool) return;
    const { rows } = await pool.query<{ version: string; name: string }>(
      `SELECT version, name FROM ${MIGRATION_LEDGER_TABLE} WHERE version = '0001'`,
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]?.name).toBe('0001-roles');
  });

  it('is repeatable: a second runMigrations applies nothing new', async () => {
    if (!pool) return;
    expect(await runMigrations(pool)).toEqual([]);
  });

  it('creates the distinct least-privilege roles', async () => {
    if (!pool) return;
    const { rows } = await pool.query<{
      rolname: string;
      rolsuper: boolean;
      rolbypassrls: boolean;
      rolcreatedb: boolean;
      rolcreaterole: boolean;
    }>(
      `SELECT rolname, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole
       FROM pg_roles
       WHERE rolname IN ('gateway_owner', 'gateway_migrator', 'gateway_startup', 'gateway_app',
                         'gateway_worker', 'gateway_auth_executor', 'gateway_ops_executor')
       ORDER BY rolname`,
    );
    const byName = new Map(rows.map((row) => [row.rolname, row]));
    for (const rolname of ROLE_NAMES) {
      const role = byName.get(rolname);
      expect(role, `role ${rolname} should exist`).toBeDefined();
      expect(role?.rolsuper).toBe(false);
      // Executor roles are BYPASSRLS by design (Architecture v1.2 §12.1); all other roles are not.
      expect(role?.rolbypassrls).toBe(EXECUTOR_NAMES.has(rolname));
      expect(role?.rolcreatedb).toBe(false);
      expect(role?.rolcreaterole).toBe(false);
    }
  });

  it('creates the NOLOGIN executor roles', async () => {
    if (!pool) return;
    const { rows } = await pool.query<{ rolname: string; rolcanlogin: boolean }>(
      `SELECT rolname, rolcanlogin FROM pg_roles
       WHERE rolname IN ('gateway_auth_executor', 'gateway_ops_executor')`,
    );
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row.rolcanlogin).toBe(false);
    }
  });

  it('grants no runtime-role membership into executors and no table ownership to runtime roles', async () => {
    if (!pool) return;
    const { rows: memberships } = await pool.query<{ member: string }>(
      `SELECT am.member::regrole::text AS member
       FROM pg_auth_members am
       WHERE am.roleid IN ('gateway_auth_executor'::regrole, 'gateway_ops_executor'::regrole)
         AND am.member IN ('gateway_owner'::regrole, 'gateway_migrator'::regrole, 'gateway_startup'::regrole,
                           'gateway_app'::regrole, 'gateway_worker'::regrole)`,
    );
    expect(memberships).toHaveLength(0);

    const { rows: owned } = await pool.query<{ relname: string; tableowner: string }>(
      `SELECT c.relname AS relname, r.rolname AS tableowner
       FROM pg_class c
       JOIN pg_roles r ON r.oid = c.relowner
       WHERE c.relkind = 'r'
         AND r.rolname IN ('gateway_owner', 'gateway_migrator', 'gateway_startup', 'gateway_app',
                           'gateway_worker', 'gateway_auth_executor', 'gateway_ops_executor')`,
    );
    expect(owned).toHaveLength(0);
  });

  it('runtime roles cannot DDL tables', async () => {
    if (!pool) return;
    const client = await pool.connect();
    try {
      for (const roleName of ROLE_NAMES) {
        await client.query(`SET ROLE ${roleName}`);
        const { rows } = await client.query<{ current_user: string }>('SELECT current_user');
        expect(rows[0]?.current_user).toBe(roleName);
        await expect(client.query(`CREATE TABLE ${roleName}_ddl_probe (id INT)`)).rejects.toThrow();
        await client.query('RESET ROLE');
      }
    } finally {
      client.release();
    }
  });
});
