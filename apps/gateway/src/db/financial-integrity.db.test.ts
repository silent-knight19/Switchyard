import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MIGRATION_LEDGER_TABLE, loadMigrationFiles, runMigrations } from './migrate.js';
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

const ORG_A = '11111111-1111-4111-8111-111111111111';
const ORG_B = '22222222-2222-4222-8222-222222222222';
const VIRTUAL_KEY_A_ID = '66666666-6666-4666-8666-666666666667';
const VIRTUAL_KEY_B_ID = '77777777-7777-4777-8777-777777777779';
const GATEWAY_INSTANCE_ID = '88888888-8888-4888-8888-888888888888';

async function expectSqlState(promise: Promise<unknown>, expectedState: string): Promise<void> {
  try {
    await promise;
    expect.unreachable(`Expected SQL query to fail with SQLSTATE ${expectedState}`);
  } catch (error: unknown) {
    const pgError = error as { code?: string; message?: string };
    expect(
      pgError.code,
      `Expected SQLSTATE ${expectedState} but got ${pgError.code}: ${pgError.message}`,
    ).toBe(expectedState);
  }
}

describe('SW-1.3.4 Financial Immutability, Append-Only Adjustments, and Monetary Bounds', () => {
  let cluster: DisposableCluster;
  const databases: DisposableDatabase[] = [];
  const passwords = createRolePasswords();

  let fresh: DisposableDatabase;
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

  async function connectAs(database: DisposableDatabase, role: LoginRole): Promise<pg.Client> {
    const client = new pg.Client({
      connectionString: roleConnectionString(database.url, role, passwords[role]),
    });
    await client.connect();
    return client;
  }

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    fresh = await createDatabase('financial-integrity-main');
    await migrate(fresh);

    pool = new pg.Pool({ connectionString: fresh.url, max: 10 });

    // Seed test organizations and virtual keys
    await pool.query(
      `INSERT INTO organizations
         (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
       VALUES
         ($1, 'Org A', 1000000000000, 1, $2, $3, $4),
         ($5, 'Org B', 1000000000000, 1, $2, $3, $4)`,
      [
        ORG_A,
        Buffer.from('mock_wrapped_dek_a'),
        Buffer.from('123456789012'),
        Buffer.from('1234567890123456'),
        ORG_B,
      ],
    );

    await pool.query(
      `INSERT INTO virtual_keys
         (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
       VALUES
         ($1, $2, 'key-a', 'sk-a-', $3, ARRAY['gpt-4o'], 60, 10000, 5),
         ($4, $5, 'key-b', 'sk-b-', $6, ARRAY['gpt-4o'], 60, 10000, 5)`,
      [
        VIRTUAL_KEY_A_ID,
        ORG_A,
        Buffer.from('hash_a'),
        VIRTUAL_KEY_B_ID,
        ORG_B,
        Buffer.from('hash_b'),
      ],
    );
  });

  afterAll(async () => {
    await pool?.end().catch(() => undefined);
    for (const db of databases) {
      await db.drop().catch(() => undefined);
    }
    await cluster?.stop().catch(() => undefined);
  });

  // =========================================================================
  // Section A: Catalog & Structural Verification
  // =========================================================================
  describe('A. PostgreSQL Catalog & Structural Verification', () => {
    it('verifies migration 0008 was applied and ledger records correct metadata', async () => {
      const { rows } = await pool.query<{ version: string; name: string; checksum: string }>(
        `SELECT version, name, checksum FROM ${MIGRATION_LEDGER_TABLE} WHERE version = '0008'`,
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]?.name).toBe('0008-financial-integrity');
      expect(rows[0]?.checksum).toHaveLength(64);
    });

    it('verifies all expected trigger functions exist in app_private owned by gateway_owner', async () => {
      const expectedFunctions = [
        'enforce_gateway_requests_immutability',
        'enforce_provider_attempts_immutability',
        'enforce_provider_cost_adjustments_immutability',
        'enforce_provider_cost_adjustments_truncate',
        'enforce_provider_cost_adjustments_insert',
      ];

      const { rows } = await pool.query<{ proname: string; nspname: string; rolname: string }>(
        `SELECT p.proname, n.nspname, r.rolname
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_roles r ON r.oid = p.proowner
         WHERE n.nspname = 'app_private' AND p.proname = ANY($1)`,
        [expectedFunctions],
      );

      expect(rows).toHaveLength(expectedFunctions.length);
      for (const row of rows) {
        expect(row.nspname).toBe('app_private');
        expect(row.rolname).toBe('gateway_owner');
      }
    });

    it('verifies trigger registrations on target tables', async () => {
      const { rows } = await pool.query<{
        relname: string;
        tgname: string;
      }>(
        `SELECT c.relname, t.tgname
         FROM pg_trigger t
         JOIN pg_class c ON c.oid = t.tgrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND t.tgname = ANY(ARRAY[
             'trg_gateway_requests_immutability',
             'trg_provider_attempts_immutability',
             'trg_provider_cost_adjustments_no_update_delete',
             'trg_provider_cost_adjustments_no_truncate',
             'trg_provider_cost_adjustments_insert'
           ])`,
      );

      const byTable = new Map<string, string[]>();
      for (const row of rows) {
        const list = byTable.get(row.relname) ?? [];
        list.push(row.tgname);
        byTable.set(row.relname, list);
      }

      expect(byTable.get('gateway_requests')).toContain('trg_gateway_requests_immutability');
      expect(byTable.get('provider_attempts')).toContain('trg_provider_attempts_immutability');
      expect(byTable.get('provider_cost_adjustments')).toContain(
        'trg_provider_cost_adjustments_no_update_delete',
      );
      expect(byTable.get('provider_cost_adjustments')).toContain(
        'trg_provider_cost_adjustments_no_truncate',
      );
      expect(byTable.get('provider_cost_adjustments')).toContain(
        'trg_provider_cost_adjustments_insert',
      );
    });

    it('verifies admission-time check constraint installed and universal monetary caps avoided (DB-22)', async () => {
      const { rows } = await pool.query<{
        conname: string;
        relname: string;
      }>(
        `SELECT c.conname, cl.relname
         FROM pg_constraint c
         JOIN pg_class cl ON cl.oid = c.conrelid
         WHERE c.conname = ANY(ARRAY[
           'chk_gateway_requests_billing_period',
           'chk_provider_attempts_monetary_bounds',
           'chk_provider_cost_adjustments_bounds'
         ])`,
      );

      const found = new Map(rows.map((r) => [r.conname, r.relname]));
      expect(found.get('chk_gateway_requests_billing_period')).toBe('gateway_requests');
      // DB-22: Universal 10^15 caps must NOT be applied to individual attempts or adjustments
      expect(found.has('chk_provider_attempts_monetary_bounds')).toBe(false);
      expect(found.has('chk_provider_cost_adjustments_bounds')).toBe(false);
    });

    it('verifies zero execute privileges granted to PUBLIC on trigger functions', async () => {
      const { rows } = await pool.query<{ proname: string; public_can_execute: boolean }>(
        `SELECT p.proname, has_function_privilege('public', p.oid, 'EXECUTE') AS public_can_execute
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'app_private'
           AND p.proname LIKE 'enforce_%'`,
      );

      expect(rows.length).toBeGreaterThan(0);
      for (const row of rows) {
        expect(row.public_can_execute, `PUBLIC must NOT have EXECUTE on ${row.proname}`).toBe(
          false,
        );
      }
    });

    it('verifies all tenant tables retain ENABLE and FORCE RLS with zero permissive policies', async () => {
      const tables = [
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

      const { rows: rlsRows } = await pool.query<{
        relname: string;
        rowsecurity: boolean;
        forcerowsecurity: boolean;
      }>(
        `SELECT c.relname, c.relrowsecurity AS rowsecurity, c.relforcerowsecurity AS forcerowsecurity
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relname = ANY($1)`,
        [tables],
      );

      expect(rlsRows).toHaveLength(tables.length);
      for (const row of rlsRows) {
        expect(row.rowsecurity, `${row.relname} must have rowsecurity`).toBe(true);
        expect(row.forcerowsecurity, `${row.relname} must have forcerowsecurity`).toBe(true);
      }

      const { rows: policyRows } = await pool.query<{ count: number }>(
        `SELECT count(*)::int AS count
         FROM pg_policy pol
         JOIN pg_class c ON c.oid = pol.polrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relname = ANY($1)`,
        [tables],
      );
      expect(policyRows[0]?.count).toBe(0);
    });
  });

  // =========================================================================
  // Section B: Request Billing-Period and Identity Immutability
  // =========================================================================
  describe('B. Gateway Requests Billing-Period and Identity Immutability', () => {
    it('allows valid request lifecycle: creation, summary updates, and terminal finalization', async () => {
      const reqId = 'a0000001-0000-4000-8000-000000000001';
      const admittedAt = '2026-11-15T10:00:00.000Z';

      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $5, $5::timestamptz + interval '30s')`,
        [reqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );

      // In-progress metadata update
      await pool.query(
        `UPDATE gateway_requests
         SET attempt_count = 1,
             ttft_ms = 120,
             total_latency_ms = 450
         WHERE request_id = $1`,
        [reqId],
      );

      // Finalize request to completed
      await pool.query(
        `UPDATE gateway_requests
         SET status = 'completed',
             final_provider = 'openai',
             final_model = 'gpt-4o',
             http_status = 200,
             finalized_at = clock_timestamp()
         WHERE request_id = $1`,
        [reqId],
      );

      const { rows } = await pool.query<{
        status: string;
        billing_period: string;
        attempt_count: number;
        http_status: number;
      }>(
        'SELECT status, billing_period, attempt_count, http_status FROM gateway_requests WHERE request_id = $1',
        [reqId],
      );
      expect(rows[0]?.status).toBe('completed');
      expect(rows[0]?.billing_period).toBe('2026-11');
      expect(rows[0]?.attempt_count).toBe(1);
      expect(rows[0]?.http_status).toBe(200);

      // Idempotent finalization retry with same values succeeds
      const retry = await pool.query(
        `UPDATE gateway_requests
         SET status = 'completed',
             http_status = 200
         WHERE request_id = $1`,
        [reqId],
      );
      expect(retry.rowCount).toBe(1);
    });

    it('rejects attempt to change billing_period on gateway_requests (23514)', async () => {
      const reqId = 'a0000001-0000-4000-8000-000000000002';
      const admittedAt = '2026-11-15T10:00:00.000Z';

      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $5, $5::timestamptz + interval '30s')`,
        [reqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );

      await expectSqlState(
        pool.query(
          `UPDATE gateway_requests
           SET billing_period = '2026-12'
           WHERE request_id = $1`,
          [reqId],
        ),
        '23514',
      );

      // Verify row unchanged
      const { rows } = await pool.query<{ billing_period: string }>(
        'SELECT billing_period FROM gateway_requests WHERE request_id = $1',
        [reqId],
      );
      expect(rows[0]?.billing_period).toBe('2026-11');
    });

    it('rejects insertion of gateway_requests where billing_period does not match admitted_at UTC month (23514)', async () => {
      const reqId = 'a0000001-0000-4000-8000-000000000003';
      const admittedAt = '2026-11-15T10:00:00.000Z'; // November UTC

      await expectSqlState(
        pool.query(
          `INSERT INTO gateway_requests
             (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
              billing_period, status, cache_status, admitted_at, deadline_at)
           VALUES
             ($1, $2, $3, $4, 1, 'gpt-4o', '2026-12', 'in_progress', 'miss', $5, $5::timestamptz + interval '30s')`,
          [reqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
        ),
        '23514',
      );
    });

    it('allows fixed December UTC admission with matching December billing period (DB-23)', async () => {
      const reqId = 'a0000001-0000-4000-8000-00000000000d';
      const admittedAt = '2026-12-15T10:00:00.000Z'; // December UTC

      const { rowCount } = await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-12', 'in_progress', 'miss', $5, $5::timestamptz + interval '30s')`,
        [reqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );
      expect(rowCount).toBe(1);

      const { rows } = await pool.query<{ billing_period: string }>(
        'SELECT billing_period FROM gateway_requests WHERE request_id = $1',
        [reqId],
      );
      expect(rows[0]?.billing_period).toBe('2026-12');
    });

    it('rejects insertion of gateway_requests where December UTC admission has November billing period (23514)', async () => {
      const reqId = 'a0000001-0000-4000-8000-00000000000e';
      const admittedAt = '2026-12-05T10:00:00.000Z'; // December UTC

      await expectSqlState(
        pool.query(
          `INSERT INTO gateway_requests
             (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
              billing_period, status, cache_status, admitted_at, deadline_at)
           VALUES
             ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $5, $5::timestamptz + interval '30s')`,
          [reqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
        ),
        '23514',
      );
    });

    it('enforces UTC billing period consistency across diverse session time zones (Asia/Kolkata, America/New_York) (DB-23, DB-25)', async () => {
      const client = await pool.connect();
      const { rows: initialTzRows } = await client.query<{ tz: string }>(
        "SELECT current_setting('TimeZone') AS tz",
      );
      const initialTimeZone = initialTzRows[0]?.tz;

      try {
        // 1. Session in Asia/Kolkata (+05:30) - session-scoped SET (DB-25)
        await client.query("SET TimeZone = 'Asia/Kolkata'");
        const { rows: kolkataTzRows } = await client.query<{ tz: string }>(
          "SELECT current_setting('TimeZone') AS tz",
        );
        expect(kolkataTzRows[0]?.tz).toBe('Asia/Kolkata');

        // 2026-11-30 23:30:00 UTC is 2026-12-01 05:00:00 in Kolkata (+05:30).
        // But its UTC month is strictly November ('2026-11').
        const reqKolkataOk = 'a0000001-0000-4000-8000-0000000000b1';
        const admittedNovUtc = '2026-11-30T23:30:00.000Z';

        const okResult = await client.query(
          `INSERT INTO gateway_requests
             (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
              billing_period, status, cache_status, admitted_at, deadline_at)
           VALUES
             ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $5, $5::timestamptz + interval '30s')`,
          [reqKolkataOk, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedNovUtc],
        );
        expect(okResult.rowCount).toBe(1);

        // Mismatched December period fails even though Kolkata local date is December 1
        const reqKolkataFail = 'a0000001-0000-4000-8000-0000000000b2';
        await expectSqlState(
          client.query(
            `INSERT INTO gateway_requests
               (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
                billing_period, status, cache_status, admitted_at, deadline_at)
             VALUES
               ($1, $2, $3, $4, 1, 'gpt-4o', '2026-12', 'in_progress', 'miss', $5, $5::timestamptz + interval '30s')`,
            [reqKolkataFail, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedNovUtc],
          ),
          '23514',
        );

        // Verify connection is healthy and not in an aborted transaction block (DB-25)
        const { rows: healthCheckKolkata } = await client.query<{ tz: string }>(
          "SELECT current_setting('TimeZone') AS tz",
        );
        expect(healthCheckKolkata[0]?.tz).toBe('Asia/Kolkata');

        // 2. Session in America/New_York (-05:00) - session-scoped SET (DB-25)
        await client.query("SET TimeZone = 'America/New_York'");
        const { rows: nyTzRows } = await client.query<{ tz: string }>(
          "SELECT current_setting('TimeZone') AS tz",
        );
        expect(nyTzRows[0]?.tz).toBe('America/New_York');

        // 2026-12-01 02:00:00 UTC is 2026-11-30 21:00:00 in New York (-05:00).
        // But its UTC month is strictly December ('2026-12').
        const reqNyOk = 'a0000001-0000-4000-8000-0000000000c1';
        const admittedDecUtc = '2026-12-01T02:00:00.000Z';

        const okNyResult = await client.query(
          `INSERT INTO gateway_requests
             (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
              billing_period, status, cache_status, admitted_at, deadline_at)
           VALUES
             ($1, $2, $3, $4, 1, 'gpt-4o', '2026-12', 'in_progress', 'miss', $5, $5::timestamptz + interval '30s')`,
          [reqNyOk, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedDecUtc],
        );
        expect(okNyResult.rowCount).toBe(1);

        // Mismatched November period fails even though New York local date is November 30
        const reqNyFail = 'a0000001-0000-4000-8000-0000000000c2';
        await expectSqlState(
          client.query(
            `INSERT INTO gateway_requests
               (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
                billing_period, status, cache_status, admitted_at, deadline_at)
             VALUES
               ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $5, $5::timestamptz + interval '30s')`,
            [reqNyFail, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedDecUtc],
          ),
          '23514',
        );

        // Verify connection is healthy and not in an aborted transaction block (DB-25)
        const { rows: healthCheckNy } = await client.query<{ tz: string }>(
          "SELECT current_setting('TimeZone') AS tz",
        );
        expect(healthCheckNy[0]?.tz).toBe('America/New_York');
      } finally {
        await client.query('RESET TimeZone').catch(() => undefined);
        if (initialTimeZone !== undefined) {
          const { rows: restoredTz } = await client.query<{ tz: string }>(
            "SELECT current_setting('TimeZone') AS tz",
          );
          expect(restoredTz[0]?.tz).toBe(initialTimeZone);
        }
        client.release();
      }
    });

    it('preserves November billing period for month-boundary request finalized in December', async () => {
      const reqId = 'a0000001-0000-4000-8000-000000000004';
      const admittedAt = '2026-11-30T23:59:59.999Z';
      const finalizedAt = '2026-12-01T00:00:15.000Z';

      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $5, $5::timestamptz + interval '60s')`,
        [reqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );

      await pool.query(
        `UPDATE gateway_requests
         SET status = 'completed',
             finalized_at = $2
         WHERE request_id = $1`,
        [reqId, finalizedAt],
      );

      const { rows } = await pool.query<{ billing_period: string; status: string }>(
        'SELECT billing_period, status FROM gateway_requests WHERE request_id = $1',
        [reqId],
      );
      expect(rows[0]?.billing_period).toBe('2026-11');
      expect(rows[0]?.status).toBe('completed');
    });

    it('rejects mutation of request identity and tenancy fields (23514)', async () => {
      const reqId = 'a0000001-0000-4000-8000-000000000005';
      const admittedAt = '2026-11-15T10:00:00.000Z';

      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $5, $5::timestamptz + interval '30s')`,
        [reqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );

      // Attempt to mutate org_id
      await expectSqlState(
        pool.query('UPDATE gateway_requests SET org_id = $2 WHERE request_id = $1', [reqId, ORG_B]),
        '23514',
      );

      // Attempt to mutate virtual_key_id
      await expectSqlState(
        pool.query('UPDATE gateway_requests SET virtual_key_id = $2 WHERE request_id = $1', [
          reqId,
          VIRTUAL_KEY_B_ID,
        ]),
        '23514',
      );

      // Attempt to mutate admitted_at
      await expectSqlState(
        pool.query(
          "UPDATE gateway_requests SET admitted_at = '2026-11-16T00:00:00.000Z' WHERE request_id = $1",
          [reqId],
        ),
        '23514',
      );

      // Attempt to mutate gateway_epoch
      await expectSqlState(
        pool.query('UPDATE gateway_requests SET gateway_epoch = 2 WHERE request_id = $1', [reqId]),
        '23514',
      );
    });

    it('rejects terminal status regression and status alteration on gateway_requests (23514)', async () => {
      const reqId = 'a0000001-0000-4000-8000-000000000006';
      const admittedAt = '2026-11-15T10:00:00.000Z';

      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'completed', 'exact_hit', $5, $5::timestamptz + interval '30s')`,
        [reqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );

      // Regression to in_progress
      await expectSqlState(
        pool.query("UPDATE gateway_requests SET status = 'in_progress' WHERE request_id = $1", [
          reqId,
        ]),
        '23514',
      );

      // Switching terminal status to interrupted
      await expectSqlState(
        pool.query("UPDATE gateway_requests SET status = 'interrupted' WHERE request_id = $1", [
          reqId,
        ]),
        '23514',
      );
    });

    it('allows cache-hit request with zero provider attempts to finalize cleanly', async () => {
      const reqId = 'a0000001-0000-4000-8000-000000000007';
      const admittedAt = '2026-11-15T10:00:00.000Z';

      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'exact_hit', $5, $5::timestamptz + interval '30s')`,
        [reqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );

      await pool.query(
        `UPDATE gateway_requests
         SET status = 'completed',
             attempt_count = 0,
             http_status = 200,
             total_latency_ms = 12,
             finalized_at = clock_timestamp()
         WHERE request_id = $1`,
        [reqId],
      );

      const { rows } = await pool.query<{ status: string; attempt_count: number }>(
        'SELECT status, attempt_count FROM gateway_requests WHERE request_id = $1',
        [reqId],
      );
      expect(rows[0]?.status).toBe('completed');
      expect(rows[0]?.attempt_count).toBe(0);
    });
  });

  // =========================================================================
  // Section C: Provider-Attempt Settlement and Immutability
  // =========================================================================
  describe('C. Provider Attempts Settlement and Immutability', () => {
    const parentReqId = 'b0000001-0000-4000-8000-000000000001';
    const admittedAt = '2026-11-15T10:00:00.000Z';

    beforeAll(async () => {
      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $5, $5::timestamptz + interval '120s')`,
        [parentReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );
    });

    it('allows valid initial settlement: reserved -> settled with confirmed actual cost', async () => {
      const attemptId = 'b0000002-0000-4000-8000-000000000001';

      await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
            cost_status, admitted_at, hard_deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, $5, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 5000,
            'estimated', $6, $6::timestamptz + interval '60s')`,
        [attemptId, parentReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );

      // Transition to settled
      await pool.query(
        `UPDATE provider_attempts
         SET status = 'settled',
             actual_cost_microdollars = 4200,
             cost_status = 'confirmed',
             outcome = 'completed',
             tokens_in = 100,
             tokens_out = 50,
             duration_ms = 500,
             http_status = 200,
             settled_at = clock_timestamp()
         WHERE attempt_id = $1`,
        [attemptId],
      );

      const { rows } = await pool.query<{
        status: string;
        actual: string;
        effective: string;
        cost_status: string;
      }>(
        `SELECT status, actual_cost_microdollars::text AS actual,
                effective_cost_microdollars::text AS effective, cost_status
         FROM provider_attempts WHERE attempt_id = $1`,
        [attemptId],
      );
      expect(rows[0]?.status).toBe('settled');
      expect(rows[0]?.actual).toBe('4200');
      expect(rows[0]?.effective).toBe('4200');
      expect(rows[0]?.cost_status).toBe('confirmed');

      // Idempotent replay of terminal update succeeds
      const replay = await pool.query(
        `UPDATE provider_attempts
         SET status = 'settled',
             actual_cost_microdollars = 4200,
             cost_status = 'confirmed'
         WHERE attempt_id = $1`,
        [attemptId],
      );
      expect(replay.rowCount).toBe(1);
    });

    it('allows valid initial settlement: reserved -> settled with estimated cost', async () => {
      const attemptId = 'b0000002-0000-4000-8000-000000000002';

      await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
            cost_status, admitted_at, hard_deadline_at)
         VALUES
           ($1, $2, $3, $4, 2, $5, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 5000,
            'estimated', $6, $6::timestamptz + interval '60s')`,
        [attemptId, parentReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );

      await pool.query(
        `UPDATE provider_attempts
         SET status = 'settled',
             actual_cost_microdollars = NULL,
             cost_status = 'estimated',
             outcome = 'pre_token_timeout',
             settled_at = clock_timestamp()
         WHERE attempt_id = $1`,
        [attemptId],
      );

      const { rows } = await pool.query<{
        status: string;
        actual: string | null;
        effective: string;
        cost_status: string;
      }>(
        `SELECT status, actual_cost_microdollars::text AS actual,
                effective_cost_microdollars::text AS effective, cost_status
         FROM provider_attempts WHERE attempt_id = $1`,
        [attemptId],
      );
      expect(rows[0]?.status).toBe('settled');
      expect(rows[0]?.actual).toBeNull();
      expect(rows[0]?.effective).toBe('5000');
      expect(rows[0]?.cost_status).toBe('estimated');
    });

    it('allows valid conservative settlement: reserved -> interrupted', async () => {
      const attemptId = 'b0000002-0000-4000-8000-000000000003';

      await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
            cost_status, admitted_at, hard_deadline_at)
         VALUES
           ($1, $2, $3, $4, 3, $5, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 6000,
            'estimated', $6, $6::timestamptz + interval '60s')`,
        [attemptId, parentReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );

      await pool.query(
        `UPDATE provider_attempts
         SET status = 'interrupted',
             outcome = 'interrupted',
             settled_at = clock_timestamp()
         WHERE attempt_id = $1`,
        [attemptId],
      );

      const { rows } = await pool.query<{
        status: string;
        effective: string;
        cost_status: string;
      }>(
        `SELECT status, effective_cost_microdollars::text AS effective, cost_status
         FROM provider_attempts WHERE attempt_id = $1`,
        [attemptId],
      );
      expect(rows[0]?.status).toBe('interrupted');
      expect(rows[0]?.effective).toBe('6000');
      expect(rows[0]?.cost_status).toBe('estimated');
    });

    it('allows confirmed zero cost settlement', async () => {
      const attemptId = 'b0000002-0000-4000-8000-000000000004';

      await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
            cost_status, admitted_at, hard_deadline_at)
         VALUES
           ($1, $2, $3, $4, 4, $5, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 5000,
            'estimated', $6, $6::timestamptz + interval '60s')`,
        [attemptId, parentReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );

      await pool.query(
        `UPDATE provider_attempts
         SET status = 'settled',
             actual_cost_microdollars = 0,
             cost_status = 'confirmed',
             outcome = 'client_aborted',
             settled_at = clock_timestamp()
         WHERE attempt_id = $1`,
        [attemptId],
      );

      const { rows } = await pool.query<{ effective: string; actual: string }>(
        `SELECT effective_cost_microdollars::text AS effective, actual_cost_microdollars::text AS actual
         FROM provider_attempts WHERE attempt_id = $1`,
        [attemptId],
      );
      expect(rows[0]?.effective).toBe('0');
      expect(rows[0]?.actual).toBe('0');
    });

    it('rejects attempt to mutate base cost fields of settled attempt (23514)', async () => {
      const attemptId = 'b0000002-0000-4000-8000-000000000001'; // Settled above with actual = 4200

      // Mutate actual_cost_microdollars
      await expectSqlState(
        pool.query(
          'UPDATE provider_attempts SET actual_cost_microdollars = 9999 WHERE attempt_id = $1',
          [attemptId],
        ),
        '23514',
      );

      // Mutate estimated_cost_microdollars
      await expectSqlState(
        pool.query(
          'UPDATE provider_attempts SET estimated_cost_microdollars = 9999 WHERE attempt_id = $1',
          [attemptId],
        ),
        '23514',
      );

      // Mutate cost_status
      await expectSqlState(
        pool.query("UPDATE provider_attempts SET cost_status = 'estimated' WHERE attempt_id = $1", [
          attemptId,
        ]),
        '23514',
      );

      // Verify row unchanged
      const { rows } = await pool.query<{ actual: string; cost_status: string }>(
        'SELECT actual_cost_microdollars::text AS actual, cost_status FROM provider_attempts WHERE attempt_id = $1',
        [attemptId],
      );
      expect(rows[0]?.actual).toBe('4200');
      expect(rows[0]?.cost_status).toBe('confirmed');
    });

    it('rejects terminal status regressions and terminal status changes (23514)', async () => {
      const settledId = 'b0000002-0000-4000-8000-000000000001';
      const interruptedId = 'b0000002-0000-4000-8000-000000000003';

      // Settle -> reserved regression
      await expectSqlState(
        pool.query("UPDATE provider_attempts SET status = 'reserved' WHERE attempt_id = $1", [
          settledId,
        ]),
        '23514',
      );

      // Interrupted -> reserved regression
      await expectSqlState(
        pool.query("UPDATE provider_attempts SET status = 'reserved' WHERE attempt_id = $1", [
          interruptedId,
        ]),
        '23514',
      );

      // Settled -> interrupted flip
      await expectSqlState(
        pool.query("UPDATE provider_attempts SET status = 'interrupted' WHERE attempt_id = $1", [
          settledId,
        ]),
        '23514',
      );

      // Interrupted -> settled flip
      await expectSqlState(
        pool.query("UPDATE provider_attempts SET status = 'settled' WHERE attempt_id = $1", [
          interruptedId,
        ]),
        '23514',
      );
    });

    it('rejects identity reattribution and billing period mutation on attempts (23514)', async () => {
      const attemptId = 'b0000002-0000-4000-8000-000000000001';

      // Billing period
      await expectSqlState(
        pool.query(
          "UPDATE provider_attempts SET billing_period = '2026-12' WHERE attempt_id = $1",
          [attemptId],
        ),
        '23514',
      );

      // Org ID
      await expectSqlState(
        pool.query('UPDATE provider_attempts SET org_id = $2 WHERE attempt_id = $1', [
          attemptId,
          ORG_B,
        ]),
        '23514',
      );

      // Request ID
      await expectSqlState(
        pool.query('UPDATE provider_attempts SET request_id = $2 WHERE attempt_id = $1', [
          attemptId,
          'b0000001-0000-4000-8000-999999999999',
        ]),
        '23514',
      );

      // Attempt number
      await expectSqlState(
        pool.query('UPDATE provider_attempts SET attempt_number = 99 WHERE attempt_id = $1', [
          attemptId,
        ]),
        '23514',
      );
    });

    it('rejects direct write to generated effective_cost_microdollars (428C9)', async () => {
      const attemptId = 'b0000002-0000-4000-8000-000000000001';
      await expectSqlState(
        pool.query(
          'UPDATE provider_attempts SET effective_cost_microdollars = 9999 WHERE attempt_id = $1',
          [attemptId],
        ),
        '428C9',
      );
    });
  });

  // =========================================================================
  // Section D: Append-Only Adjustments
  // =========================================================================
  describe('D. Append-Only Adjustments Immutability', () => {
    const parentReqId = 'c0000001-0000-4000-8000-000000000001';
    const settledAttemptId = 'c0000002-0000-4000-8000-000000000001';
    const reservedAttemptId = 'c0000002-0000-4000-8000-000000000002';
    const admittedAt = '2026-11-15T10:00:00.000Z';

    beforeAll(async () => {
      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'completed', 'miss', $5, $5::timestamptz + interval '120s')`,
        [parentReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );

      // Settled attempt
      await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
            actual_cost_microdollars, cost_status, admitted_at, hard_deadline_at, settled_at)
         VALUES
           ($1, $2, $3, $4, 1, $5, 1, '2026-11', 'openai', 'gpt-4o', 'settled', 5000,
            4500, 'confirmed', $6, $6::timestamptz + interval '60s', clock_timestamp())`,
        [settledAttemptId, parentReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );

      // Active reserved attempt
      await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
            cost_status, admitted_at, hard_deadline_at)
         VALUES
           ($1, $2, $3, $4, 2, $5, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 5000,
            'estimated', $6, $6::timestamptz + interval '60s')`,
        [reservedAttemptId, parentReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );
    });

    it('allows valid positive, negative, and zero delta adjustment inserts', async () => {
      const adj1 = 'c0000003-0000-4000-8000-000000000001';
      const adj2 = 'c0000003-0000-4000-8000-000000000002';
      const adj3 = 'c0000003-0000-4000-8000-000000000003';

      // Negative delta: 4500 -> 4000 (delta = -500)
      await pool.query(
        `INSERT INTO provider_cost_adjustments
           (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
            delta_microdollars, source, source_reference)
         VALUES
           ($1, $2, $3, 4500, 4000, -500, 'provider_usage', 'ref_01')`,
        [adj1, settledAttemptId, ORG_A],
      );

      // Positive delta: 4000 -> 4200 (delta = +200)
      await pool.query(
        `INSERT INTO provider_cost_adjustments
           (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
            delta_microdollars, source, source_reference)
         VALUES
           ($1, $2, $3, 4000, 4200, 200, 'provider_invoice', 'ref_02')`,
        [adj2, settledAttemptId, ORG_A],
      );

      // Zero delta: 4200 -> 4200 (delta = 0)
      await pool.query(
        `INSERT INTO provider_cost_adjustments
           (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
            delta_microdollars, source, source_reference)
         VALUES
           ($1, $2, $3, 4200, 4200, 0, 'manual_review', 'ref_03')`,
        [adj3, settledAttemptId, ORG_A],
      );

      const { rows } = await pool.query<{ count: number }>(
        'SELECT count(*)::int AS count FROM provider_cost_adjustments WHERE attempt_id = $1',
        [settledAttemptId],
      );
      expect(rows[0]?.count).toBe(3);
    });

    it('rejects inserting an adjustment targeting an active reserved attempt (23514)', async () => {
      const adjId = 'c0000003-0000-4000-8000-000000000004';
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_cost_adjustments
             (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
              delta_microdollars, source, source_reference)
           VALUES
             ($1, $2, $3, 5000, 4500, -500, 'provider_usage', 'ref_reserved')`,
          [adjId, reservedAttemptId, ORG_A],
        ),
        '23514',
      );
    });

    it('strictly prohibits UPDATE on provider_cost_adjustments (23514)', async () => {
      const adjId = 'c0000003-0000-4000-8000-000000000001';

      // Value-changing UPDATE
      await expectSqlState(
        pool.query(
          'UPDATE provider_cost_adjustments SET delta_microdollars = 9999 WHERE adjustment_id = $1',
          [adjId],
        ),
        '23514',
      );

      // No-op UPDATE (setting same value)
      await expectSqlState(
        pool.query(
          'UPDATE provider_cost_adjustments SET delta_microdollars = -500 WHERE adjustment_id = $1',
          [adjId],
        ),
        '23514',
      );

      // Verify row unchanged
      const { rows } = await pool.query<{ delta: string }>(
        'SELECT delta_microdollars::text AS delta FROM provider_cost_adjustments WHERE adjustment_id = $1',
        [adjId],
      );
      expect(rows[0]?.delta).toBe('-500');
    });

    it('strictly prohibits DELETE on provider_cost_adjustments (23514)', async () => {
      const adjId = 'c0000003-0000-4000-8000-000000000001';
      await expectSqlState(
        pool.query('DELETE FROM provider_cost_adjustments WHERE adjustment_id = $1', [adjId]),
        '23514',
      );
    });

    it('strictly prohibits TRUNCATE on provider_cost_adjustments (23514)', async () => {
      await expectSqlState(pool.query('TRUNCATE TABLE provider_cost_adjustments'), '23514');
    });

    it('rejects duplicate adjustment_id and duplicate source_reference replay (23505)', async () => {
      const adj1 = 'c0000003-0000-4000-8000-000000000001';
      const adjNew = 'c0000003-0000-4000-8000-000000000099';

      // Duplicate adjustment_id
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_cost_adjustments
             (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
              delta_microdollars, source, source_reference)
           VALUES
             ($1, $2, $3, 4500, 4000, -500, 'provider_usage', 'ref_dup_id')`,
          [adj1, settledAttemptId, ORG_A],
        ),
        '23505',
      );

      // Duplicate (attempt_id, source, source_reference)
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_cost_adjustments
             (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
              delta_microdollars, source, source_reference)
           VALUES
             ($1, $2, $3, 4500, 4000, -500, 'provider_usage', 'ref_01')`,
          [adjNew, settledAttemptId, ORG_A],
        ),
        '23505',
      );
    });
  });

  // =========================================================================
  // Section E: Monetary Bounds & Canonical Cost Arithmetic
  // =========================================================================
  describe('E. Monetary Bounds and Canonical Cost Arithmetic', () => {
    const parentReqId = 'd0000001-0000-4000-8000-000000000001';
    const attemptId = 'd0000002-0000-4000-8000-000000000001';
    const admittedAt = '2026-11-15T10:00:00.000Z';

    beforeAll(async () => {
      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'completed', 'miss', $5, $5::timestamptz + interval '120s')`,
        [parentReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );

      await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
            actual_cost_microdollars, cost_status, admitted_at, hard_deadline_at, settled_at)
         VALUES
           ($1, $2, $3, $4, 1, $5, 1, '2026-11', 'openai', 'gpt-4o', 'settled', 10000,
            10000, 'confirmed', $6, $6::timestamptz + interval '60s', clock_timestamp())`,
        [attemptId, parentReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );
    });

    it('allows reserved attempt with valid estimate inside Redis reservation domain (DB-22 positive)', async () => {
      const resAttempt = 'd0000002-0000-4000-8000-000000000002';
      const { rowCount } = await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
            cost_status, admitted_at, hard_deadline_at)
         VALUES
           ($1, $2, $3, $4, 2, $5, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 5000,
            'estimated', $6, $6::timestamptz + interval '60s')`,
        [resAttempt, parentReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );
      expect(rowCount).toBe(1);

      const { rows } = await pool.query<{ effective: string; status: string; cost_status: string }>(
        'SELECT effective_cost_microdollars::text AS effective, status, cost_status FROM provider_attempts WHERE attempt_id = $1',
        [resAttempt],
      );
      expect(rows[0]?.effective).toBe('5000');
      expect(rows[0]?.status).toBe('reserved');
      expect(rows[0]?.cost_status).toBe('estimated');
    });

    it('allows terminal confirmed attempt with actual cost of 10^15 + 1 (DB-22 positive: authoritative financial fact)', async () => {
      const overAttempt = 'd0000002-0000-4000-8000-000000000003';
      const actualAbove10_15 = '1000000000000001'; // 10^15 + 1 microdollars

      const { rowCount } = await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
            actual_cost_microdollars, cost_status, admitted_at, hard_deadline_at, settled_at)
         VALUES
           ($1, $2, $3, $4, 3, $5, 1, '2026-11', 'openai', 'gpt-4o', 'settled', 10000,
            $6, 'confirmed', $7, $7::timestamptz + interval '60s', clock_timestamp())`,
        [
          overAttempt,
          parentReqId,
          ORG_A,
          VIRTUAL_KEY_A_ID,
          GATEWAY_INSTANCE_ID,
          actualAbove10_15,
          admittedAt,
        ],
      );
      expect(rowCount).toBe(1);

      const { rows } = await pool.query<{ actual: string; effective: string }>(
        `SELECT actual_cost_microdollars::text AS actual,
                effective_cost_microdollars::text AS effective
         FROM provider_attempts WHERE attempt_id = $1`,
        [overAttempt],
      );
      expect(rows[0]?.actual).toBe(actualAbove10_15);
      expect(rows[0]?.effective).toBe(actualAbove10_15);
    });

    it('allows adjustments changing canonical cost from below to above 10^15, and reducing it again (DB-22 positive)', async () => {
      const scaleAttempt = 'd0000002-0000-4000-8000-000000000004';
      const baseCost = '900000000000000'; // 9 * 10^14 (< 10^15)

      await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
            actual_cost_microdollars, cost_status, admitted_at, hard_deadline_at, settled_at)
         VALUES
           ($1, $2, $3, $4, 4, $5, 1, '2026-11', 'openai', 'gpt-4o', 'settled', 5000,
            $6, 'confirmed', $7, $7::timestamptz + interval '60s', clock_timestamp())`,
        [
          scaleAttempt,
          parentReqId,
          ORG_A,
          VIRTUAL_KEY_A_ID,
          GATEWAY_INSTANCE_ID,
          baseCost,
          admittedAt,
        ],
      );

      // Adjustment 1: raises canonical cost from 9*10^14 to 1.1*10^15 (> 10^15) with delta +2*10^14
      const adjAbove = 'd0000003-0000-4000-8000-0000000000a1';
      await pool.query(
        `INSERT INTO provider_cost_adjustments
           (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
            delta_microdollars, source, source_reference)
         VALUES
           ($1, $2, $3, 900000000000000, 1100000000000000, 200000000000000, 'provider_invoice', 'ref_up')`,
        [adjAbove, scaleAttempt, ORG_A],
      );

      const { rows: r1 } = await pool.query<{ canonical: string }>(
        `SELECT (pa.effective_cost_microdollars + COALESCE(SUM(pca.delta_microdollars), 0))::bigint::text AS canonical
         FROM provider_attempts pa
         LEFT JOIN provider_cost_adjustments pca ON pca.attempt_id = pa.attempt_id AND pca.org_id = pa.org_id
         WHERE pa.attempt_id = $1
         GROUP BY pa.attempt_id, pa.effective_cost_microdollars`,
        [scaleAttempt],
      );
      expect(r1[0]?.canonical).toBe('1100000000000000');

      // Adjustment 2: reduces canonical cost from 1.1*10^15 to 9.5*10^14 (< 10^15) with delta -1.5*10^14
      const adjReduce = 'd0000003-0000-4000-8000-0000000000a2';
      await pool.query(
        `INSERT INTO provider_cost_adjustments
           (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
            delta_microdollars, source, source_reference)
         VALUES
           ($1, $2, $3, 1100000000000000, 950000000000000, -150000000000000, 'provider_invoice', 'ref_down')`,
        [adjReduce, scaleAttempt, ORG_A],
      );

      const { rows: r2 } = await pool.query<{ canonical: string }>(
        `SELECT (pa.effective_cost_microdollars + COALESCE(SUM(pca.delta_microdollars), 0))::bigint::text AS canonical
         FROM provider_attempts pa
         LEFT JOIN provider_cost_adjustments pca ON pca.attempt_id = pa.attempt_id AND pca.org_id = pa.org_id
         WHERE pa.attempt_id = $1
         GROUP BY pa.attempt_id, pa.effective_cost_microdollars`,
        [scaleAttempt],
      );
      expect(r2[0]?.canonical).toBe('950000000000000');
    });

    it('allows valid confirmed zero cost (DB-22 positive)', async () => {
      const zeroAttempt = 'd0000002-0000-4000-8000-000000000005';
      const { rowCount } = await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
            actual_cost_microdollars, cost_status, admitted_at, hard_deadline_at, settled_at)
         VALUES
           ($1, $2, $3, $4, 5, $5, 1, '2026-11', 'openai', 'gpt-4o', 'settled', 1000,
            0, 'confirmed', $6, $6::timestamptz + interval '60s', clock_timestamp())`,
        [zeroAttempt, parentReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
      );
      expect(rowCount).toBe(1);

      const { rows } = await pool.query<{ actual: string; effective: string }>(
        `SELECT actual_cost_microdollars::text AS actual,
                effective_cost_microdollars::text AS effective
         FROM provider_attempts WHERE attempt_id = $1`,
        [zeroAttempt],
      );
      expect(rows[0]?.actual).toBe('0');
      expect(rows[0]?.effective).toBe('0');
    });

    it('rejects negative estimated cost and negative actual cost on provider_attempts (23514) (DB-22 negative)', async () => {
      const badAttempt = 'd0000002-0000-4000-8000-000000000006';

      // Negative estimated cost
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              cost_status, admitted_at, hard_deadline_at)
           VALUES
             ($1, $2, $3, $4, 6, $5, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', -100,
              'estimated', $6, $6::timestamptz + interval '60s')`,
          [badAttempt, parentReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
        ),
        '23514',
      );

      // Negative actual cost
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              actual_cost_microdollars, cost_status, admitted_at, hard_deadline_at)
           VALUES
             ($1, $2, $3, $4, 6, $5, 1, '2026-11', 'openai', 'gpt-4o', 'settled', 1000,
              -50, 'confirmed', $6, $6::timestamptz + interval '60s')`,
          [badAttempt, parentReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
        ),
        '23514',
      );
    });

    it('rejects negative previous/corrected cost and inconsistent deltas in adjustments (23514) (DB-22 negative)', async () => {
      const badAdj = 'd0000003-0000-4000-8000-0000000000b1';

      // Negative previous cost
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_cost_adjustments
             (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
              delta_microdollars, source, source_reference)
           VALUES
             ($1, $2, $3, -100, 1000, 1100, 'provider_invoice', 'ref_neg_prev')`,
          [badAdj, attemptId, ORG_A],
        ),
        '23514',
      );

      // Negative corrected cost
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_cost_adjustments
             (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
              delta_microdollars, source, source_reference)
           VALUES
             ($1, $2, $3, 1000, -50, -1050, 'provider_invoice', 'ref_neg_corr')`,
          [badAdj, attemptId, ORG_A],
        ),
        '23514',
      );

      // Inconsistent delta: delta = 500 but corrected - previous = 12000 - 10000 = 2000
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_cost_adjustments
             (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
              delta_microdollars, source, source_reference)
           VALUES
             ($1, $2, $3, 10000, 12000, 500, 'provider_invoice', 'ref_bad_delta')`,
          [badAdj, attemptId, ORG_A],
        ),
        '23514',
      );
    });

    it('rejects BIGINT values beyond PostgreSQL representable range (22003) (DB-22 negative)', async () => {
      const outOfRangeAttempt = 'd0000002-0000-4000-8000-000000000007';
      // 9223372036854775808 is 2^63, which exceeds PostgreSQL BIGINT max (9223372036854775807)
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              cost_status, admitted_at, hard_deadline_at)
           VALUES
             ($1, $2, $3, $4, 7, $5, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 9223372036854775808,
              'estimated', $6, $6::timestamptz + interval '60s')`,
          [
            outOfRangeAttempt,
            parentReqId,
            ORG_A,
            VIRTUAL_KEY_A_ID,
            GATEWAY_INSTANCE_ID,
            admittedAt,
          ],
        ),
        '22003',
      );
    });

    it('rejects unsupported fractional monetary representation (22P02) (DB-22 negative)', async () => {
      const fracAttempt = 'd0000002-0000-4000-8000-000000000008';
      // Passing floating-point/fractional string to BIGINT fails with 22P02 invalid_text_representation
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              cost_status, admitted_at, hard_deadline_at)
           VALUES
             ($1, $2, $3, $4, 8, $5, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', $6::bigint,
              'estimated', $7, $7::timestamptz + interval '60s')`,
          [
            fracAttempt,
            parentReqId,
            ORG_A,
            VIRTUAL_KEY_A_ID,
            GATEWAY_INSTANCE_ID,
            '1000.50',
            admittedAt,
          ],
        ),
        '22P02',
      );
    });

    it('computes exact canonical cost arithmetic without adjustments and with multiple adjustments', async () => {
      // 1. Without adjustments: canonical cost equals effective cost (10,000)
      const { rows: noAdj } = await pool.query<{ canonical: string }>(
        `SELECT (pa.effective_cost_microdollars + COALESCE(SUM(pca.delta_microdollars), 0))::bigint::text AS canonical
         FROM provider_attempts pa
         LEFT JOIN provider_cost_adjustments pca ON pca.attempt_id = pa.attempt_id AND pca.org_id = pa.org_id
         WHERE pa.attempt_id = $1
         GROUP BY pa.attempt_id, pa.effective_cost_microdollars`,
        [attemptId],
      );
      expect(noAdj[0]?.canonical).toBe('10000');

      // 2. Add adjustment 1: +1,500
      await pool.query(
        `INSERT INTO provider_cost_adjustments
           (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
            delta_microdollars, source, source_reference)
         VALUES
           ($1, $2, $3, 10000, 11500, 1500, 'provider_invoice', 'adj_canon_1')`,
        ['d0000003-0000-4000-8000-000000000003', attemptId, ORG_A],
      );

      // 3. Add adjustment 2: -2,000
      await pool.query(
        `INSERT INTO provider_cost_adjustments
           (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
            delta_microdollars, source, source_reference)
         VALUES
           ($1, $2, $3, 11500, 9500, -2000, 'provider_usage', 'adj_canon_2')`,
        ['d0000003-0000-4000-8000-000000000004', attemptId, ORG_A],
      );

      // Total canonical cost: 10,000 + 1,500 - 2,000 = 9,500
      const { rows: withAdj } = await pool.query<{ canonical: string }>(
        `SELECT (pa.effective_cost_microdollars + COALESCE(SUM(pca.delta_microdollars), 0))::bigint::text AS canonical
         FROM provider_attempts pa
         LEFT JOIN provider_cost_adjustments pca ON pca.attempt_id = pa.attempt_id AND pca.org_id = pa.org_id
         WHERE pa.attempt_id = $1
         GROUP BY pa.attempt_id, pa.effective_cost_microdollars`,
        [attemptId],
      );
      expect(withAdj[0]?.canonical).toBe('9500');
    });
  });

  // =========================================================================
  // Section F: Migration Concurrency, Rollback, and Upgrade Safety (DB-24)
  // =========================================================================
  describe('F. Migration Concurrency, Rollback, and Upgrade Safety (DB-24)', () => {
    it('serializes concurrent migration runners via PostgreSQL advisory locking (DB-24 migration concurrency)', async () => {
      const concDb = await createDatabase('mig-concurrency');
      const migrator1 = new pg.Pool({
        connectionString: roleConnectionString(
          concDb.url,
          'gateway_migrator',
          passwords.gateway_migrator,
        ),
      });
      const migrator2 = new pg.Pool({
        connectionString: roleConnectionString(
          concDb.url,
          'gateway_migrator',
          passwords.gateway_migrator,
        ),
      });

      try {
        const [res1, res2] = await Promise.all([
          runMigrations(migrator1),
          runMigrations(migrator2),
        ]);

        const allApplied = [...res1, ...res2];
        const versions = loadMigrationFiles().map((f) => f.version);
        expect(allApplied).toHaveLength(versions.length);
        expect(new Set(allApplied).size).toBe(versions.length);
      } finally {
        await Promise.all([migrator1.end(), migrator2.end()]);
      }
    });

    it('rolls back completely if a migration statement fails without leaving partial artifacts', async () => {
      const rollbackDb = await createDatabase('mig-rollback');
      const tempDir = path.join(process.cwd(), 'temp-rollback-test-' + Date.now());
      fs.mkdirSync(tempDir, { recursive: true });

      try {
        const files = loadMigrationFiles();
        for (const file of files) {
          fs.writeFileSync(path.join(tempDir, `${file.name}.sql`), file.sql, 'utf8');
        }

        // Add failing migration 0009
        fs.writeFileSync(
          path.join(tempDir, '0009-failing-migration.sql'),
          'SET ROLE gateway_owner; CREATE TABLE broken_table (id int); SYNTAX_ERROR_CRASH;',
          'utf8',
        );

        const migrator = new pg.Pool({
          connectionString: roleConnectionString(
            rollbackDb.url,
            'gateway_migrator',
            passwords.gateway_migrator,
          ),
        });
        try {
          await expect(runMigrations(migrator, { migrationsDir: tempDir })).rejects.toThrow();
        } finally {
          await migrator.end();
        }

        // Verify broken_table does not exist
        const verifier = new pg.Client({ connectionString: rollbackDb.url });
        await verifier.connect();
        try {
          const { rows } = await verifier.query<{ exists: boolean }>(
            "SELECT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'broken_table') AS exists",
          );
          expect(rows[0]?.exists).toBe(false);

          const { rows: ledger } = await verifier.query<{ version: string }>(
            `SELECT version FROM ${MIGRATION_LEDGER_TABLE} WHERE version = '0009'`,
          );
          expect(ledger).toHaveLength(0);
        } finally {
          await verifier.end();
        }
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('upgrades a database from 0007 to 0008 preserving existing valid financial rows (including costs > 10^15) (DB-22 upgrade regression)', async () => {
      const upgradeDb = await createDatabase('upgrade-0007-to-0008');
      const tempDir = path.join(process.cwd(), 'temp-upgrade-test-' + Date.now());
      fs.mkdirSync(tempDir, { recursive: true });

      try {
        const files = loadMigrationFiles();
        // Copy 0001 through 0007 only
        for (const file of files.filter((f) => f.version <= '0007')) {
          fs.writeFileSync(path.join(tempDir, `${file.name}.sql`), file.sql, 'utf8');
        }

        // Apply 0001-0007
        const migrator = new pg.Pool({
          connectionString: roleConnectionString(
            upgradeDb.url,
            'gateway_migrator',
            passwords.gateway_migrator,
          ),
        });
        try {
          const applied = await runMigrations(migrator, { migrationsDir: tempDir });
          expect(applied).toEqual(['0001', '0002', '0003', '0004', '0005', '0006', '0007']);
        } finally {
          await migrator.end();
        }

        // Seed valid financial records under 0007 schema
        const seeder = new pg.Client({ connectionString: upgradeDb.url });
        await seeder.connect();
        const upReqId = 'e0000001-0000-4000-8000-000000000001';
        const upAttemptSettled = 'e0000002-0000-4000-8000-000000000001';
        const upAttemptReserved = 'e0000002-0000-4000-8000-000000000002';
        const upAttemptOver10_15 = 'e0000002-0000-4000-8000-000000000003';
        const upAdj = 'e0000003-0000-4000-8000-000000000001';
        const actualOver10_15 = '1000000000000001'; // 10^15 + 1
        const admittedAt = '2026-11-20T12:00:00.000Z';

        try {
          await seeder.query(
            `INSERT INTO organizations
               (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
             VALUES
               ($1, 'Upgrade Org', 5000000, 1, $2, $3, $4)`,
            [ORG_A, Buffer.from('dek'), Buffer.from('iv'), Buffer.from('tag')],
          );

          await seeder.query(
            `INSERT INTO virtual_keys
               (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
             VALUES
               ($1, $2, 'key-a', 'sk-a-', $3, ARRAY['gpt-4o'], 60, 10000, 5)`,
            [VIRTUAL_KEY_A_ID, ORG_A, Buffer.from('hash_a')],
          );

          await seeder.query(
            `INSERT INTO gateway_requests
               (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
                billing_period, status, cache_status, admitted_at, deadline_at)
             VALUES
               ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $5, $5::timestamptz + interval '60s')`,
            [upReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
          );

          await seeder.query(
            `INSERT INTO provider_attempts
               (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
                gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
                actual_cost_microdollars, cost_status, admitted_at, hard_deadline_at, settled_at)
             VALUES
               ($1, $2, $3, $4, 1, $5, 1, '2026-11', 'openai', 'gpt-4o', 'settled', 5000,
                4200, 'confirmed', $6, $6::timestamptz + interval '60s', clock_timestamp())`,
            [upAttemptSettled, upReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
          );

          await seeder.query(
            `INSERT INTO provider_attempts
               (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
                gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
                cost_status, admitted_at, hard_deadline_at)
             VALUES
               ($1, $2, $3, $4, 2, $5, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 5000,
                'estimated', $6, $6::timestamptz + interval '60s')`,
            [upAttemptReserved, upReqId, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, admittedAt],
          );

          // Seed a terminal attempt with actual cost > 10^15 under 0007 schema
          await seeder.query(
            `INSERT INTO provider_attempts
               (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
                gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
                actual_cost_microdollars, cost_status, admitted_at, hard_deadline_at, settled_at)
             VALUES
               ($1, $2, $3, $4, 3, $5, 1, '2026-11', 'openai', 'gpt-4o', 'settled', 10000,
                $6, 'confirmed', $7, $7::timestamptz + interval '60s', clock_timestamp())`,
            [
              upAttemptOver10_15,
              upReqId,
              ORG_A,
              VIRTUAL_KEY_A_ID,
              GATEWAY_INSTANCE_ID,
              actualOver10_15,
              admittedAt,
            ],
          );

          await seeder.query(
            `INSERT INTO provider_cost_adjustments
               (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
                delta_microdollars, source, source_reference)
             VALUES
               ($1, $2, $3, 4200, 3900, -300, 'provider_usage', 'up_ref_01')`,
            [upAdj, upAttemptSettled, ORG_A],
          );
        } finally {
          await seeder.end();
        }

        // Apply remaining migrations using authoritative migration directory (applies 0008)
        const migrator2 = new pg.Pool({
          connectionString: roleConnectionString(
            upgradeDb.url,
            'gateway_migrator',
            passwords.gateway_migrator,
          ),
        });
        try {
          const secondRun = await runMigrations(migrator2);
          expect(secondRun).toEqual(['0008']);
        } finally {
          await migrator2.end();
        }

        // Verify seeded data remains intact and queryable
        const verifier = new pg.Client({ connectionString: upgradeDb.url });
        await verifier.connect();
        try {
          const { rows: attRows } = await verifier.query<{ effective: string; status: string }>(
            'SELECT effective_cost_microdollars::text AS effective, status FROM provider_attempts WHERE attempt_id = $1',
            [upAttemptSettled],
          );
          expect(attRows[0]?.effective).toBe('4200');
          expect(attRows[0]?.status).toBe('settled');

          // Verify attempt with actual cost > 10^15 is completely intact and matches canonical cost
          const { rows: overRows } = await verifier.query<{ actual: string; effective: string }>(
            `SELECT actual_cost_microdollars::text AS actual,
                    effective_cost_microdollars::text AS effective
             FROM provider_attempts WHERE attempt_id = $1`,
            [upAttemptOver10_15],
          );
          expect(overRows[0]?.actual).toBe(actualOver10_15);
          expect(overRows[0]?.effective).toBe(actualOver10_15);

          // Verify that 0008 immutability triggers now protect the pre-existing settled row
          await expectSqlState(
            verifier.query(
              'UPDATE provider_attempts SET actual_cost_microdollars = 9999 WHERE attempt_id = $1',
              [upAttemptSettled],
            ),
            '23514',
          );

          // Verify that 0008 immutability triggers protect the row with cost > 10^15
          await expectSqlState(
            verifier.query(
              'UPDATE provider_attempts SET actual_cost_microdollars = 9999 WHERE attempt_id = $1',
              [upAttemptOver10_15],
            ),
            '23514',
          );

          // Verify pre-existing adjustment row is now protected from UPDATE
          await expectSqlState(
            verifier.query(
              'UPDATE provider_cost_adjustments SET delta_microdollars = 100 WHERE adjustment_id = $1',
              [upAdj],
            ),
            '23514',
          );
        } finally {
          await verifier.end();
        }
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });

  // =========================================================================
  // Section G: PostgreSQL Role Least Privilege under Authenticated Sessions
  // =========================================================================
  describe('G. Role Least Privilege under Authenticated Sessions', () => {
    it('verifies gateway_app cannot execute DML on financial tables (42501)', async () => {
      const appClient = await connectAs(fresh, 'gateway_app');
      try {
        await expectSqlState(appClient.query('SELECT * FROM gateway_requests LIMIT 1'), '42501');
        await expectSqlState(appClient.query('SELECT * FROM provider_attempts LIMIT 1'), '42501');
        await expectSqlState(
          appClient.query('SELECT * FROM provider_cost_adjustments LIMIT 1'),
          '42501',
        );
        await expectSqlState(appClient.query('SELECT * FROM trace_payloads LIMIT 1'), '42501');

        await expectSqlState(
          appClient.query("DELETE FROM provider_attempts WHERE status = 'settled'"),
          '42501',
        );
      } finally {
        await appClient.end();
      }
    });

    it('verifies gateway_worker cannot execute DML on financial tables (42501)', async () => {
      const workerClient = await connectAs(fresh, 'gateway_worker');
      try {
        await expectSqlState(workerClient.query('SELECT * FROM gateway_requests LIMIT 1'), '42501');
        await expectSqlState(
          workerClient.query('SELECT * FROM provider_attempts LIMIT 1'),
          '42501',
        );
        await expectSqlState(
          workerClient.query('SELECT * FROM provider_cost_adjustments LIMIT 1'),
          '42501',
        );
        await expectSqlState(workerClient.query('SELECT * FROM trace_payloads LIMIT 1'), '42501');
      } finally {
        await workerClient.end();
      }
    });

    it('verifies gateway_startup cannot execute DML on financial tables (42501)', async () => {
      const startupClient = await connectAs(fresh, 'gateway_startup');
      try {
        await expectSqlState(
          startupClient.query('SELECT * FROM gateway_requests LIMIT 1'),
          '42501',
        );
        await expectSqlState(
          startupClient.query('SELECT * FROM provider_attempts LIMIT 1'),
          '42501',
        );
      } finally {
        await startupClient.end();
      }
    });

    it('verifies runtime roles cannot SET ROLE gateway_owner (42501)', async () => {
      const appClient = await connectAs(fresh, 'gateway_app');
      try {
        await expectSqlState(appClient.query('SET ROLE gateway_owner'), '42501');
      } finally {
        await appClient.end();
      }
    });
  });
});
