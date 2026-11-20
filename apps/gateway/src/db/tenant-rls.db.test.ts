import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { runMigrations } from './migrate.js';
import { withTenant, getActiveTenantContext, TenantTransactionError } from './tenant.js';
import {
  bootstrapDatabase,
  createDisposableDatabase,
  createRolePasswords,
  roleConnectionString,
  startDisposableCluster,
  type DisposableCluster,
  type DisposableDatabase,
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

describe('SW-1.4.1 Transaction-Scoped Tenant Context & SW-1.4.2 PostgreSQL RLS Policies', () => {
  let cluster: DisposableCluster;
  const databases: DisposableDatabase[] = [];
  const passwords = createRolePasswords();
  let database: DisposableDatabase;
  let poolApp: pg.Pool;
  let poolWorker: pg.Pool;

  const ORG_A = 'a0000001-0000-4000-8000-000000000001';
  const ORG_B = 'b0000002-0000-4000-8000-000000000002';
  const USER_A = 'a1000001-0000-4000-8000-000000000001';
  const USER_B = 'b1000002-0000-4000-8000-000000000002';
  const PK_A = '10000001-0000-4000-8000-000000000001';
  const PK_B = '10000002-0000-4000-8000-000000000002';
  const VK_A = '20000001-0000-4000-8000-000000000001';
  const VK_B = '20000002-0000-4000-8000-000000000002';
  const REQ_A = '30000001-0000-4000-8000-000000000001';
  const REQ_B = '30000002-0000-4000-8000-000000000002';
  const ATT_A = '40000001-0000-4000-8000-000000000001';
  const ATT_B = '40000002-0000-4000-8000-000000000002';
  const ATT_A_SETTLED = '40000003-0000-4000-8000-000000000001';
  const ATT_B_SETTLED = '40000004-0000-4000-8000-000000000002';
  const ADJ_A = '50000001-0000-4000-8000-000000000001';
  const ADJ_B = '50000002-0000-4000-8000-000000000002';
  const SESSION_A = Buffer.from('session-secret-hash-tenant-a-1111');
  const SESSION_B = Buffer.from('session-secret-hash-tenant-b-2222');
  const CSRF_A = Buffer.from('csrf-token-hash-tenant-a-1111111');
  const CSRF_B = Buffer.from('csrf-token-hash-tenant-b-2222222');
  const GW_INSTANCE = '90000001-0000-4000-8000-000000000001';

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    database = await createDisposableDatabase(cluster, 'tenant_rls');
    databases.push(database);
    await bootstrapDatabase(database, passwords);

    // Run forward migrations (0001 through 0009) as gateway_migrator
    const migrator = new pg.Pool({
      connectionString: roleConnectionString(
        database.url,
        'gateway_migrator',
        passwords.gateway_migrator,
      ),
    });
    try {
      const applied = await runMigrations(migrator);
      expect(applied.length).toBeGreaterThanOrEqual(9);
      expect(applied).toContain('0009');
    } finally {
      await migrator.end();
    }

    // Seed test fixtures using superuser seeder (bypasses RLS to initialize multi-tenant fixtures)
    const seeder = new pg.Client({ connectionString: database.url });
    await seeder.connect();
    try {
      // Initialize gateway_control singleton
      await seeder.query(
        'INSERT INTO gateway_control (id, gateway_epoch, updated_at) VALUES (1, 1, clock_timestamp())',
      );

      // Seed organizations A and B
      await seeder.query(`
        INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
        VALUES
          ('${ORG_A}', 'Acme Tenant A', 10000000, 1, '\\x01020304', '\\x05060708', '\\x090a0b0c'),
          ('${ORG_B}', 'Beta Tenant B', 20000000, 1, '\\x11121314', '\\x15161718', '\\x191a1b1c')
      `);

      // Seed users
      await seeder.query(`
        INSERT INTO users (id, org_id, email_normalized, password_hash, role)
        VALUES
          ('${USER_A}', '${ORG_A}', 'alice@acme.example', 'hash-a', 'admin'),
          ('${USER_B}', '${ORG_B}', 'bob@beta.example', 'hash-b', 'member')
      `);

      // Seed web sessions
      await seeder.query(
        `
        INSERT INTO web_sessions (session_id_hash, user_id, org_id, csrf_token_hash, last_seen_at, idle_expires_at, absolute_expires_at)
        VALUES
          ($1, '${USER_A}', '${ORG_A}', $2, clock_timestamp(), clock_timestamp() + interval '1 hour', clock_timestamp() + interval '24 hours'),
          ($3, '${USER_B}', '${ORG_B}', $4, clock_timestamp(), clock_timestamp() + interval '1 hour', clock_timestamp() + interval '24 hours')
      `,
        [SESSION_A, CSRF_A, SESSION_B, CSRF_B],
      );

      // Seed provider keys
      await seeder.query(`
        INSERT INTO provider_keys (id, org_id, provider, label, key_hint, ciphertext, iv, auth_tag, is_active)
        VALUES
          ('${PK_A}', '${ORG_A}', 'openai', 'Acme Key A', 'sk-a1', '\\xaa01', '\\xaa02', '\\xaa03', true),
          ('${PK_B}', '${ORG_B}', 'openai', 'Beta Key B', 'sk-b1', '\\xbb01', '\\xbb02', '\\xbb03', true)
      `);

      // Seed virtual keys
      await seeder.query(`
        INSERT INTO virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
        VALUES
          ('${VK_A}', '${ORG_A}', 'Acme VK A', 'gw_live_a', '\\xcc01', ARRAY['gpt-4o'], 100, 10000, 5),
          ('${VK_B}', '${ORG_B}', 'Beta VK B', 'gw_live_b', '\\xdd01', ARRAY['gpt-4o'], 200, 20000, 10)
      `);

      // Seed gateway requests
      await seeder.query(`
        INSERT INTO gateway_requests (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model, billing_period, status, cache_status, admitted_at, deadline_at)
        VALUES
          ('${REQ_A}', '${ORG_A}', '${VK_A}', '${GW_INSTANCE}', 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', '2026-11-15T12:00:00.000Z', '2026-11-15T12:01:00.000Z'),
          ('${REQ_B}', '${ORG_B}', '${VK_B}', '${GW_INSTANCE}', 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', '2026-11-15T12:00:00.000Z', '2026-11-15T12:01:00.000Z')
      `);

      // Seed provider attempts
      await seeder.query(`
        INSERT INTO provider_attempts (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id, gateway_epoch, billing_period, provider, model, status, cost_status, estimated_cost_microdollars, actual_cost_microdollars, outcome, admitted_at, hard_deadline_at, settled_at)
        VALUES
          ('${ATT_A}', '${REQ_A}', '${ORG_A}', '${VK_A}', 1, '${GW_INSTANCE}', 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 'estimated', 5000, NULL, NULL, '2026-11-15T12:00:00.000Z', '2026-11-15T12:01:00.000Z', NULL),
          ('${ATT_B}', '${REQ_B}', '${ORG_B}', '${VK_B}', 1, '${GW_INSTANCE}', 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 'estimated', 6000, NULL, NULL, '2026-11-15T12:00:00.000Z', '2026-11-15T12:01:00.000Z', NULL),
          ('${ATT_A_SETTLED}', '${REQ_A}', '${ORG_A}', '${VK_A}', 2, '${GW_INSTANCE}', 1, '2026-11', 'openai', 'gpt-4o', 'settled', 'confirmed', 5000, 4500, 'completed', '2026-11-15T12:00:00.000Z', '2026-11-15T12:01:00.000Z', clock_timestamp()),
          ('${ATT_B_SETTLED}', '${REQ_B}', '${ORG_B}', '${VK_B}', 2, '${GW_INSTANCE}', 1, '2026-11', 'openai', 'gpt-4o', 'settled', 'confirmed', 6000, 4500, 'completed', '2026-11-15T12:00:00.000Z', '2026-11-15T12:01:00.000Z', clock_timestamp())
      `);

      // Seed cost adjustments
      await seeder.query(`
        INSERT INTO provider_cost_adjustments (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars, delta_microdollars, source, source_reference)
        VALUES
          ('${ADJ_A}', '${ATT_A_SETTLED}', '${ORG_A}', 4500, 4000, -500, 'provider_invoice', 'inv-a-1'),
          ('${ADJ_B}', '${ATT_B_SETTLED}', '${ORG_B}', 4500, 5000, 500, 'provider_invoice', 'inv-b-1')
      `);

      // Seed trace payloads
      await seeder.query(`
        INSERT INTO trace_payloads (request_id, org_id, request_body, response_text, expires_at)
        VALUES
          ('${REQ_A}', '${ORG_A}', '{"prompt": "Hello Org A"}', 'Response Org A', clock_timestamp() + interval '7 days'),
          ('${REQ_B}', '${ORG_B}', '{"prompt": "Hello Org B"}', 'Response Org B', clock_timestamp() + interval '7 days')
      `);
    } finally {
      await seeder.end();
    }

    // Create pooled connections for gateway_app and gateway_worker
    poolApp = new pg.Pool({
      connectionString: roleConnectionString(database.url, 'gateway_app', passwords.gateway_app),
      max: 5,
    });
    poolWorker = new pg.Pool({
      connectionString: roleConnectionString(
        database.url,
        'gateway_worker',
        passwords.gateway_worker,
      ),
      max: 5,
    });
  });

  afterAll(async () => {
    await poolApp?.end().catch(() => undefined);
    await poolWorker?.end().catch(() => undefined);
    for (const db of databases) await db.drop().catch(() => undefined);
    await cluster?.stop();
  });

  // =========================================================================
  // Gate A1 — SW-1.4.1 Transaction-Scoped Tenant Context Helper
  // =========================================================================
  describe('Gate A1: SW-1.4.1 withTenant() helper interface and lifecycle', () => {
    it('executes callback with transaction-local tenant context and commits on success', async () => {
      const result = await withTenant(poolApp, ORG_A, async (client) => {
        const { rows } = await client.query<{ current_org: string }>(
          "SELECT current_setting('app.current_org_id', true) AS current_org",
        );
        expect(rows[0]?.current_org).toBe(ORG_A);

        const active = getActiveTenantContext();
        expect(active?.orgId).toBe(ORG_A);
        expect(active?.client).toBe(client);

        const { rows: users } = await client.query('SELECT id, email_normalized FROM users');
        expect(users).toHaveLength(1);
        expect(users[0]?.id).toBe(USER_A);

        return 'org-a-success';
      });

      expect(result).toBe('org-a-success');
    });

    it('rolls back transaction on callback failure and propagates the original error', async () => {
      const probeUserId = 'a1000009-0000-4000-8000-000000000001';
      const customError = new Error('simulated-business-logic-failure');

      await expect(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query(
            `INSERT INTO users (id, org_id, email_normalized, password_hash, role)
             VALUES ($1, $2, 'rollback-probe@example.com', 'h', 'member')`,
            [probeUserId, ORG_A],
          );
          throw customError;
        }),
      ).rejects.toThrow('simulated-business-logic-failure');

      // Verify row was rolled back and is not present in database
      await withTenant(poolApp, ORG_A, async (client) => {
        const { rows } = await client.query('SELECT id FROM users WHERE id = $1', [probeUserId]);
        expect(rows).toHaveLength(0);
      });
    });

    it('rejects nested withTenant calls to prevent pool deadlocks and transaction misuse', async () => {
      await withTenant(poolApp, ORG_A, async () => {
        await expect(
          withTenant(poolApp, ORG_A, async () => {
            return 'nested';
          }),
        ).rejects.toThrow(TenantTransactionError);
      });
    });

    it('forbids callback from calling release() directly on the client', async () => {
      await withTenant(poolApp, ORG_A, async (client) => {
        expect(() => client.release()).toThrow(TenantTransactionError);
      });
    });

    it('re-uses constrained pool (max: 1) without leaking tenant context across tenants', async () => {
      const singleConnPool = new pg.Pool({
        connectionString: roleConnectionString(database.url, 'gateway_app', passwords.gateway_app),
        max: 1,
      });

      try {
        // Run 1: Org A
        await withTenant(singleConnPool, ORG_A, async (client) => {
          const { rows } = await client.query<{ count: number }>(
            'SELECT count(*)::int AS count FROM users',
          );
          expect(rows[0]?.count).toBe(1);
        });

        // Run 2: Same pooled connection reused for Org B
        await withTenant(singleConnPool, ORG_B, async (client) => {
          const { rows: currentGuc } = await client.query<{ current_org: string }>(
            "SELECT current_setting('app.current_org_id', true) AS current_org",
          );
          expect(currentGuc[0]?.current_org).toBe(ORG_B);

          const { rows: users } = await client.query<{ id: string }>('SELECT id FROM users');
          expect(users).toHaveLength(1);
          expect(users[0]?.id).toBe(USER_B);
        });

        // Run 3: Same pooled connection reused outside withTenant (no context)
        const noContextClient = await singleConnPool.connect();
        try {
          const { rows: gucOutside } = await noContextClient.query<{ current_org: string }>(
            "SELECT current_setting('app.current_org_id', true) AS current_org",
          );
          expect(gucOutside[0]?.current_org).toBe('');

          const { rows: usersOutside } = await noContextClient.query('SELECT * FROM users');
          expect(usersOutside).toHaveLength(0);
        } finally {
          noContextClient.release();
        }

        // Run 4: Repeat reuse after an injected rollback
        await expect(
          withTenant(singleConnPool, ORG_A, async () => {
            throw new Error('injected error on max=1 pool');
          }),
        ).rejects.toThrow('injected error on max=1 pool');

        // Next checkout must succeed cleanly with zero leakage
        await withTenant(singleConnPool, ORG_B, async (client) => {
          const { rows } = await client.query<{ current_org: string }>(
            "SELECT current_setting('app.current_org_id', true) AS current_org",
          );
          expect(rows[0]?.current_org).toBe(ORG_B);
        });
      } finally {
        await singleConnPool.end();
      }
    });

    it('executes concurrent withTenant calls across Org A and Org B in complete isolation', async () => {
      const concurrency = 10;
      const tasks = Array.from({ length: concurrency }, (_, i) => {
        const orgId = i % 2 === 0 ? ORG_A : ORG_B;
        const expectedUserId = i % 2 === 0 ? USER_A : USER_B;

        return withTenant(poolApp, orgId, async (client) => {
          const { rows: gucRows } = await client.query<{ current_org: string }>(
            "SELECT current_setting('app.current_org_id', true) AS current_org",
          );
          expect(gucRows[0]?.current_org).toBe(orgId);

          const { rows: users } = await client.query<{ id: string }>('SELECT id FROM users');
          expect(users).toHaveLength(1);
          expect(users[0]?.id).toBe(expectedUserId);
          return orgId;
        });
      });

      const results = await Promise.all(tasks);
      expect(results).toHaveLength(concurrency);
    });
  });

  // =========================================================================
  // Gate A2 — SW-1.4.2 PostgreSQL Catalog & Policy Structure
  // =========================================================================
  describe('Gate A2: SW-1.4.2 RLS catalog verification and DB-04 policy composition guard', () => {
    const TENANT_TABLES = [
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

    it('enforces relrowsecurity and relforcerowsecurity on all nine tenant tables', async () => {
      const { rows } = await poolApp.query<{
        relname: string;
        rowsecurity: boolean;
        forcerowsecurity: boolean;
        owner: string;
      }>(
        `SELECT c.relname, c.relrowsecurity AS rowsecurity, c.relforcerowsecurity AS forcerowsecurity,
                pg_get_userbyid(c.relowner) AS owner
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relname = ANY($1::text[])`,
        [TENANT_TABLES],
      );

      expect(rows).toHaveLength(9);
      for (const row of rows) {
        expect(row.rowsecurity, `${row.relname} rowsecurity`).toBe(true);
        expect(row.forcerowsecurity, `${row.relname} forcerowsecurity`).toBe(true);
        expect(row.owner, `${row.relname} owner`).toBe('gateway_owner');
      }
    });

    it('confirms gateway_control has NO row security', async () => {
      const { rows } = await poolApp.query<{
        rowsecurity: boolean;
        forcerowsecurity: boolean;
      }>(
        `SELECT c.relrowsecurity AS rowsecurity, c.relforcerowsecurity AS forcerowsecurity
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relname = 'gateway_control'`,
      );

      expect(rows[0]?.rowsecurity).toBe(false);
      expect(rows[0]?.forcerowsecurity).toBe(false);
    });

    it('DB-04 guard: verifies exactly one unified permissive policy per table with USING and WITH CHECK', async () => {
      const { rows: policies } = await poolApp.query<{
        tablename: string;
        policyname: string;
        cmd: string;
        permissive: string;
        qual: string;
        with_check: string;
      }>(
        `SELECT tablename, policyname, cmd, permissive, qual, with_check
         FROM pg_policies
         WHERE schemaname = 'public' AND tablename = ANY($1::text[])
         ORDER BY tablename`,
        [TENANT_TABLES],
      );

      // Exactly 9 policies total (1 policy per table)
      expect(policies).toHaveLength(9);

      for (const pol of policies) {
        expect(pol.policyname).toBe(`${pol.tablename}_tenant_isolation`);
        expect(pol.cmd).toBe('ALL'); // FOR ALL
        expect(pol.permissive).toBe('PERMISSIVE');

        const expectedCol = pol.tablename === 'organizations' ? 'id' : 'org_id';
        expect(pol.qual).toContain(expectedCol);
        expect(pol.qual).toContain('app.current_org_id');
        expect(pol.with_check).toContain(expectedCol);
        expect(pol.with_check).toContain('app.current_org_id');
      }
    });
  });

  // =========================================================================
  // Gate A2 — Cross-Tenant Isolation Matrix (gateway_app)
  // =========================================================================
  describe('Gate A2: Cross-tenant operation matrix for gateway_app', () => {
    it('isolates organizations: Org A sees Org A, cannot see or mutate Org B', async () => {
      // 1. Org A context
      await withTenant(poolApp, ORG_A, async (client) => {
        const { rows } = await client.query<{ id: string }>('SELECT id FROM organizations');
        expect(rows).toHaveLength(1);
        expect(rows[0]?.id).toBe(ORG_A);

        // Update Org A row succeeds
        const updateA = await client.query(
          "UPDATE organizations SET name = 'Acme Corp Updated' WHERE id = $1",
          [ORG_A],
        );
        expect(updateA.rowCount).toBe(1);

        // Update Org B row targets invisible row -> affects 0 rows
        const updateB = await client.query(
          "UPDATE organizations SET name = 'Hacked Beta' WHERE id = $1",
          [ORG_B],
        );
        expect(updateB.rowCount).toBe(0);
      });

      // Attempting to insert an organization with Org B id fails WITH CHECK (42501)
      await withTenant(poolApp, ORG_A, async (client) => {
        await expectSqlState(
          client.query(`
            INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
            VALUES ('${ORG_B}', 'Fake B', 100, 1, '\\x01', '\\x02', '\\x03')
          `),
          '42501',
        );
      });

      // 2. No context -> zero rows
      const { rows: noContextRows } = await poolApp.query('SELECT * FROM organizations');
      expect(noContextRows).toHaveLength(0);
    });

    it('isolates users: SELECT, INSERT, UPDATE, DELETE strictly scoped to active org', async () => {
      const newUserId = 'a100000a-0000-4000-8000-000000000001';

      // 1. Permitted lifecycle for Org A user and cross-tenant mutation targeting invisible Org B user
      await withTenant(poolApp, ORG_A, async (client) => {
        // Read: Only User A visible
        const { rows: readRows } = await client.query<{ id: string }>('SELECT id FROM users');
        expect(readRows).toHaveLength(1);
        expect(readRows[0]?.id).toBe(USER_A);

        // Insert: Allowed for Org A
        await client.query(`
          INSERT INTO users (id, org_id, email_normalized, password_hash, role)
          VALUES ('${newUserId}', '${ORG_A}', 'new_a@acme.example', 'pass', 'member')
        `);

        // Update Org B user affects 0 rows
        const updateB = await client.query(
          `UPDATE users SET role = 'admin' WHERE id = '${USER_B}'`,
        );
        expect(updateB.rowCount).toBe(0);

        // Delete Org B user affects 0 rows
        const deleteB = await client.query(`DELETE FROM users WHERE id = '${USER_B}'`);
        expect(deleteB.rowCount).toBe(0);

        // Delete Org A user succeeds
        const deleteA = await client.query(`DELETE FROM users WHERE id = '${newUserId}'`);
        expect(deleteA.rowCount).toBe(1);
      });

      // 2. Insert with Org B org_id fails WITH CHECK (42501)
      await withTenant(poolApp, ORG_A, async (client) => {
        await expectSqlState(
          client.query(`
            INSERT INTO users (id, org_id, email_normalized, password_hash, role)
            VALUES ('b100000b-0000-4000-8000-000000000001', '${ORG_B}', 'new_b@beta.example', 'pass', 'member')
          `),
          '42501',
        );
      });

      // 3. Mutation attack: Attempt to move user to Org B fails WITH CHECK (42501)
      await withTenant(poolApp, ORG_A, async (client) => {
        await expectSqlState(
          client.query(`UPDATE users SET org_id = '${ORG_B}' WHERE id = '${USER_A}'`),
          '42501',
        );
      });
    });

    it('isolates virtual_keys even when queries lack tenant WHERE clauses', async () => {
      await withTenant(poolApp, ORG_A, async (client) => {
        // Unscoped query: SELECT * FROM virtual_keys
        const { rows } = await client.query<{ id: string }>('SELECT * FROM virtual_keys');
        expect(rows).toHaveLength(1);
        expect(rows[0]?.id).toBe(VK_A);
      });

      await withTenant(poolApp, ORG_B, async (client) => {
        const { rows } = await client.query<{ id: string }>('SELECT * FROM virtual_keys');
        expect(rows).toHaveLength(1);
        expect(rows[0]?.id).toBe(VK_B);
      });
    });

    it('isolates provider_keys, web_sessions, and trace_payloads across tenants', async () => {
      await withTenant(poolApp, ORG_A, async (client) => {
        const { rows: pks } = await client.query('SELECT * FROM provider_keys');
        expect(pks).toHaveLength(1);
        expect(pks[0]?.id).toBe(PK_A);

        const { rows: sessions } = await client.query('SELECT * FROM web_sessions');
        expect(sessions).toHaveLength(1);
        expect(sessions[0]?.user_id).toBe(USER_A);

        const { rows: traces } = await client.query('SELECT * FROM trace_payloads');
        expect(traces).toHaveLength(1);
        expect(traces[0]?.request_id).toBe(REQ_A);
      });

      await withTenant(poolApp, ORG_B, async (client) => {
        const { rows: pks } = await client.query('SELECT * FROM provider_keys');
        expect(pks).toHaveLength(1);
        expect(pks[0]?.id).toBe(PK_B);

        const { rows: sessions } = await client.query('SELECT * FROM web_sessions');
        expect(sessions).toHaveLength(1);
        expect(sessions[0]?.user_id).toBe(USER_B);

        const { rows: traces } = await client.query('SELECT * FROM trace_payloads');
        expect(traces).toHaveLength(1);
        expect(traces[0]?.request_id).toBe(REQ_B);
      });
    });

    it('enforces financial least privilege: DELETE on requests and attempts is denied', async () => {
      await withTenant(poolApp, ORG_A, async (client) => {
        await expectSqlState(client.query('DELETE FROM gateway_requests'), '42501');
      });
      await withTenant(poolApp, ORG_A, async (client) => {
        await expectSqlState(client.query('DELETE FROM provider_attempts'), '42501');
      });
      await withTenant(poolApp, ORG_A, async (client) => {
        await expectSqlState(client.query('DELETE FROM provider_cost_adjustments'), '42501');
      });
      await withTenant(poolApp, ORG_A, async (client) => {
        await expectSqlState(
          client.query('UPDATE provider_cost_adjustments SET delta_microdollars = 0'),
          '42501',
        );
      });
    });
  });

  // =========================================================================
  // Gate A2 — Sensitive Column Restrictions on gateway_worker
  // =========================================================================
  describe('Gate A2: Sensitive data protection on gateway_worker', () => {
    it('allows worker to read non-secret organization metadata under tenant context', async () => {
      await withTenant(poolWorker, ORG_A, async (client) => {
        const { rows } = await client.query<{ id: string; name: string }>(
          'SELECT id, name, monthly_budget_microdollars, kek_version, created_at FROM organizations',
        );
        expect(rows).toHaveLength(1);
        expect(rows[0]?.id).toBe(ORG_A);
      });
    });

    it('strictly denies worker from reading wrapped DEK and DEK encryption tags (42501)', async () => {
      await withTenant(poolWorker, ORG_A, async (client) => {
        await expectSqlState(client.query('SELECT wrapped_dek FROM organizations'), '42501');
      });
      await withTenant(poolWorker, ORG_A, async (client) => {
        await expectSqlState(client.query('SELECT dek_iv FROM organizations'), '42501');
      });
      await withTenant(poolWorker, ORG_A, async (client) => {
        await expectSqlState(client.query('SELECT dek_auth_tag FROM organizations'), '42501');
      });
      await withTenant(poolWorker, ORG_A, async (client) => {
        await expectSqlState(client.query('SELECT * FROM organizations'), '42501');
      });
    });

    it('strictly denies worker from reading provider key ciphertext and tags (42501)', async () => {
      // Allowed: non-secret metadata
      await withTenant(poolWorker, ORG_A, async (client) => {
        const { rows } = await client.query<{ id: string; label: string }>(
          'SELECT id, org_id, provider, label, key_hint, is_active, created_at FROM provider_keys',
        );
        expect(rows).toHaveLength(1);
        expect(rows[0]?.id).toBe(PK_A);
      });

      // Denied: secret ciphertext and authentication tags
      await withTenant(poolWorker, ORG_A, async (client) => {
        await expectSqlState(client.query('SELECT ciphertext FROM provider_keys'), '42501');
      });
      await withTenant(poolWorker, ORG_A, async (client) => {
        await expectSqlState(client.query('SELECT iv FROM provider_keys'), '42501');
      });
      await withTenant(poolWorker, ORG_A, async (client) => {
        await expectSqlState(client.query('SELECT auth_tag FROM provider_keys'), '42501');
      });
      await withTenant(poolWorker, ORG_A, async (client) => {
        await expectSqlState(client.query('SELECT * FROM provider_keys'), '42501');
      });
    });

    it('strictly denies worker from accessing users and web_sessions (§12.1)', async () => {
      await withTenant(poolWorker, ORG_A, async (client) => {
        await expectSqlState(client.query('SELECT * FROM users'), '42501');
      });
      await withTenant(poolWorker, ORG_A, async (client) => {
        await expectSqlState(client.query('SELECT * FROM web_sessions'), '42501');
      });
      await withTenant(poolWorker, ORG_A, async (client) => {
        await expectSqlState(
          client.query(
            `INSERT INTO users (id, org_id, email_normalized, password_hash, role) VALUES ('${USER_A}', '${ORG_A}', 'probe@example.com', 'p', 'member')`,
          ),
          '42501',
        );
      });
    });

    it('permits worker to perform attempt updates, adjustment inserts, and trace maintenance', async () => {
      await withTenant(poolWorker, ORG_A, async (client) => {
        // Worker updates attempt status (e.g., recovery)
        const updateAttempt = await client.query(
          "UPDATE provider_attempts SET status = 'interrupted', outcome = 'interrupted' WHERE attempt_id = $1",
          [ATT_A],
        );
        expect(updateAttempt.rowCount).toBe(1);

        // Worker inserts append-only adjustment
        const workerAdjId = '50000003-0000-4000-8000-000000000001';
        await client.query(`
          INSERT INTO provider_cost_adjustments (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars, delta_microdollars, source, source_reference)
          VALUES ('${workerAdjId}', '${ATT_A_SETTLED}', '${ORG_A}', 4000, 3800, -200, 'provider_usage', 'usage-w-1')
        `);

        // Worker prunes expired trace payloads
        const deleteTrace = await client.query(
          "DELETE FROM trace_payloads WHERE request_id = $1 AND expires_at < clock_timestamp() + interval '10 days'",
          [REQ_A],
        );
        expect(deleteTrace.rowCount).toBe(1);
      });
    });
  });

  // =========================================================================
  // Gate A2 — Cross-Tenant Referential Integrity & Immutability Integration
  // =========================================================================
  describe('Gate A2: Cross-tenant referential integrity & financial immutability integration', () => {
    it('blocks cross-tenant composite FK references even if caller attempts forgery', async () => {
      await withTenant(poolApp, ORG_A, async (client) => {
        // Org A request referencing Org B virtual key fails FK check (23503)
        await expectSqlState(
          client.query(`
            INSERT INTO gateway_requests (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model, billing_period, status, cache_status, deadline_at)
            VALUES ('30000009-0000-4000-8000-000000000001', '${ORG_A}', '${VK_B}', '${GW_INSTANCE}', 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', '2026-11-15T12:01:00.000Z')
          `),
          '23503',
        );
      });
    });

    it('preserves financial immutability triggers (0008) under tenant RLS (0009)', async () => {
      // 1. Attempting to mutate base cost of settled attempt is blocked by trigger (23514)
      await withTenant(poolApp, ORG_A, async (client) => {
        await expectSqlState(
          client.query(
            'UPDATE provider_attempts SET actual_cost_microdollars = 999999 WHERE attempt_id = $1',
            [ATT_A_SETTLED],
          ),
          '23514',
        );
      });

      // 2. Attempting to change billing period on gateway request is blocked by trigger (23514)
      await withTenant(poolApp, ORG_A, async (client) => {
        await expectSqlState(
          client.query(
            "UPDATE gateway_requests SET billing_period = '2026-12' WHERE request_id = $1",
            [REQ_A],
          ),
          '23514',
        );
      });
    });
  });
});
