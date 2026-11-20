import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { runMigrations } from './migrate.js';
import {
  withTenant,
  getActiveTenantContext,
  TenantTransactionError,
  type TenantClient,
} from './tenant.js';
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
  let poolStartup: pg.Pool;

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

    // Create pooled connections for gateway_app, gateway_worker, and gateway_startup
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
    poolStartup = new pg.Pool({
      connectionString: roleConnectionString(
        database.url,
        'gateway_startup',
        passwords.gateway_startup,
      ),
      max: 5,
    });
  });

  afterAll(async () => {
    await poolApp?.end().catch(() => undefined);
    await poolWorker?.end().catch(() => undefined);
    await poolStartup?.end().catch(() => undefined);
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
        expect('client' in (active ?? {})).toBe(false);

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
        expect(() => (client as unknown as { release: () => void }).release()).toThrow(
          TenantTransactionError,
        );
      });
    });

    it('DB-34: prepared-statement cache invalidation prevention and session parameter cleanup under pooled reuse (max: 1)', async () => {
      const singleConnPool = new pg.Pool({
        connectionString: roleConnectionString(database.url, 'gateway_app', passwords.gateway_app),
        max: 1,
      });

      try {
        // 1. Repeated named QueryConfig query using the same pooled connection (DB-34 reproduction & verification)
        const namedQueryA = {
          name: 'get_user_by_email_normalized',
          text: 'SELECT id, email_normalized FROM users WHERE email_normalized = $1',
          values: ['alice@acme.example'],
        };
        const r1 = await withTenant(singleConnPool, ORG_A, async (client) => {
          return client.query<{ id: string; email_normalized: string }>(namedQueryA);
        });
        expect(r1.rows).toHaveLength(1);
        expect(r1.rows[0]?.id).toBe(USER_A);

        // Same connection reused by Org B with identical statement name must NOT fail with SQLSTATE 26000
        const namedQueryB = {
          name: 'get_user_by_email_normalized',
          text: 'SELECT id, email_normalized FROM users WHERE email_normalized = $1',
          values: ['bob@beta.example'],
        };
        const r2 = await withTenant(singleConnPool, ORG_B, async (client) => {
          return client.query<{ id: string; email_normalized: string }>(namedQueryB);
        });
        expect(r2.rows).toHaveLength(1);
        expect(r2.rows[0]?.id).toBe(USER_B);

        // 2. Repeated unnamed parameterized query
        const u1 = await withTenant(singleConnPool, ORG_A, async (client) => {
          return client.query<{ val: string }>('SELECT $1::text AS val', ['alpha']);
        });
        expect(u1.rows[0]?.val).toBe('alpha');

        const u2 = await withTenant(singleConnPool, ORG_B, async (client) => {
          return client.query<{ val: string }>('SELECT $1::text AS val', ['beta']);
        });
        expect(u2.rows[0]?.val).toBe('beta');

        // 3. Caller QueryConfig attempting to override extended mode is rejected by single-statement enforcement
        await expectSqlState(
          withTenant(singleConnPool, ORG_A, async (client) => {
            await client.query({
              text: 'SELECT 1; SELECT 2;',
              queryMode: 'simple',
            } as pg.QueryConfig);
          }),
          '42601',
        );

        // 4. Org A -> Org B -> no-context pool reuse
        let noCtx = await singleConnPool.connect();
        try {
          const guc = await noCtx.query<{ org: string | null }>(
            "SELECT current_setting('app.current_org_id', true) AS org",
          );
          expect(guc.rows[0]?.org === '' || guc.rows[0]?.org === null).toBe(true);
          const users = await noCtx.query('SELECT * FROM users');
          expect(users.rows).toHaveLength(0);
        } finally {
          noCtx.release();
        }

        // 5. Session-level SET app.current_org_id contamination cleaned up by RESET ALL
        await withTenant(singleConnPool, ORG_A, async (client) => {
          await client.query(`SET app.current_org_id = '${ORG_A}'`);
        });

        noCtx = await singleConnPool.connect();
        try {
          const guc = await noCtx.query<{ org: string | null }>(
            "SELECT current_setting('app.current_org_id', true) AS org",
          );
          expect(guc.rows[0]?.org === '' || guc.rows[0]?.org === null).toBe(true);
          const users = await noCtx.query('SELECT * FROM users');
          expect(users.rows).toHaveLength(0);
        } finally {
          noCtx.release();
        }

        // 6. Session-level set_config(..., false) contamination cleaned up by RESET ALL
        await withTenant(singleConnPool, ORG_A, async (client) => {
          await client.query(`SELECT set_config('app.current_org_id', '${ORG_A}', false)`);
        });

        noCtx = await singleConnPool.connect();
        try {
          const guc = await noCtx.query<{ org: string | null }>(
            "SELECT current_setting('app.current_org_id', true) AS org",
          );
          expect(guc.rows[0]?.org === '' || guc.rows[0]?.org === null).toBe(true);
          const users = await noCtx.query('SELECT * FROM users');
          expect(users.rows).toHaveLength(0);
        } finally {
          noCtx.release();
        }

        // 7. Callback rollback after a session-setting change
        await expect(
          withTenant(singleConnPool, ORG_A, async (client) => {
            await client.query(`SELECT set_config('app.current_org_id', '${ORG_A}', false)`);
            throw new Error('deliberate-error-with-session-guc');
          }),
        ).rejects.toThrow('deliberate-error-with-session-guc');

        noCtx = await singleConnPool.connect();
        try {
          const guc = await noCtx.query<{ org: string | null }>(
            "SELECT current_setting('app.current_org_id', true) AS org",
          );
          expect(guc.rows[0]?.org === '' || guc.rows[0]?.org === null).toBe(true);
          const users = await noCtx.query('SELECT * FROM users');
          expect(users.rows).toHaveLength(0);
        } finally {
          noCtx.release();
        }

        // 8. Connection sanitation failure and destruction
        const deadClient = await singleConnPool.connect();
        deadClient.release(true); // destroy connection
        expect(singleConnPool.waitingCount).toBe(0);

        // 9. No stale tenant identity on a reused connection
        const freshClient = await singleConnPool.connect();
        try {
          const guc = await freshClient.query<{ org: string | null }>(
            "SELECT current_setting('app.current_org_id', true) AS org",
          );
          expect(guc.rows[0]?.org === '' || guc.rows[0]?.org === null).toBe(true);
        } finally {
          freshClient.release();
        }
      } finally {
        await singleConnPool.end();
      }
    });

    it('DB-33: false failure after confirmed COMMIT prevention, durable write preservation, and distinct outcome reporting', async () => {
      // 1. Execute actual INSERT through withTenant() with deterministic failure in post-COMMIT sanitation
      const committedUserId = 'a1000009-0000-4000-8000-000000000066';
      let postCommitCleanupError: unknown;

      const postCommitFailPool = {
        connect: async () => {
          const client = await poolApp.connect();
          const originalQuery = client.query.bind(client);
          client.query = (async (...args: unknown[]) => {
            const first = args[0];
            const sql =
              typeof first === 'string' ? first : (first as { text?: string } | undefined)?.text;
            if (sql === 'RESET ALL') {
              throw new Error('Injected post-commit sanitation failure');
            }
            return (originalQuery as (...a: unknown[]) => Promise<unknown>)(...args);
          }) as unknown as typeof client.query;
          return client;
        },
      } as unknown as pg.Pool;

      // 2. Allow PostgreSQL to confirm COMMIT; post-COMMIT sanitation step fails
      const result = await withTenant(
        postCommitFailPool,
        ORG_A,
        async (txClient) => {
          await txClient.query(
            `INSERT INTO users (id, org_id, email_normalized, password_hash, role)
             VALUES ($1, $2, 'durable-commit@example.com', 'h', 'member')`,
            [committedUserId, ORG_A],
          );
          return 'committed-durable-result';
        },
        {
          onCleanupError: (err) => {
            postCommitCleanupError = err;
          },
        },
      );

      // 3. Verify helper preserves confirmed result and does not represent transaction as rolled back or failed
      expect(result).toBe('committed-durable-result');
      expect(postCommitCleanupError).toBeDefined();
      expect((postCommitCleanupError as Error).message).toBe(
        'Injected post-commit sanitation failure',
      );

      // 4. Verify row is durably present in the database
      await withTenant(poolApp, ORG_A, async (client) => {
        const { rows } = await client.query<{ id: string }>('SELECT id FROM users WHERE id = $1', [
          committedUserId,
        ]);
        expect(rows).toHaveLength(1);
        expect(rows[0]?.id).toBe(committedUserId);
      });

      // Clean up durable test row so subsequent fixture-dependent assertions are unaffected
      await withTenant(poolApp, ORG_A, async (client) => {
        await client.query('DELETE FROM users WHERE id = $1', [committedUserId]);
      });

      // 5. Verify subsequent checkout from pool succeeds safely
      const subsequentClient = await poolApp.connect();
      try {
        const { rows } = await subsequentClient.query<{ n: number }>('SELECT 1 AS n');
        expect(rows[0]?.n).toBe(1);
      } finally {
        subsequentClient.release();
      }

      // 6. Separately test: COMMIT returning ROLLBACK (aborted transaction with swallowed error)
      const probeRollbackId = 'a1000009-0000-4000-8000-000000000067';
      await expect(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query(
            `INSERT INTO users (id, org_id, email_normalized, password_hash, role)
             VALUES ($1, $2, 'rollback-swallowed@example.com', 'h', 'member')`,
            [probeRollbackId, ORG_A],
          );
          try {
            await client.query('SYNTAX ERROR TRIGGERING 42601 TO ABORT TRANSACTION');
          } catch {
            // Swallowing statement error inside callback
          }
          return 'should-not-reach-here';
        }),
      ).rejects.toThrow(/PostgreSQL rolled back the aborted transaction/i);

      // Confirm row was NOT committed
      await withTenant(poolApp, ORG_A, async (client) => {
        const { rows } = await client.query('SELECT id FROM users WHERE id = $1', [
          probeRollbackId,
        ]);
        expect(rows).toHaveLength(0);
      });

      // 7. Separately test: actual COMMIT execution failure
      const commitFailPool = {
        connect: async () => {
          const client = await poolApp.connect();
          const originalQuery = client.query.bind(client);
          client.query = (async (...args: unknown[]) => {
            const first = args[0];
            const sql =
              typeof first === 'string' ? first : (first as { text?: string } | undefined)?.text;
            if (sql === 'COMMIT') {
              throw new Error('Injected network disruption on COMMIT');
            }
            return (originalQuery as (...a: unknown[]) => Promise<unknown>)(...args);
          }) as unknown as typeof client.query;
          return client;
        },
      } as unknown as pg.Pool;

      await expect(
        withTenant(commitFailPool, ORG_A, async (client) => {
          await client.query('SELECT 1');
          return 'ok';
        }),
      ).rejects.toThrow('Failed to execute COMMIT statement');

      // 8. Separately test: callback failure
      const cbFailId = 'a1000009-0000-4000-8000-000000000068';
      const customAppError = new Error('Custom application business logic error');
      await expect(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query(
            `INSERT INTO users (id, org_id, email_normalized, password_hash, role)
             VALUES ($1, $2, 'cb-fail@example.com', 'h', 'member')`,
            [cbFailId, ORG_A],
          );
          throw customAppError;
        }),
      ).rejects.toThrow(customAppError);

      await withTenant(poolApp, ORG_A, async (client) => {
        const { rows } = await client.query('SELECT id FROM users WHERE id = $1', [cbFailId]);
        expect(rows).toHaveLength(0);
      });

      // 9. Separately test: rollback cleanup failure preserves original callback error
      let rollbackCleanupWarning: unknown;
      const rollbackCleanupFailPool = {
        connect: async () => {
          const client = await poolApp.connect();
          const originalQuery = client.query.bind(client);
          client.query = (async (...args: unknown[]) => {
            const first = args[0];
            const sql =
              typeof first === 'string' ? first : (first as { text?: string } | undefined)?.text;
            if (sql === 'RESET ALL') {
              throw new Error('Injected post-rollback cleanup failure');
            }
            return (originalQuery as (...a: unknown[]) => Promise<unknown>)(...args);
          }) as unknown as typeof client.query;
          return client;
        },
      } as unknown as pg.Pool;

      const originalAppError = new Error('Original application error before rollback');
      await expect(
        withTenant(
          rollbackCleanupFailPool,
          ORG_A,
          async () => {
            throw originalAppError;
          },
          {
            onCleanupError: (err) => {
              rollbackCleanupWarning = err;
            },
          },
        ),
      ).rejects.toThrow(originalAppError);

      expect(rollbackCleanupWarning).toBeDefined();
      expect((rollbackCleanupWarning as Error).message).toContain(
        'Injected post-rollback cleanup failure',
      );
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

    it('DB-26: rejects silent rollback on aborted transaction and does not report successful commit', async () => {
      const probeUserId = 'a1000009-0000-4000-8000-000000000002';

      // Transaction attempts insert, triggers a statement error, catches/swallows it, and returns normally
      await expect(
        withTenant(poolApp, ORG_A, async (client) => {
          // 1. Valid insert
          await client.query(
            `INSERT INTO users (id, org_id, email_normalized, password_hash, role)
             VALUES ($1, $2, 'aborted-swallow-probe@example.com', 'h', 'member')`,
            [probeUserId, ORG_A],
          );

          // 2. Execute invalid statement that raises a known SQLSTATE (syntax error 42601)
          try {
            await client.query('SYNTAX_ERROR_TO_ABORT_TRANSACTION;');
          } catch {
            // 3. Swallow statement error inside callback
          }

          // 4. Return normally from callback
          return 'swallowed-success';
        }),
      ).rejects.toThrow(/PostgreSQL rolled back the aborted transaction/i);

      // 5. Verify the earlier inserted row was rolled back and does not persist
      await withTenant(poolApp, ORG_A, async (client) => {
        const { rows } = await client.query('SELECT id FROM users WHERE id = $1', [probeUserId]);
        expect(rows).toHaveLength(0);
      });

      // 6. Verify pool remains healthy and a subsequent tenant transaction genuinely commits
      const cleanProbeId = 'a1000009-0000-4000-8000-000000000003';
      const normalResult = await withTenant(poolApp, ORG_A, async (client) => {
        await client.query(
          `INSERT INTO users (id, org_id, email_normalized, password_hash, role)
           VALUES ($1, $2, 'normal-commit-probe@example.com', 'h', 'member')`,
          [cleanProbeId, ORG_A],
        );
        return 'normal-commit-success';
      });
      expect(normalResult).toBe('normal-commit-success');

      // Verify the row from the normal commit persisted
      await withTenant(poolApp, ORG_A, async (client) => {
        const { rows } = await client.query('SELECT id FROM users WHERE id = $1', [cleanProbeId]);
        expect(rows).toHaveLength(1);
        await client.query('DELETE FROM users WHERE id = $1', [cleanProbeId]);
      });
    });

    it('DB-30: rejects transaction control and multi-statement queries across formats, bindings, and aliases', async () => {
      // 1. Direct COMMIT, ROLLBACK, BEGIN with and without semicolons
      await withTenant(poolApp, ORG_A, async (client) => {
        await expect(client.query('COMMIT')).rejects.toThrow(TenantTransactionError);
        await expect(client.query('commit;')).rejects.toThrow(TenantTransactionError);
        await expect(client.query('ROLLBACK')).rejects.toThrow(TenantTransactionError);
        await expect(client.query('rollback;')).rejects.toThrow(TenantTransactionError);
        await expect(client.query('BEGIN')).rejects.toThrow(TenantTransactionError);
        await expect(client.query('begin;')).rejects.toThrow(TenantTransactionError);
      });

      // 2. Transaction aliases: START TRANSACTION, END, ABORT
      await withTenant(poolApp, ORG_A, async (client) => {
        await expect(client.query('START TRANSACTION')).rejects.toThrow(TenantTransactionError);
        await expect(client.query('END')).rejects.toThrow(TenantTransactionError);
        await expect(client.query('ABORT')).rejects.toThrow(TenantTransactionError);
      });

      // 3. Savepoint controls: SAVEPOINT, RELEASE, ROLLBACK TO
      await withTenant(poolApp, ORG_A, async (client) => {
        await expect(client.query('SAVEPOINT sp1')).rejects.toThrow(TenantTransactionError);
        await expect(client.query('RELEASE SAVEPOINT sp1')).rejects.toThrow(TenantTransactionError);
        await expect(client.query('ROLLBACK TO sp1')).rejects.toThrow(TenantTransactionError);
      });

      // 4. Leading comments (line and block comments)
      await withTenant(poolApp, ORG_A, async (client) => {
        await expect(client.query('/* block comment */ COMMIT;')).rejects.toThrow(
          TenantTransactionError,
        );
        await expect(client.query('-- line comment\nROLLBACK;')).rejects.toThrow(
          TenantTransactionError,
        );
      });

      // 5. QueryConfig-based attempts (with caller queryMode override attempt)
      await withTenant(poolApp, ORG_A, async (client) => {
        await expect(client.query({ text: 'COMMIT' })).rejects.toThrow(TenantTransactionError);
      });
      await expect(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query({ text: 'SELECT 1; COMMIT;', queryMode: 'simple' } as pg.QueryConfig);
        }),
      ).rejects.toThrow();

      // 6. Multiple commands submitted through one query rejected by PostgreSQL (42601)
      await expectSqlState(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query('SELECT 1; SELECT 2;');
        }),
        '42601',
      );

      // 7. Confirmed standard-conforming-string lexer discrepancy: SELECT 'a\'; COMMIT; SELECT 'b'
      // Under PostgreSQL 16 standard_conforming_strings=on, 'a\' closes the string.
      // Rejected fail-closed before any COMMIT can execute.
      await expect(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query("SELECT 'a\\'; COMMIT; SELECT 'b'");
        }),
      ).rejects.toThrow();

      // 8. Queries with parameter bindings: legitimate query succeeds, multi-command with bindings rejected
      await withTenant(poolApp, ORG_A, async (client) => {
        const goodRes = await client.query('SELECT $1::text AS val', ['hello']);
        expect(goodRes.rows[0]?.val).toBe('hello');
      });
      await expectSqlState(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query('SELECT $1::text; SELECT 2;', ['hello']);
        }),
        '42601',
      );

      // 9. Legitimate query containing transaction words inside literals or identifiers succeeds
      await withTenant(poolApp, ORG_A, async (client) => {
        const res = await client.query<{ literal_val: string; lit2: string }>(
          "SELECT 'COMMIT' AS literal_val, 'BEGIN' AS lit2",
        );
        expect(res.rows[0]?.literal_val).toBe('COMMIT');
        expect(res.rows[0]?.lit2).toBe('BEGIN');
      });
    });

    it('DB-30: mandatory persistent-state verification — write then unauthorized query rejection', async () => {
      const probeWriteId = 'a1000009-0000-4000-8000-000000000008';

      // 1. Inside withTenant: perform valid write, then attempt unauthorized query, then force failure
      await expect(
        withTenant(poolApp, ORG_A, async (client) => {
          // Valid write
          await client.query(
            `INSERT INTO users (id, org_id, email_normalized, password_hash, role)
             VALUES ($1, $2, 'persistent-state-probe@example.com', 'h', 'member')`,
            [probeWriteId, ORG_A],
          );

          // Attempt to terminate transaction through unauthorized query (the confirmed parser discrepancy)
          try {
            await client.query("SELECT 'a\\'; COMMIT; SELECT 'b'");
          } catch {
            // Unauthorized query was rejected before transaction boundary altered!
          }

          // Force the callback to fail
          throw new Error('deliberate-failure-after-unauthorized-attempt');
        }),
      ).rejects.toThrow('deliberate-failure-after-unauthorized-attempt');

      // 2. Verify NO write persisted in PostgreSQL
      await withTenant(poolApp, ORG_A, async (client) => {
        const { rows } = await client.query('SELECT id FROM users WHERE id = $1', [probeWriteId]);
        expect(rows).toHaveLength(0);
      });

      // 3. Confirm subsequent normal transactions continue to operate cleanly
      const subsequentId = 'a1000009-0000-4000-8000-000000000009';
      await withTenant(poolApp, ORG_A, async (client) => {
        await client.query(
          `INSERT INTO users (id, org_id, email_normalized, password_hash, role)
           VALUES ($1, $2, 'subsequent-normal-probe@example.com', 'h', 'member')`,
          [subsequentId, ORG_A],
        );
      });

      // Row from subsequent normal transaction persisted
      await withTenant(poolApp, ORG_A, async (client) => {
        const { rows } = await client.query('SELECT id FROM users WHERE id = $1', [subsequentId]);
        expect(rows).toHaveLength(1);
        await client.query('DELETE FROM users WHERE id = $1', [subsequentId]);
      });
    });

    it('DB-27: rolls back writes when callback throws; persists writes when callback succeeds', async () => {
      const rollbackId = 'a1000009-0000-4000-8000-000000000004';
      const commitId = 'a1000009-0000-4000-8000-000000000005';

      // 1. Callback writes then throws -> no write persists
      await expect(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query(
            `INSERT INTO users (id, org_id, email_normalized, password_hash, role)
             VALUES ($1, $2, 'write-throw-probe@example.com', 'h', 'member')`,
            [rollbackId, ORG_A],
          );
          throw new Error('deliberate callback throw');
        }),
      ).rejects.toThrow('deliberate callback throw');

      await withTenant(poolApp, ORG_A, async (client) => {
        const { rows } = await client.query('SELECT id FROM users WHERE id = $1', [rollbackId]);
        expect(rows).toHaveLength(0);
      });

      // 2. Normal callback writes and commits -> write persists
      await withTenant(poolApp, ORG_A, async (client) => {
        await client.query(
          `INSERT INTO users (id, org_id, email_normalized, password_hash, role)
           VALUES ($1, $2, 'write-commit-probe@example.com', 'h', 'member')`,
          [commitId, ORG_A],
        );
      });

      await withTenant(poolApp, ORG_A, async (client) => {
        const { rows } = await client.query('SELECT id FROM users WHERE id = $1', [commitId]);
        expect(rows).toHaveLength(1);
        await client.query('DELETE FROM users WHERE id = $1', [commitId]);
      });
    });

    it('DB-29: marks async context inactive and prevents detached async continuations from misusing released clients', async () => {
      let leakedClient: TenantClient | undefined;
      let backgroundDonePromise: Promise<void>;

      await withTenant(poolApp, ORG_A, async (client) => {
        leakedClient = client;

        backgroundDonePromise = new Promise<void>((resolve, reject) => {
          setTimeout(async () => {
            try {
              // 1. In detached continuation, old context must no longer be active
              const ctx = getActiveTenantContext();
              expect(ctx).toBeUndefined();

              // 2. Querying through the leaked TenantClient must fail because transaction is inactive
              await expect(leakedClient!.query('SELECT 1')).rejects.toThrow(
                /Cannot execute query: tenant transaction is no longer active/,
              );

              // 3. A subsequent legitimate withTenant call must NOT be treated as nested
              const subsequentResult = await withTenant(poolApp, ORG_A, async (subClient) => {
                const { rows } = await subClient.query('SELECT 42 AS val');
                return rows[0]?.val;
              });
              expect(subsequentResult).toBe(42);

              resolve();
            } catch (err) {
              reject(err);
            }
          }, 50);
        });

        return 'parent-done';
      });

      // Await detached continuation to verify assertions completed
      await backgroundDonePromise!;

      // 4. Verify pool connection reuse remains completely isolated for Org B
      await withTenant(poolApp, ORG_B, async (client) => {
        const { rows } = await client.query<{ id: string }>('SELECT id FROM users');
        expect(rows).toHaveLength(1);
        expect(rows[0]?.id).toBe(USER_B);
      });
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
    it('enforces table-driven cross-tenant visibility and isolation across all nine tenant tables', async () => {
      const TABLE_MATRIX = [
        { table: 'organizations', orgCol: 'id', expectedA: ORG_A, expectedB: ORG_B },
        { table: 'users', orgCol: 'org_id', expectedA: ORG_A, expectedB: ORG_B },
        { table: 'web_sessions', orgCol: 'org_id', expectedA: ORG_A, expectedB: ORG_B },
        { table: 'provider_keys', orgCol: 'org_id', expectedA: ORG_A, expectedB: ORG_B },
        { table: 'virtual_keys', orgCol: 'org_id', expectedA: ORG_A, expectedB: ORG_B },
        { table: 'gateway_requests', orgCol: 'org_id', expectedA: ORG_A, expectedB: ORG_B },
        { table: 'provider_attempts', orgCol: 'org_id', expectedA: ORG_A, expectedB: ORG_B },
        {
          table: 'provider_cost_adjustments',
          orgCol: 'org_id',
          expectedA: ORG_A,
          expectedB: ORG_B,
        },
        { table: 'trace_payloads', orgCol: 'org_id', expectedA: ORG_A, expectedB: ORG_B },
      ] as const;

      for (const item of TABLE_MATRIX) {
        // 1. Under Org A context: exactly Org A rows visible, Org B rows completely invisible
        await withTenant(poolApp, ORG_A, async (client) => {
          const { rows } = await client.query<{ org_val: string }>(
            `SELECT ${item.orgCol} AS org_val FROM ${item.table}`,
          );
          expect(rows.length, `${item.table} Org A count`).toBeGreaterThanOrEqual(1);
          for (const row of rows) {
            expect(row.org_val, `${item.table} row belongs to Org A`).toBe(item.expectedA);
          }
        });

        // 2. Under Org B context: exactly Org B rows visible, Org A rows completely invisible
        await withTenant(poolApp, ORG_B, async (client) => {
          const { rows } = await client.query<{ org_val: string }>(
            `SELECT ${item.orgCol} AS org_val FROM ${item.table}`,
          );
          expect(rows.length, `${item.table} Org B count`).toBeGreaterThanOrEqual(1);
          for (const row of rows) {
            expect(row.org_val, `${item.table} row belongs to Org B`).toBe(item.expectedB);
          }
        });

        // 3. Under No Context (poolApp.query with no app.current_org_id): exactly 0 rows returned
        const { rows: noContextRows } = await poolApp.query(
          `SELECT ${item.orgCol} FROM ${item.table}`,
        );
        expect(noContextRows, `${item.table} no-context row count`).toHaveLength(0);
      }
    });

    it('distinguishes PostgreSQL privilege denial from RLS policy violation', async () => {
      // 1. Privilege denial: gateway_app is not granted DELETE on gateway_requests
      const err1 = await captureError(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query('DELETE FROM gateway_requests');
        }),
      );
      expect(errorCode(err1)).toBe('42501');
      expect(errorMessage(err1)).toMatch(/permission denied for table gateway_requests/i);

      // 2. RLS policy violation: gateway_app is granted INSERT on organizations, but violates RLS WITH CHECK
      const err2 = await captureError(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query(`
            INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
            VALUES ('${ORG_B}', 'Probe Forgery', 100, 1, '\\x01', '\\x02', '\\x03')
          `);
        }),
      );
      expect(errorCode(err2)).toBe('42501');
      expect(errorMessage(err2)).toMatch(
        /violates row-level security policy for table "organizations"/i,
      );

      // 3. Worker column-level privilege denial: worker is not granted wrapped_dek on organizations
      const err3 = await captureError(
        withTenant(poolWorker, ORG_A, async (client) => {
          await client.query('SELECT wrapped_dek FROM organizations');
        }),
      );
      expect(errorCode(err3)).toBe('42501');
      expect(errorMessage(err3)).toMatch(/permission denied for (table|column) organizations/i);

      // 4. Worker table-level privilege denial: worker has zero grants on users
      const err4 = await captureError(
        withTenant(poolWorker, ORG_A, async (client) => {
          await client.query('SELECT * FROM users');
        }),
      );
      expect(errorCode(err4)).toBe('42501');
      expect(errorMessage(err4)).toMatch(/permission denied for table users/i);
    });

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
      await expectSqlState(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query(`
            INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
            VALUES ('${ORG_B}', 'Fake B', 100, 1, '\\x01', '\\x02', '\\x03')
          `);
        }),
        '42501',
      );

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
      await expectSqlState(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query(`
            INSERT INTO users (id, org_id, email_normalized, password_hash, role)
            VALUES ('b100000b-0000-4000-8000-000000000001', '${ORG_B}', 'new_b@beta.example', 'pass', 'member')
          `);
        }),
        '42501',
      );

      // 3. Mutation attack: Attempt to move user to Org B fails WITH CHECK (42501)
      await expectSqlState(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query(`UPDATE users SET org_id = '${ORG_B}' WHERE id = '${USER_A}'`);
        }),
        '42501',
      );
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
      await expectSqlState(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query('DELETE FROM gateway_requests');
        }),
        '42501',
      );
      await expectSqlState(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query('DELETE FROM provider_attempts');
        }),
        '42501',
      );
      await expectSqlState(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query('DELETE FROM provider_cost_adjustments');
        }),
        '42501',
      );
      await expectSqlState(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query('UPDATE provider_cost_adjustments SET delta_microdollars = 0');
        }),
        '42501',
      );
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
      await expectSqlState(
        withTenant(poolWorker, ORG_A, async (client) => {
          await client.query('SELECT wrapped_dek FROM organizations');
        }),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, async (client) => {
          await client.query('SELECT dek_iv FROM organizations');
        }),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, async (client) => {
          await client.query('SELECT dek_auth_tag FROM organizations');
        }),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, async (client) => {
          await client.query('SELECT * FROM organizations');
        }),
        '42501',
      );
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
      await expectSqlState(
        withTenant(poolWorker, ORG_A, async (client) => {
          await client.query('SELECT ciphertext FROM provider_keys');
        }),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, async (client) => {
          await client.query('SELECT iv FROM provider_keys');
        }),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, async (client) => {
          await client.query('SELECT auth_tag FROM provider_keys');
        }),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, async (client) => {
          await client.query('SELECT * FROM provider_keys');
        }),
        '42501',
      );
    });

    it('strictly denies worker from accessing users and web_sessions (§12.1)', async () => {
      await expectSqlState(
        withTenant(poolWorker, ORG_A, async (client) => {
          await client.query('SELECT * FROM users');
        }),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, async (client) => {
          await client.query('SELECT * FROM web_sessions');
        }),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, async (client) => {
          await client.query(
            `INSERT INTO users (id, org_id, email_normalized, password_hash, role) VALUES ('${USER_A}', '${ORG_A}', 'probe@example.com', 'p', 'member')`,
          );
        }),
        '42501',
      );
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
    it('DB-28: blocks cross-tenant composite FK references with deterministic timestamp (23503)', async () => {
      // Org A request referencing Org B virtual key fails FK check (23503)
      const err = await captureError(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query(`
            INSERT INTO gateway_requests (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model, billing_period, status, cache_status, admitted_at, deadline_at)
            VALUES ('30000009-0000-4000-8000-000000000001', '${ORG_A}', '${VK_B}', '${GW_INSTANCE}', 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', '2026-11-15T12:00:00.000Z', '2026-11-15T12:01:00.000Z')
          `);
        }),
      );
      expect(errorCode(err)).toBe('23503');
      expect((err as { constraint?: string })?.constraint).toBe('fk_gateway_requests_virtual_key');
    });

    it('preserves financial immutability triggers (0008) under tenant RLS (0009)', async () => {
      // 1. Attempting to mutate base cost of settled attempt is blocked by trigger (23514)
      await expectSqlState(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query(
            'UPDATE provider_attempts SET actual_cost_microdollars = 999999 WHERE attempt_id = $1',
            [ATT_A_SETTLED],
          );
        }),
        '23514',
      );

      // 2. Attempting to change billing period on gateway request is blocked by trigger (23514)
      await expectSqlState(
        withTenant(poolApp, ORG_A, async (client) => {
          await client.query(
            "UPDATE gateway_requests SET billing_period = '2026-12' WHERE request_id = $1",
            [REQ_A],
          );
        }),
        '23514',
      );
    });
  });

  // =========================================================================
  // Gate A2 — DB-32: Complete Role-by-Table Operation Matrix
  // =========================================================================
  describe('Gate A2 — DB-32: Complete role-by-table mutation matrix (app, worker, startup)', () => {
    const ALL_NINE_TABLES = [
      'organizations',
      'users',
      'web_sessions',
      'provider_keys',
      'virtual_keys',
      'gateway_requests',
      'provider_attempts',
      'provider_cost_adjustments',
      'trace_payloads',
    ] as const;

    const TABLE_UPDATE_PROBES: Record<(typeof ALL_NINE_TABLES)[number], string> = {
      organizations: 'UPDATE organizations SET name = name',
      users: 'UPDATE users SET email_normalized = email_normalized',
      web_sessions: 'UPDATE web_sessions SET idle_expires_at = idle_expires_at',
      provider_keys: 'UPDATE provider_keys SET label = label',
      virtual_keys: 'UPDATE virtual_keys SET name = name',
      gateway_requests: 'UPDATE gateway_requests SET status = status',
      provider_attempts: 'UPDATE provider_attempts SET status = status',
      provider_cost_adjustments:
        'UPDATE provider_cost_adjustments SET delta_microdollars = delta_microdollars',
      trace_payloads: 'UPDATE trace_payloads SET response_text = response_text',
    };

    const TABLE_INSERT_PROBES: Record<(typeof ALL_NINE_TABLES)[number], string> = {
      organizations: `INSERT INTO organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag) VALUES ('${ORG_A}', 'X', 1, 1, '\\x01', '\\x01', '\\x01')`,
      users: `INSERT INTO users (id, org_id, email_normalized, password_hash, role) VALUES ('${USER_A}', '${ORG_A}', 'x@x.com', 'h', 'member')`,
      web_sessions: `INSERT INTO web_sessions (session_id_hash, user_id, org_id, csrf_token_hash, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ('\\x01', '${USER_A}', '${ORG_A}', '\\x01', clock_timestamp(), clock_timestamp(), clock_timestamp())`,
      provider_keys: `INSERT INTO provider_keys (id, org_id, provider, label, key_hint, ciphertext, iv, auth_tag) VALUES ('${PK_A}', '${ORG_A}', 'openai', 'L', 'h', '\\x01', '\\x01', '\\x01')`,
      virtual_keys: `INSERT INTO virtual_keys (id, org_id, name, key_prefix, allowed_models) VALUES ('${VK_A}', '${ORG_A}', 'test', 'sk-test', '{"gpt-4o"}')`,
      gateway_requests: `INSERT INTO gateway_requests (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model, billing_period, status, cache_status, admitted_at, deadline_at) VALUES ('30000009-0000-4000-8000-000000000099', '${ORG_A}', '${VK_A}', '${GW_INSTANCE}', 1, 'm', '2026-11', 'in_progress', 'miss', '2026-11-15T12:00:00.000Z', '2026-11-15T12:01:00.000Z')`,
      provider_attempts: `INSERT INTO provider_attempts (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id, gateway_epoch, billing_period, provider, model, status, cost_status, estimated_cost_microdollars, admitted_at, hard_deadline_at) VALUES ('40000009-0000-4000-8000-000000000099', '${REQ_A}', '${ORG_A}', '${VK_A}', 1, '${GW_INSTANCE}', 1, '2026-11', 'p', 'm', 'reserved', 'estimated', 1000, '2026-11-15T12:00:00.000Z', '2026-11-15T12:01:00.000Z')`,
      provider_cost_adjustments: `INSERT INTO provider_cost_adjustments (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars, delta_microdollars, source, source_reference) VALUES ('50000003-0000-4000-8000-000000000099', '${ATT_A_SETTLED}', '${ORG_A}', 4000, 3900, -100, 'provider_usage', 'usage-ref-99')`,
      trace_payloads: `INSERT INTO trace_payloads (request_id, org_id, request_body, response_text, expires_at) VALUES ('${REQ_A}', '${ORG_A}', '{"req":true}', 'res', clock_timestamp() + interval '1 day')`,
    };

    // 1. gateway_startup: strictly denied across all 9 tenant tables for SELECT, INSERT, UPDATE, DELETE (42501)
    it('DB-32: gateway_startup is strictly denied across all 9 tenant tables for SELECT, INSERT, UPDATE, DELETE (42501)', async () => {
      const client = await poolStartup.connect();
      try {
        for (const tbl of ALL_NINE_TABLES) {
          // SELECT denied (42501)
          const selErr = await captureError(client.query(`SELECT * FROM ${tbl} LIMIT 1`));
          expect(errorCode(selErr), `SELECT ${tbl}: ${(selErr as Error)?.message}`).toBe('42501');
          expect((selErr as Error).message).toMatch(/permission denied for (table|relation)/i);

          // INSERT denied (42501)
          const insErr = await captureError(client.query(TABLE_INSERT_PROBES[tbl]));
          expect(errorCode(insErr), `INSERT ${tbl}: ${(insErr as Error)?.message}`).toBe('42501');
          expect((insErr as Error).message).toMatch(/permission denied for (table|relation)/i);

          // UPDATE denied (42501)
          const updErr = await captureError(client.query(TABLE_UPDATE_PROBES[tbl]));
          expect(errorCode(updErr), `UPDATE ${tbl}: ${(updErr as Error)?.message}`).toBe('42501');
          expect((updErr as Error).message).toMatch(/permission denied for (table|relation)/i);

          // DELETE denied (42501)
          const delErr = await captureError(client.query(`DELETE FROM ${tbl}`));
          expect(errorCode(delErr), `DELETE ${tbl}: ${(delErr as Error)?.message}`).toBe('42501');
          expect((delErr as Error).message).toMatch(/permission denied for (table|relation)/i);
        }

        // Positive control: gateway_startup CAN read and update gateway_epoch on gateway_control
        const ctrlRes = await client.query<{ gateway_epoch: number }>(
          'SELECT gateway_epoch FROM gateway_control WHERE id = 1',
        );
        expect(ctrlRes.rows).toHaveLength(1);
        const updCtrl = await client.query(
          'UPDATE gateway_control SET gateway_epoch = gateway_epoch + 1 WHERE id = 1',
        );
        expect(updCtrl.rowCount).toBe(1);
      } finally {
        client.release();
      }
    });

    // 2. gateway_worker: table-by-table privilege boundaries, tenant-scoping, and mutation restrictions
    it('DB-32: gateway_worker positive operations, row filtering, and mutation restrictions', async () => {
      // Positive and row-filtered operations (non-aborting)
      await withTenant(poolWorker, ORG_A, async (client) => {
        // organizations: metadata SELECT ok, cross-tenant rowCount=0
        const orgMeta = await client.query('SELECT id, name FROM organizations WHERE id = $1', [
          ORG_A,
        ]);
        expect(orgMeta.rowCount).toBe(1);
        const orgCross = await client.query('SELECT id, name FROM organizations WHERE id = $1', [
          ORG_B,
        ]);
        expect(orgCross.rowCount).toBe(0);

        // provider_keys: metadata SELECT ok, cross-tenant rowCount=0
        const pkMeta = await client.query('SELECT id, provider FROM provider_keys WHERE id = $1', [
          PK_A,
        ]);
        expect(pkMeta.rowCount).toBe(1);
        const pkCross = await client.query('SELECT id, provider FROM provider_keys WHERE id = $1', [
          PK_B,
        ]);
        expect(pkCross.rowCount).toBe(0);

        // virtual_keys: SELECT ok and tenant-scoped
        const vkRes = await client.query('SELECT id FROM virtual_keys WHERE id = $1', [VK_A]);
        expect(vkRes.rowCount).toBe(1);
        const vkCross = await client.query('SELECT id FROM virtual_keys WHERE id = $1', [VK_B]);
        expect(vkCross.rowCount).toBe(0);

        // gateway_requests: SELECT ok, permitted columns UPDATE ok on same tenant, cross-tenant UPDATE rowCount=0
        const reqRes = await client.query(
          'SELECT request_id FROM gateway_requests WHERE request_id = $1',
          [REQ_A],
        );
        expect(reqRes.rowCount).toBe(1);
        const reqUpd = await client.query(
          "UPDATE gateway_requests SET status = 'completed', http_status = 200, finalized_at = clock_timestamp() WHERE request_id = $1",
          [REQ_A],
        );
        expect(reqUpd.rowCount).toBe(1);
        const reqUpdCross = await client.query(
          "UPDATE gateway_requests SET status = 'completed' WHERE request_id = $1",
          [REQ_B],
        );
        expect(reqUpdCross.rowCount).toBe(0);

        // provider_attempts: SELECT ok, permitted columns UPDATE ok on unsettled attempt, cross-tenant rowCount=0
        const attRes = await client.query(
          'SELECT attempt_id FROM provider_attempts WHERE attempt_id = $1',
          [ATT_A],
        );
        expect(attRes.rowCount).toBe(1);
        const attUpd = await client.query(
          "UPDATE provider_attempts SET status = 'interrupted', outcome = 'interrupted' WHERE attempt_id = $1",
          [ATT_A],
        );
        expect(attUpd.rowCount).toBe(1);
        const attUpdCross = await client.query(
          "UPDATE provider_attempts SET status = 'interrupted' WHERE attempt_id = $1",
          [ATT_B],
        );
        expect(attUpdCross.rowCount).toBe(0);

        // provider_cost_adjustments: SELECT ok, same-tenant INSERT ok
        const adjRes = await client.query(
          'SELECT adjustment_id FROM provider_cost_adjustments WHERE adjustment_id = $1',
          [ADJ_A],
        );
        expect(adjRes.rowCount).toBe(1);
        const workerAdjId = '50000003-0000-4000-8000-000000000099';
        await client.query(
          `INSERT INTO provider_cost_adjustments (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars, delta_microdollars, source, source_reference)
           VALUES ($1, $2, $3, 4000, 3900, -100, 'provider_usage', 'usage-ref-99')`,
          [workerAdjId, ATT_A_SETTLED, ORG_A],
        );

        // trace_payloads: INSERT ok, SELECT ok, UPDATE ok, DELETE ok for same tenant; cross-tenant UPDATE/DELETE rowCount=0
        await client.query(
          `INSERT INTO trace_payloads (request_id, org_id, request_body, response_text, expires_at)
           VALUES ($1, $2, '{"trace":true}', 'init', clock_timestamp() + interval '7 days')
           ON CONFLICT (request_id) DO UPDATE SET response_text = 'init'`,
          [REQ_A, ORG_A],
        );
        const traceRes = await client.query(
          'SELECT request_id FROM trace_payloads WHERE request_id = $1',
          [REQ_A],
        );
        expect(traceRes.rowCount).toBe(1);
        const traceUpd = await client.query(
          "UPDATE trace_payloads SET response_text = 'updated' WHERE request_id = $1",
          [REQ_A],
        );
        expect(traceUpd.rowCount).toBe(1);
        const traceUpdCross = await client.query(
          "UPDATE trace_payloads SET response_text = 'hack' WHERE request_id = $1",
          [REQ_B],
        );
        expect(traceUpdCross.rowCount).toBe(0);
        const traceDel = await client.query('DELETE FROM trace_payloads WHERE request_id = $1', [
          REQ_A,
        ]);
        expect(traceDel.rowCount).toBe(1);
        const traceDelCross = await client.query(
          'DELETE FROM trace_payloads WHERE request_id = $1',
          [REQ_B],
        );
        expect(traceDelCross.rowCount).toBe(0);
      });

      // Negative operations: column and table privileges strictly denied (42501)
      // organizations: column privilege on wrapped_dek, table INSERT, UPDATE, DELETE denied
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('SELECT wrapped_dek FROM organizations')),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query(TABLE_INSERT_PROBES.organizations)),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('UPDATE organizations SET name = $1', ['X'])),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('DELETE FROM organizations')),
        '42501',
      );

      // users: all operations denied
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('SELECT * FROM users')),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query(TABLE_INSERT_PROBES.users)),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('UPDATE users SET role = $1', ['admin'])),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('DELETE FROM users')),
        '42501',
      );

      // web_sessions: all operations denied
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('SELECT * FROM web_sessions')),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query(TABLE_INSERT_PROBES.web_sessions)),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) =>
          c.query('UPDATE web_sessions SET idle_expires_at = clock_timestamp()'),
        ),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('DELETE FROM web_sessions')),
        '42501',
      );

      // provider_keys: column privilege on ciphertext, table INSERT, UPDATE, DELETE denied
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('SELECT ciphertext FROM provider_keys')),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query(TABLE_INSERT_PROBES.provider_keys)),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('UPDATE provider_keys SET label = $1', ['X'])),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('DELETE FROM provider_keys')),
        '42501',
      );

      // virtual_keys: table INSERT, UPDATE, DELETE denied
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query(TABLE_INSERT_PROBES.virtual_keys)),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) =>
          c.query('UPDATE virtual_keys SET revoked_at = clock_timestamp() WHERE id = $1', [VK_A]),
        ),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('DELETE FROM virtual_keys')),
        '42501',
      );

      // gateway_requests: column UPDATE on ungranted column, table INSERT and DELETE denied
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) =>
          c.query("UPDATE gateway_requests SET billing_period = '2026-12' WHERE request_id = $1", [
            REQ_A,
          ]),
        ),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query(TABLE_INSERT_PROBES.gateway_requests)),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('DELETE FROM gateway_requests')),
        '42501',
      );

      // provider_attempts: column UPDATE on ungranted column, table INSERT and DELETE denied
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) =>
          c.query("UPDATE provider_attempts SET model = 'custom' WHERE attempt_id = $1", [ATT_A]),
        ),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query(TABLE_INSERT_PROBES.provider_attempts)),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('DELETE FROM provider_attempts')),
        '42501',
      );

      // provider_cost_adjustments: cross-tenant INSERT fails foreign-key parent isolation (23503), UPDATE and DELETE denied (append-only 42501)
      const crossWorkerAdjErr = await captureError(
        withTenant(poolWorker, ORG_A, (c) =>
          c.query(
            `INSERT INTO provider_cost_adjustments (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars, delta_microdollars, source, source_reference)
             VALUES ('50000003-0000-4000-8000-000000000098', $1, $2, 4000, 3900, -100, 'provider_usage', 'usage-ref-98')`,
            [ATT_B_SETTLED, ORG_B],
          ),
        ),
      );
      expect(errorCode(crossWorkerAdjErr)).toBe('23503');

      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) =>
          c.query(
            'UPDATE provider_cost_adjustments SET delta_microdollars = 0 WHERE adjustment_id = $1',
            [ADJ_A],
          ),
        ),
        '42501',
      );
      await expectSqlState(
        withTenant(poolWorker, ORG_A, (c) => c.query('DELETE FROM provider_cost_adjustments')),
        '42501',
      );
    });

    // 3. gateway_app: full tenant operation with clear differentiation of RLS WITH CHECK, row filtering, and financial immutability
    it('DB-32: gateway_app operation matrix across all nine tables', async () => {
      // Positive operations and row filtering
      await withTenant(poolApp, ORG_A, async (client) => {
        // users: same-tenant CRUD succeeds; cross-tenant UPDATE/DELETE rowCount=0
        const testUserId = 'a1000009-0000-4000-8000-000000000088';
        await client.query(
          `INSERT INTO users (id, org_id, email_normalized, password_hash, role) VALUES ($1, $2, 'crud@example.com', 'h', 'member')`,
          [testUserId, ORG_A],
        );
        const userUpd = await client.query('UPDATE users SET role = $1 WHERE id = $2', [
          'admin',
          testUserId,
        ]);
        expect(userUpd.rowCount).toBe(1);
        const crossUserUpd = await client.query('UPDATE users SET role = $1 WHERE id = $2', [
          'admin',
          USER_B,
        ]);
        expect(crossUserUpd.rowCount).toBe(0); // RLS row filtering
        const userDel = await client.query('DELETE FROM users WHERE id = $1', [testUserId]);
        expect(userDel.rowCount).toBe(1);
        const crossUserDel = await client.query('DELETE FROM users WHERE id = $1', [USER_B]);
        expect(crossUserDel.rowCount).toBe(0); // RLS row filtering

        // organizations: same-tenant SELECT and UPDATE ok; cross-tenant UPDATE rowCount=0
        const orgUpdCross = await client.query('UPDATE organizations SET name = $1 WHERE id = $2', [
          'Hack',
          ORG_B,
        ]);
        expect(orgUpdCross.rowCount).toBe(0);

        // gateway_requests: cross-tenant UPDATE rowCount=0
        const reqUpdCross = await client.query(
          "UPDATE gateway_requests SET status = 'completed' WHERE request_id = $1",
          [REQ_B],
        );
        expect(reqUpdCross.rowCount).toBe(0);

        // provider_attempts: cross-tenant UPDATE rowCount=0
        const attUpdCross = await client.query(
          "UPDATE provider_attempts SET status = 'interrupted' WHERE attempt_id = $1",
          [ATT_B],
        );
        expect(attUpdCross.rowCount).toBe(0);

        // provider_cost_adjustments: same-tenant INSERT succeeds
        const appAdjId = '50000003-0000-4000-8000-000000000077';
        await client.query(
          `INSERT INTO provider_cost_adjustments (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars, delta_microdollars, source, source_reference)
           VALUES ($1, $2, $3, 4500, 4200, -300, 'provider_usage', 'app-ref-77')`,
          [appAdjId, ATT_A_SETTLED, ORG_A],
        );

        // trace_payloads: same-tenant INSERT/UPDATE/DELETE succeeds; cross-tenant rowCount=0
        const traceUpdCross = await client.query(
          "UPDATE trace_payloads SET response_text = 'hack' WHERE request_id = $1",
          [REQ_B],
        );
        expect(traceUpdCross.rowCount).toBe(0);
        const traceDelCross = await client.query(
          'DELETE FROM trace_payloads WHERE request_id = $1',
          [REQ_B],
        );
        expect(traceDelCross.rowCount).toBe(0);
      });

      // Negative operations: RLS WITH CHECK, least privilege DELETE, and financial immutability triggers
      // users: cross-tenant INSERT fails RLS WITH CHECK (42501)
      const crossUserInsErr = await captureError(
        withTenant(poolApp, ORG_A, (c) =>
          c.query(
            `INSERT INTO users (id, org_id, email_normalized, password_hash, role) VALUES ('b1000009-0000-4000-8000-000000000088', '${ORG_B}', 'cross@example.com', 'h', 'member')`,
          ),
        ),
      );
      expect(errorCode(crossUserInsErr)).toBe('42501');
      expect((crossUserInsErr as Error).message).toMatch(/violates row-level security policy/i);

      // organizations: DELETE denied by privilege (42501)
      await expectSqlState(
        withTenant(poolApp, ORG_A, (c) =>
          c.query('DELETE FROM organizations WHERE id = $1', [ORG_A]),
        ),
        '42501',
      );

      // gateway_requests: DELETE denied by privilege (42501); immutable billing_period UPDATE fails with 23514
      await expectSqlState(
        withTenant(poolApp, ORG_A, (c) =>
          c.query('DELETE FROM gateway_requests WHERE request_id = $1', [REQ_A]),
        ),
        '42501',
      );
      await expectSqlState(
        withTenant(poolApp, ORG_A, (c) =>
          c.query("UPDATE gateway_requests SET billing_period = '2026-12' WHERE request_id = $1", [
            REQ_A,
          ]),
        ),
        '23514',
      );

      // provider_attempts: DELETE denied by privilege (42501); settled cost UPDATE fails with 23514 (chk_provider_attempts_settled_cost_immutable)
      await expectSqlState(
        withTenant(poolApp, ORG_A, (c) =>
          c.query('DELETE FROM provider_attempts WHERE attempt_id = $1', [ATT_A]),
        ),
        '42501',
      );
      await expectSqlState(
        withTenant(poolApp, ORG_A, (c) =>
          c.query(
            'UPDATE provider_attempts SET actual_cost_microdollars = 99999 WHERE attempt_id = $1',
            [ATT_A_SETTLED],
          ),
        ),
        '23514',
      );

      // provider_cost_adjustments: UPDATE/DELETE denied by privilege (42501); cross-tenant INSERT fails foreign-key parent isolation (23503)
      await expectSqlState(
        withTenant(poolApp, ORG_A, (c) =>
          c.query(
            'UPDATE provider_cost_adjustments SET delta_microdollars = 0 WHERE adjustment_id = $1',
            [ADJ_A],
          ),
        ),
        '42501',
      );
      await expectSqlState(
        withTenant(poolApp, ORG_A, (c) =>
          c.query('DELETE FROM provider_cost_adjustments WHERE adjustment_id = $1', [ADJ_A]),
        ),
        '42501',
      );
      const crossAdjErr = await captureError(
        withTenant(poolApp, ORG_A, (c) =>
          c.query(
            `INSERT INTO provider_cost_adjustments (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars, delta_microdollars, source, source_reference)
             VALUES ('50000003-0000-4000-8000-000000000076', $1, $2, 4500, 4200, -300, 'provider_usage', 'app-ref-76')`,
            [ATT_B_SETTLED, ORG_B],
          ),
        ),
      );
      expect(errorCode(crossAdjErr)).toBe('23503');
    });
  });
});
