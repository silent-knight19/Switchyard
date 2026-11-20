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
  type LoginRole,
} from './test/disposable-pg.js';

const FINANCIAL_TABLES = [
  'gateway_requests',
  'provider_attempts',
  'provider_cost_adjustments',
  'trace_payloads',
];

const ORG_A = '11111111-1111-4111-8111-111111111111';
const ORG_B = '22222222-2222-4222-8222-222222222222';
const VIRTUAL_KEY_A_ID = '66666666-6666-4666-8666-666666666667';
const VIRTUAL_KEY_A2_ID = '66666666-6666-4666-8666-666666666668';
const VIRTUAL_KEY_B_ID = '77777777-7777-4777-8777-777777777779';
const GATEWAY_INSTANCE_ID = '88888888-8888-4888-8888-888888888888';
const ADMITTED_NOV_2026 = '2026-11-15T12:00:00.000Z';

type ColumnInfo = {
  column_name: string;
  data_type: string;
  is_nullable: string;
  column_default: string | null;
  udt_name: string;
  is_generated: string;
  generation_expression: string | null;
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
    `SELECT column_name, data_type, is_nullable, column_default, udt_name, is_generated, generation_expression
     FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1`,
    [table],
  );
  return new Map(rows.map((row) => [row.column_name, row]));
}

describe('SW-1.3.3 financial and observability schema: constraints, FKs, generated columns, RLS', () => {
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
    fresh = await createDatabase('financial-schema');
    await migrate(fresh);
    pool = new pg.Pool({ connectionString: fresh.url });

    // Seed base organizations and virtual keys for tests
    await pool.query(
      `INSERT INTO organizations
         (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
       VALUES
         ($1, 'Org A', 10000000, 1, $3, $4, $5),
         ($2, 'Org B', 20000000, 1, $3, $4, $5)`,
      [ORG_A, ORG_B, Buffer.from('dek'), Buffer.from('iv'), Buffer.from('auth_tag')],
    );

    await pool.query(
      `INSERT INTO virtual_keys
         (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
       VALUES
         ($1, $2, 'key-a', 'sk-a-', $3, ARRAY['gpt-4o'], 60, 10000, 5),
         ($4, $2, 'key-a2', 'sk-a2-', $5, ARRAY['gpt-4o'], 60, 10000, 5),
         ($6, $7, 'key-b', 'sk-b-', $8, ARRAY['gpt-4o'], 60, 10000, 5)`,
      [
        VIRTUAL_KEY_A_ID,
        ORG_A,
        Buffer.from('hash_a'),
        VIRTUAL_KEY_A2_ID,
        Buffer.from('hash_a2'),
        VIRTUAL_KEY_B_ID,
        ORG_B,
        Buffer.from('hash_b'),
      ],
    );
  });

  afterAll(async () => {
    await pool?.end().catch(() => undefined);
    for (const database of databases) {
      await database.drop().catch(() => undefined);
    }
    await cluster?.stop();
  });

  describe('Structural assertions: table ownership, column types, nullability, generated expressions', () => {
    it('creates all four financial/observability tables owned by gateway_owner', async () => {
      const { rows } = await pool.query<{ relname: string; owner: string }>(
        `SELECT c.relname, pg_get_userbyid(c.relowner) AS owner
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname = ANY($1::text[])
         ORDER BY c.relname`,
        [FINANCIAL_TABLES],
      );
      expect(rows.map((r) => r.relname)).toEqual([...FINANCIAL_TABLES].sort());
      for (const row of rows) {
        expect(row.owner).toBe('gateway_owner');
      }
    });

    it('enforces required columns and types on gateway_requests', async () => {
      const cols = await columnInfo(pool, 'gateway_requests');

      const expectedTypes: Record<string, string> = {
        request_id: 'uuid',
        org_id: 'uuid',
        virtual_key_id: 'uuid',
        gateway_instance_id: 'uuid',
        gateway_epoch: 'bigint',
        requested_model: 'text',
        billing_period: 'text',
        status: 'text',
        final_provider: 'text',
        final_model: 'text',
        attempt_count: 'integer',
        cache_status: 'text',
        http_status: 'integer',
        ttft_ms: 'integer',
        total_latency_ms: 'integer',
        pii_redacted_count: 'integer',
        error_code: 'text',
        admitted_at: 'timestamp with time zone',
        deadline_at: 'timestamp with time zone',
        created_at: 'timestamp with time zone',
        finalized_at: 'timestamp with time zone',
      };

      for (const [col, type] of Object.entries(expectedTypes)) {
        expect(cols.get(col)?.data_type, `gateway_requests.${col} type`).toBe(type);
      }

      for (const col of [
        'request_id',
        'org_id',
        'virtual_key_id',
        'gateway_instance_id',
        'gateway_epoch',
        'requested_model',
        'billing_period',
        'status',
        'attempt_count',
        'cache_status',
        'pii_redacted_count',
        'admitted_at',
        'deadline_at',
        'created_at',
      ]) {
        expect(cols.get(col)?.is_nullable, `gateway_requests.${col} must be NOT NULL`).toBe('NO');
      }

      for (const col of [
        'final_provider',
        'final_model',
        'http_status',
        'ttft_ms',
        'total_latency_ms',
        'error_code',
        'finalized_at',
      ]) {
        expect(cols.get(col)?.is_nullable, `gateway_requests.${col} must be nullable`).toBe('YES');
      }
    });

    it('enforces required columns, types, and generated effective_cost on provider_attempts', async () => {
      const cols = await columnInfo(pool, 'provider_attempts');

      const expectedTypes: Record<string, string> = {
        attempt_id: 'uuid',
        request_id: 'uuid',
        org_id: 'uuid',
        virtual_key_id: 'uuid',
        attempt_number: 'integer',
        gateway_instance_id: 'uuid',
        gateway_epoch: 'bigint',
        billing_period: 'text',
        provider: 'text',
        model: 'text',
        sanitized_fields: 'ARRAY',
        status: 'text',
        outcome: 'text',
        tokens_in: 'integer',
        tokens_out: 'integer',
        duration_ms: 'integer',
        http_status: 'integer',
        estimated_cost_microdollars: 'bigint',
        actual_cost_microdollars: 'bigint',
        effective_cost_microdollars: 'bigint',
        cost_status: 'text',
        admitted_at: 'timestamp with time zone',
        hard_deadline_at: 'timestamp with time zone',
        settled_at: 'timestamp with time zone',
        created_at: 'timestamp with time zone',
      };

      for (const [col, type] of Object.entries(expectedTypes)) {
        expect(cols.get(col)?.data_type, `provider_attempts.${col} type`).toBe(type);
      }

      for (const col of [
        'attempt_id',
        'request_id',
        'org_id',
        'virtual_key_id',
        'attempt_number',
        'gateway_instance_id',
        'gateway_epoch',
        'billing_period',
        'provider',
        'model',
        'sanitized_fields',
        'status',
        'estimated_cost_microdollars',
        'cost_status',
        'admitted_at',
        'hard_deadline_at',
        'created_at',
      ]) {
        expect(cols.get(col)?.is_nullable, `provider_attempts.${col} must be NOT NULL`).toBe('NO');
      }

      for (const col of [
        'outcome',
        'tokens_in',
        'tokens_out',
        'duration_ms',
        'http_status',
        'actual_cost_microdollars',
        'settled_at',
      ]) {
        expect(cols.get(col)?.is_nullable, `provider_attempts.${col} must be nullable`).toBe('YES');
      }

      // Generated column verification
      const effCol = cols.get('effective_cost_microdollars');
      expect(effCol?.is_generated).toBe('ALWAYS');
      expect(effCol?.generation_expression).toContain(
        'COALESCE(actual_cost_microdollars, estimated_cost_microdollars)',
      );
    });

    it('enforces required columns and types on provider_cost_adjustments', async () => {
      const cols = await columnInfo(pool, 'provider_cost_adjustments');

      expect(cols.get('adjustment_id')?.data_type).toBe('uuid');
      expect(cols.get('attempt_id')?.data_type).toBe('uuid');
      expect(cols.get('org_id')?.data_type).toBe('uuid');
      expect(cols.get('previous_cost_microdollars')?.data_type).toBe('bigint');
      expect(cols.get('corrected_cost_microdollars')?.data_type).toBe('bigint');
      expect(cols.get('delta_microdollars')?.data_type).toBe('bigint');
      expect(cols.get('source')?.data_type).toBe('text');
      expect(cols.get('source_reference')?.data_type).toBe('text');
      expect(cols.get('created_at')?.data_type).toBe('timestamp with time zone');

      for (const col of [
        'adjustment_id',
        'attempt_id',
        'org_id',
        'previous_cost_microdollars',
        'corrected_cost_microdollars',
        'delta_microdollars',
        'source',
        'created_at',
      ]) {
        expect(cols.get(col)?.is_nullable, `provider_cost_adjustments.${col} NOT NULL`).toBe('NO');
      }

      expect(cols.get('source_reference')?.is_nullable).toBe('YES');
    });

    it('enforces required columns and types on trace_payloads', async () => {
      const cols = await columnInfo(pool, 'trace_payloads');

      expect(cols.get('request_id')?.data_type).toBe('uuid');
      expect(cols.get('org_id')?.data_type).toBe('uuid');
      expect(cols.get('request_body')?.data_type).toBe('jsonb');
      expect(cols.get('response_text')?.data_type).toBe('text');
      expect(cols.get('truncated')?.data_type).toBe('boolean');
      expect(cols.get('expires_at')?.data_type).toBe('timestamp with time zone');

      for (const col of ['request_id', 'org_id', 'truncated', 'expires_at']) {
        expect(cols.get(col)?.is_nullable, `trace_payloads.${col} NOT NULL`).toBe('NO');
      }

      for (const col of ['request_body', 'response_text']) {
        expect(cols.get(col)?.is_nullable, `trace_payloads.${col} nullable`).toBe('YES');
      }
    });

    it('creates all architecture-mandated indexes with expected shapes', async () => {
      const { rows } = await pool.query<{
        tablename: string;
        indexname: string;
        indexdef: string;
      }>(
        `SELECT tablename, indexname, indexdef
         FROM pg_indexes
         WHERE schemaname = 'public' AND tablename = ANY($1::text[])
         ORDER BY indexname`,
        [FINANCIAL_TABLES],
      );

      const byName = new Map(rows.map((r) => [r.indexname, r]));

      // 1. gateway_requests keyset pagination index
      const reqPagination = byName.get('idx_gateway_requests_org_pagination');
      expect(reqPagination, 'idx_gateway_requests_org_pagination must exist').toBeDefined();
      expect(reqPagination?.indexdef).toContain('(org_id, created_at DESC, request_id DESC)');

      // 2. provider_attempts billing index
      const attemptBilling = byName.get('idx_provider_attempts_billing');
      expect(attemptBilling, 'idx_provider_attempts_billing must exist').toBeDefined();
      expect(attemptBilling?.indexdef).toContain('(org_id, billing_period, created_at DESC)');

      // 3. provider_attempts stale reserved partial index
      const staleReserved = byName.get('idx_provider_attempts_stale_reserved');
      expect(staleReserved, 'idx_provider_attempts_stale_reserved must exist').toBeDefined();
      expect(staleReserved?.indexdef).toContain('(hard_deadline_at)');
      expect(staleReserved?.indexdef).toContain("WHERE (status = 'reserved'::text)");

      // 4. provider_cost_adjustments source_ref unique partial index
      const adjRef = byName.get('uq_provider_cost_adjustments_source_ref');
      expect(adjRef, 'uq_provider_cost_adjustments_source_ref must exist').toBeDefined();
      expect(adjRef?.indexdef).toContain('UNIQUE INDEX');
      expect(adjRef?.indexdef).toContain('(attempt_id, source, source_reference)');
      expect(adjRef?.indexdef).toContain('WHERE (source_reference IS NOT NULL)');

      // 5. trace_payloads retention index
      const traceRetention = byName.get('idx_trace_payloads_retention');
      expect(traceRetention, 'idx_trace_payloads_retention must exist').toBeDefined();
      expect(traceRetention?.indexdef).toContain('(expires_at)');

      // 6. provider_cost_adjustments general attempt and org index
      const adjAttempt = byName.get('idx_provider_cost_adjustments_attempt');
      expect(adjAttempt, 'idx_provider_cost_adjustments_attempt must exist').toBeDefined();
      expect(adjAttempt?.indexdef).toContain('(attempt_id, org_id)');
    });

    it('verifies catalog foreign key definitions, unique attribution, and check constraints (DB-17, DB-18, DB-19)', async () => {
      // 1. Verify foreign key fk_provider_attempts_request references all 4 columns: (request_id, org_id, virtual_key_id, billing_period)
      const { rows: fkRows } = await pool.query<{
        conname: string;
        child_table: string;
        parent_table: string;
        child_cols: string[];
        parent_cols: string[];
      }>(
        `SELECT
           c.conname,
           cl.relname AS child_table,
           cr.relname AS parent_table,
           array_to_json(ARRAY(
             SELECT a.attname
             FROM unnest(c.conkey) k
             JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k
           )) AS child_cols,
           array_to_json(ARRAY(
             SELECT a.attname
             FROM unnest(c.confkey) k
             JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k
           )) AS parent_cols
         FROM pg_constraint c
         JOIN pg_class cl ON cl.oid = c.conrelid
         JOIN pg_class cr ON cr.oid = c.confrelid
         WHERE c.conname = 'fk_provider_attempts_request'`,
      );

      expect(fkRows).toHaveLength(1);
      expect(fkRows[0]?.child_table).toBe('provider_attempts');
      expect(fkRows[0]?.parent_table).toBe('gateway_requests');
      expect(fkRows[0]?.child_cols).toEqual([
        'request_id',
        'org_id',
        'virtual_key_id',
        'billing_period',
      ]);
      expect(fkRows[0]?.parent_cols).toEqual([
        'request_id',
        'org_id',
        'virtual_key_id',
        'billing_period',
      ]);

      // 2. Verify unique attribution constraint on gateway_requests
      const { rows: uqRows } = await pool.query<{
        conname: string;
        cols: string[];
      }>(
        `SELECT
           c.conname,
           array_to_json(ARRAY(
             SELECT a.attname
             FROM unnest(c.conkey) k
             JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k
           )) AS cols
         FROM pg_constraint c
         JOIN pg_class cl ON cl.oid = c.conrelid
         WHERE cl.relname = 'gateway_requests' AND c.conname = 'uq_gateway_requests_attribution'`,
      );

      expect(uqRows).toHaveLength(1);
      expect(uqRows[0]?.cols).toEqual(['request_id', 'org_id', 'virtual_key_id', 'billing_period']);

      // 3. Verify check constraint on provider_attempts for cost_status consistency (DB-18)
      const { rows: chkRows } = await pool.query<{
        conname: string;
        definition: string;
      }>(
        `SELECT c.conname, pg_get_constraintdef(c.oid) AS definition
         FROM pg_constraint c
         JOIN pg_class cl ON cl.oid = c.conrelid
         WHERE cl.relname = 'provider_attempts' AND c.conname = 'chk_provider_attempts_cost_status'`,
      );

      expect(chkRows).toHaveLength(1);
      expect(chkRows[0]?.definition).toContain("cost_status = 'estimated'::text");
      expect(chkRows[0]?.definition).toContain('actual_cost_microdollars IS NULL');
      expect(chkRows[0]?.definition).toContain("cost_status = 'confirmed'::text");
      expect(chkRows[0]?.definition).toContain('actual_cost_microdollars IS NOT NULL');
    });

    it('enables and forces RLS on all four tables with zero permissive policies', async () => {
      const { rows } = await pool.query<{
        relname: string;
        rls: boolean;
        forced: boolean;
      }>(
        `SELECT relname, relrowsecurity AS rls, relforcerowsecurity AS forced
         FROM pg_class
         WHERE relname = ANY($1::text[])`,
        [FINANCIAL_TABLES],
      );

      for (const row of rows) {
        expect(row.rls, `${row.relname} RLS must be enabled`).toBe(true);
        expect(row.forced, `${row.relname} RLS must be forced`).toBe(true);
      }

      const { rows: policies } = await pool.query<{ tablename: string; policyname: string }>(
        `SELECT tablename, policyname
         FROM pg_policies
         WHERE schemaname = 'public' AND tablename = ANY($1::text[])
         ORDER BY tablename`,
        [FINANCIAL_TABLES],
      );
      expect(policies).toEqual([
        { tablename: 'gateway_requests', policyname: 'gateway_requests_tenant_isolation' },
        { tablename: 'provider_attempts', policyname: 'provider_attempts_tenant_isolation' },
        {
          tablename: 'provider_cost_adjustments',
          policyname: 'provider_cost_adjustments_tenant_isolation',
        },
        { tablename: 'trace_payloads', policyname: 'trace_payloads_tenant_isolation' },
      ]);
    });

    it('revokes all permissions on the four tables from PUBLIC', async () => {
      const { rows } = await pool.query<{ relname: string; count: number }>(
        `SELECT c.relname, count(acl.*)::int AS count
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         LEFT JOIN LATERAL aclexplode(c.relacl) acl ON acl.grantee = 0
         WHERE n.nspname = 'public' AND c.relname = ANY($1::text[])
         GROUP BY c.relname`,
        [FINANCIAL_TABLES],
      );
      for (const row of rows) {
        expect(row.count, `${row.relname} must have 0 PUBLIC privileges`).toBe(0);
      }
    });
  });

  describe('Positive execution: request lifecycle, generated effective cost, adjustment calculation, trace payload', () => {
    const REQUEST_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    const ATTEMPT_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
    const ADJUSTMENT_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

    it('inserts a logical gateway request with valid fields', async () => {
      const { rowCount } = await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $5, $5::timestamptz + interval '30 seconds')`,
        [REQUEST_ID, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, ADMITTED_NOV_2026],
      );
      expect(rowCount).toBe(1);

      const { rows } = await pool.query<{
        request_id: string;
        attempt_count: number;
        pii_redacted_count: number;
        status: string;
      }>(
        'SELECT request_id, attempt_count, pii_redacted_count, status FROM gateway_requests WHERE request_id = $1',
        [REQUEST_ID],
      );
      expect(rows[0]?.request_id).toBe(REQUEST_ID);
      expect(rows[0]?.attempt_count).toBe(0);
      expect(rows[0]?.pii_redacted_count).toBe(0);
      expect(rows[0]?.status).toBe('in_progress');
    });

    it('inserts a reserved provider attempt and generates effective cost from estimated cost', async () => {
      const { rowCount } = await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
            cost_status, hard_deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, $5, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 5000,
            'estimated', clock_timestamp() + interval '30 seconds')`,
        [ATTEMPT_ID, REQUEST_ID, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
      );
      expect(rowCount).toBe(1);

      const { rows } = await pool.query<{
        estimated: string;
        actual: string | null;
        effective: string;
        status: string;
      }>(
        `SELECT estimated_cost_microdollars::text AS estimated,
                actual_cost_microdollars::text AS actual,
                effective_cost_microdollars::text AS effective,
                status
         FROM provider_attempts WHERE attempt_id = $1`,
        [ATTEMPT_ID],
      );
      expect(rows[0]?.estimated).toBe('5000');
      expect(rows[0]?.actual).toBeNull();
      expect(rows[0]?.effective).toBe('5000');
      expect(rows[0]?.status).toBe('reserved');
    });

    it('settles the attempt with actual cost and updates effective cost automatically', async () => {
      const { rowCount } = await pool.query(
        `UPDATE provider_attempts
         SET status = 'settled',
             outcome = 'completed',
             actual_cost_microdollars = 4200,
             cost_status = 'confirmed',
             tokens_in = 100,
             tokens_out = 50,
             duration_ms = 450,
             http_status = 200,
             settled_at = clock_timestamp()
         WHERE attempt_id = $1`,
        [ATTEMPT_ID],
      );
      expect(rowCount).toBe(1);

      const { rows } = await pool.query<{
        estimated: string;
        actual: string | null;
        effective: string;
        cost_status: string;
      }>(
        `SELECT estimated_cost_microdollars::text AS estimated,
                actual_cost_microdollars::text AS actual,
                effective_cost_microdollars::text AS effective,
                cost_status
         FROM provider_attempts WHERE attempt_id = $1`,
        [ATTEMPT_ID],
      );
      expect(rows[0]?.estimated).toBe('5000');
      expect(rows[0]?.actual).toBe('4200');
      expect(rows[0]?.effective).toBe('4200');
      expect(rows[0]?.cost_status).toBe('confirmed');
    });

    it('inserts a cost adjustment with mathematically consistent delta', async () => {
      const { rowCount } = await pool.query(
        `INSERT INTO provider_cost_adjustments
           (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
            delta_microdollars, source, source_reference)
         VALUES
           ($1, $2, $3, 4200, 3900, -300, 'provider_invoice', 'inv_nov_001')`,
        [ADJUSTMENT_ID, ATTEMPT_ID, ORG_A],
      );
      expect(rowCount).toBe(1);

      const { rows } = await pool.query<{
        previous: string;
        corrected: string;
        delta: string;
        source: string;
        source_ref: string;
      }>(
        `SELECT previous_cost_microdollars::text AS previous,
                corrected_cost_microdollars::text AS corrected,
                delta_microdollars::text AS delta,
                source,
                source_reference AS source_ref
         FROM provider_cost_adjustments WHERE adjustment_id = $1`,
        [ADJUSTMENT_ID],
      );
      expect(rows[0]?.previous).toBe('4200');
      expect(rows[0]?.corrected).toBe('3900');
      expect(rows[0]?.delta).toBe('-300');
      expect(rows[0]?.source).toBe('provider_invoice');
      expect(rows[0]?.source_ref).toBe('inv_nov_001');
    });

    it('allows multiple cost adjustments when source_reference is NULL', async () => {
      const adjNull1 = 'cccccccc-cccc-4ccc-8ccc-cccccccccc01';
      const adjNull2 = 'cccccccc-cccc-4ccc-8ccc-cccccccccc02';

      await pool.query(
        `INSERT INTO provider_cost_adjustments
           (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
            delta_microdollars, source, source_reference)
         VALUES
           ($1, $2, $3, 3900, 3950, 50, 'manual_review', NULL),
           ($4, $2, $3, 3950, 4000, 50, 'manual_review', NULL)`,
        [adjNull1, ATTEMPT_ID, ORG_A, adjNull2],
      );

      const { rows } = await pool.query<{ count: number }>(
        `SELECT count(*)::int AS count FROM provider_cost_adjustments WHERE attempt_id = $1 AND source_reference IS NULL`,
        [ATTEMPT_ID],
      );
      expect(rows[0]?.count).toBe(2);
    });

    it('inserts a trace payload linked to the gateway request', async () => {
      const payload = { prompt: 'hello world', temperature: 0.7 };
      const { rowCount } = await pool.query(
        `INSERT INTO trace_payloads
           (request_id, org_id, request_body, response_text, truncated, expires_at)
         VALUES
           ($1, $2, $3, 'sample response', false, clock_timestamp() + interval '7 days')`,
        [REQUEST_ID, ORG_A, JSON.stringify(payload)],
      );
      expect(rowCount).toBe(1);

      const { rows } = await pool.query<{
        request_id: string;
        body: { prompt: string; temperature: number };
        response_text: string;
        truncated: boolean;
      }>(
        'SELECT request_id, request_body AS body, response_text, truncated FROM trace_payloads WHERE request_id = $1',
        [REQUEST_ID],
      );
      expect(rows[0]?.request_id).toBe(REQUEST_ID);
      expect(rows[0]?.body.prompt).toBe('hello world');
      expect(rows[0]?.response_text).toBe('sample response');
      expect(rows[0]?.truncated).toBe(false);
    });

    it('DB-18: confirmed zero cost succeeds when actual_cost_microdollars is explicitly zero', async () => {
      const reqZero = '11111111-2222-4333-8444-555555555555';
      const attZero = '66666666-7777-4888-8999-000000000000';

      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'completed', 'miss', $5, $5::timestamptz + interval '30 seconds')`,
        [reqZero, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, ADMITTED_NOV_2026],
      );

      const { rowCount } = await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, outcome, estimated_cost_microdollars,
            actual_cost_microdollars, cost_status, hard_deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, $5, 1, '2026-11', 'openai', 'gpt-4o', 'settled', 'completed', 5000,
            0, 'confirmed', clock_timestamp() + interval '30 seconds')`,
        [attZero, reqZero, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
      );
      expect(rowCount).toBe(1);

      const { rows } = await pool.query<{
        actual: string;
        effective: string;
        cost_status: string;
      }>(
        `SELECT actual_cost_microdollars::text AS actual,
                effective_cost_microdollars::text AS effective,
                cost_status
         FROM provider_attempts WHERE attempt_id = $1`,
        [attZero],
      );
      expect(rows[0]?.actual).toBe('0');
      expect(rows[0]?.effective).toBe('0');
      expect(rows[0]?.cost_status).toBe('confirmed');
    });

    it('DB-17: month-boundary request preserves request billing period across month rollover', async () => {
      const reqBoundary = 'aaaa1111-bbbb-4ccc-8ddd-eeeeffff0001';
      const attBoundary = 'aaaa1111-bbbb-4ccc-8ddd-eeeeffff0002';

      // Request admitted on the last second of November UTC
      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss',
            '2026-11-30 23:59:59.999+00'::timestamptz, '2026-12-01 00:00:30.000+00'::timestamptz)`,
        [reqBoundary, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
      );

      // Attempt admitted 5 seconds into December UTC must inherit the request's original '2026-11' period
      const { rowCount } = await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
            cost_status, admitted_at, hard_deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, $5, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 5000,
            'estimated', '2026-12-01 00:00:05.000+00'::timestamptz, '2026-12-01 00:00:30.000+00'::timestamptz)`,
        [attBoundary, reqBoundary, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
      );
      expect(rowCount).toBe(1);

      const { rows } = await pool.query<{ billing_period: string }>(
        'SELECT billing_period FROM provider_attempts WHERE attempt_id = $1',
        [attBoundary],
      );
      expect(rows[0]?.billing_period).toBe('2026-11');
    });

    it('DB-19: same-org matching virtual-key attribution succeeds', async () => {
      const reqKey2 = 'aaaa2222-bbbb-4ccc-8ddd-eeeeffff0001';
      const attKey2 = 'aaaa2222-bbbb-4ccc-8ddd-eeeeffff0002';

      // Request using second virtual key of Org A
      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $5, $5::timestamptz + interval '30 seconds')`,
        [reqKey2, ORG_A, VIRTUAL_KEY_A2_ID, GATEWAY_INSTANCE_ID, ADMITTED_NOV_2026],
      );

      // Attempt matching Org A and second virtual key
      const { rowCount } = await pool.query(
        `INSERT INTO provider_attempts
           (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
            gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
            cost_status, hard_deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, $5, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 3000,
            'estimated', clock_timestamp() + interval '30 seconds')`,
        [attKey2, reqKey2, ORG_A, VIRTUAL_KEY_A2_ID, GATEWAY_INSTANCE_ID],
      );
      expect(rowCount).toBe(1);
    });
  });

  describe('Negative constraint & cross-tenant referential integrity tests (exact SQLSTATEs)', () => {
    const REQUEST_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    const ATTEMPT_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

    it('rejects cross-tenant FK: gateway_requests for Org A referencing Virtual Key of Org B (23503)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO gateway_requests
             (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
              billing_period, status, cache_status, admitted_at, deadline_at)
           VALUES
             ('11111111-aaaa-4aaa-8aaa-aaaaaaaaaaaa', $1, $2, $3, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $4, $4::timestamptz + interval '30 seconds')`,
          [ORG_A, VIRTUAL_KEY_B_ID, GATEWAY_INSTANCE_ID, ADMITTED_NOV_2026], // Org A with Virtual Key of Org B
        ),
        '23503',
      );
    });

    it('rejects cross-tenant FK: provider_attempts for Org B referencing Request of Org A (23503)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              cost_status, hard_deadline_at)
           VALUES
             ('22222222-bbbb-4bbb-8bbb-bbbbbbbbbbbb', $1, $2, $3, 2, $4, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 1000,
              'estimated', clock_timestamp())`,
          [REQUEST_ID, ORG_B, VIRTUAL_KEY_B_ID, GATEWAY_INSTANCE_ID], // Org B referencing Request of Org A
        ),
        '23503',
      );
    });

    it('rejects cross-tenant FK: provider_attempts for Org A referencing Virtual Key of Org B (23503)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              cost_status, hard_deadline_at)
           VALUES
             ('33333333-bbbb-4bbb-8bbb-bbbbbbbbbbbb', $1, $2, $3, 3, $4, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 1000,
              'estimated', clock_timestamp())`,
          [REQUEST_ID, ORG_A, VIRTUAL_KEY_B_ID, GATEWAY_INSTANCE_ID], // Org A request referencing Org B virtual key
        ),
        '23503',
      );
    });

    it('rejects cross-tenant FK: provider_cost_adjustments for Org B referencing Attempt of Org A (23503)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_cost_adjustments
             (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
              delta_microdollars, source, source_reference)
           VALUES
             ('44444444-cccc-4ccc-8ccc-cccccccccccc', $1, $2, 4200, 4000, -200, 'manual_review', NULL)`,
          [ATTEMPT_ID, ORG_B], // Org B referencing Attempt of Org A
        ),
        '23503',
      );
    });

    it('rejects cross-tenant FK: trace_payloads for Org B referencing Request of Org A (23503)', async () => {
      const reqCross = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $5, $5::timestamptz + interval '30 seconds')`,
        [reqCross, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, ADMITTED_NOV_2026],
      );

      await expectSqlState(
        pool.query(
          `INSERT INTO trace_payloads
             (request_id, org_id, expires_at)
           VALUES
             ($1, $2, clock_timestamp() + interval '7 days')`,
          [reqCross, ORG_B], // Org B referencing Request of Org A
        ),
        '23503',
      );
    });

    // DB-17 tests: Parent-child billing-period inheritance
    it('DB-17: rejects mismatched billing_period between attempt and request (23503)', async () => {
      // REQUEST_ID was admitted with billing_period = '2026-11'. Specifying '2026-12' fails closed with 23503.
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              cost_status, hard_deadline_at)
           VALUES
             ('22222222-1111-4bbb-8bbb-bbbbbbbbbbbb', $1, $2, $3, 20, $4, 1, '2026-12', 'openai', 'gpt-4o', 'reserved', 1000,
              'estimated', clock_timestamp())`,
          [REQUEST_ID, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
        ),
        '23503',
      );
    });

    it('DB-17: month-boundary mismatch fails when attempt tries to advance period to next month (23503)', async () => {
      const reqBoundaryFail = 'aaaa3333-bbbb-4ccc-8ddd-eeeeffff0001';
      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss',
            '2026-11-30 23:59:59.000+00'::timestamptz, '2026-12-01 00:00:30.000+00'::timestamptz)`,
        [reqBoundaryFail, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
      );

      // Attempt attempts to claim '2026-12' instead of inheriting request's '2026-11'
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              cost_status, admitted_at, hard_deadline_at)
           VALUES
             ('aaaa3333-bbbb-4ccc-8ddd-eeeeffff0002', $1, $2, $3, 1, $4, 1, '2026-12', 'openai', 'gpt-4o', 'reserved', 1000,
              'estimated', '2026-12-01 00:00:05.000+00'::timestamptz, '2026-12-01 00:00:30.000+00'::timestamptz)`,
          [reqBoundaryFail, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
        ),
        '23503',
      );
    });

    // DB-18 tests: Cost-status consistency
    it('DB-18: rejects actual_cost_microdollars=NULL with cost_status="confirmed" (23514)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              actual_cost_microdollars, cost_status, hard_deadline_at)
           VALUES
             (gen_random_uuid(), $1, $2, $3, 21, $4, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 1000,
              NULL, 'confirmed', clock_timestamp())`,
          [REQUEST_ID, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
        ),
        '23514',
      );
    });

    it('DB-18: rejects non-NULL actual_cost_microdollars with cost_status="estimated" (23514)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              actual_cost_microdollars, cost_status, hard_deadline_at)
           VALUES
             (gen_random_uuid(), $1, $2, $3, 22, $4, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 1000,
              500, 'estimated', clock_timestamp())`,
          [REQUEST_ID, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
        ),
        '23514',
      );
    });

    // DB-19 tests: Virtual-key attribution
    it('DB-19: rejects same-org wrong virtual_key_id in provider_attempts (23503)', async () => {
      // REQUEST_ID was admitted with VIRTUAL_KEY_A_ID. Attempt uses VIRTUAL_KEY_A2_ID (both belong to ORG_A).
      // Fails with 23503 because attempt must match parent request's virtual key.
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              cost_status, hard_deadline_at)
           VALUES
             ('22222222-3333-4bbb-8bbb-bbbbbbbbbbbb', $1, $2, $3, 23, $4, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 1000,
              'estimated', clock_timestamp())`,
          [REQUEST_ID, ORG_A, VIRTUAL_KEY_A2_ID, GATEWAY_INSTANCE_ID],
        ),
        '23503',
      );
    });

    it('rejects duplicate attempt number for the same request (23505)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              cost_status, hard_deadline_at)
           VALUES
             ('55555555-bbbb-4bbb-8bbb-bbbbbbbbbbbb', $1, $2, $3, 1, $4, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 1000,
              'estimated', clock_timestamp())`,
          [REQUEST_ID, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID], // attempt_number 1 already exists for REQUEST_ID
        ),
        '23505',
      );
    });

    it('rejects duplicate adjustment for the same attempt, source, and non-null reference (23505)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_cost_adjustments
             (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
              delta_microdollars, source, source_reference)
           VALUES
             ('66666666-cccc-4ccc-8ccc-cccccccccccc', $1, $2, 4200, 3900, -300, 'provider_invoice', 'inv_nov_001')`,
          [ATTEMPT_ID, ORG_A], // 'inv_nov_001' already inserted for ATTEMPT_ID and 'provider_invoice'
        ),
        '23505',
      );
    });

    it('rejects invalid billing_period format (23514)', async () => {
      for (const badPeriod of ['2026-13', '2026-00', '2026', '2026-1', '2026/11', 'invalid']) {
        await expectSqlState(
          pool.query(
            `INSERT INTO gateway_requests
               (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
                billing_period, status, cache_status, admitted_at, deadline_at)
             VALUES
               (gen_random_uuid(), $1, $2, $3, 1, 'gpt-4o', $4, 'in_progress', 'miss', $5, $5::timestamptz + interval '30 seconds')`,
            [ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, badPeriod, ADMITTED_NOV_2026],
          ),
          '23514',
        );
      }
    });

    it('rejects invalid status in gateway_requests (23514)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO gateway_requests
             (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
              billing_period, status, cache_status, admitted_at, deadline_at)
           VALUES
             (gen_random_uuid(), $1, $2, $3, 1, 'gpt-4o', '2026-11', 'pending', 'miss', $4, $4::timestamptz + interval '30 seconds')`,
          [ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, ADMITTED_NOV_2026],
        ),
        '23514',
      );
    });

    it('rejects invalid cache_status in gateway_requests (23514)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO gateway_requests
             (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
              billing_period, status, cache_status, admitted_at, deadline_at)
           VALUES
             (gen_random_uuid(), $1, $2, $3, 1, 'gpt-4o', '2026-11', 'in_progress', 'hit', $4, $4::timestamptz + interval '30 seconds')`,
          [ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, ADMITTED_NOV_2026],
        ),
        '23514',
      );
    });

    it('rejects negative counters and latencies in gateway_requests (23514)', async () => {
      // negative attempt_count
      await expectSqlState(
        pool.query(
          `INSERT INTO gateway_requests
             (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
              billing_period, status, cache_status, admitted_at, deadline_at, attempt_count)
           VALUES
             (gen_random_uuid(), $1, $2, $3, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $4, $4::timestamptz + interval '30 seconds', -1)`,
          [ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, ADMITTED_NOV_2026],
        ),
        '23514',
      );

      // negative ttft_ms
      await expectSqlState(
        pool.query(
          `INSERT INTO gateway_requests
             (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
              billing_period, status, cache_status, admitted_at, deadline_at, ttft_ms)
           VALUES
             (gen_random_uuid(), $1, $2, $3, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $4, $4::timestamptz + interval '30 seconds', -1)`,
          [ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, ADMITTED_NOV_2026],
        ),
        '23514',
      );

      // out-of-range http_status
      await expectSqlState(
        pool.query(
          `INSERT INTO gateway_requests
             (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
              billing_period, status, cache_status, admitted_at, deadline_at, http_status)
           VALUES
             (gen_random_uuid(), $1, $2, $3, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $4, $4::timestamptz + interval '30 seconds', 99)`,
          [ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, ADMITTED_NOV_2026],
        ),
        '23514',
      );
    });

    it('rejects attempt_number < 1 in provider_attempts (23514)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              cost_status, hard_deadline_at)
           VALUES
             (gen_random_uuid(), $1, $2, $3, 0, $4, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 1000,
              'estimated', clock_timestamp())`,
          [REQUEST_ID, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
        ),
        '23514',
      );
    });

    it('rejects invalid status and outcome in provider_attempts (23514)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              cost_status, hard_deadline_at)
           VALUES
             (gen_random_uuid(), $1, $2, $3, 10, $4, 1, '2026-11', 'openai', 'gpt-4o', 'done', 1000,
              'estimated', clock_timestamp())`,
          [REQUEST_ID, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
        ),
        '23514',
      );

      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, outcome, estimated_cost_microdollars,
              cost_status, hard_deadline_at)
           VALUES
             (gen_random_uuid(), $1, $2, $3, 11, $4, 1, '2026-11', 'openai', 'gpt-4o', 'settled', 'success', 1000,
              'confirmed', clock_timestamp())`,
          [REQUEST_ID, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
        ),
        '23514',
      );
    });

    it('rejects negative monetary amounts in provider_attempts (23514)', async () => {
      // negative estimated cost
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              cost_status, hard_deadline_at)
           VALUES
             (gen_random_uuid(), $1, $2, $3, 12, $4, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', -100,
              'estimated', clock_timestamp())`,
          [REQUEST_ID, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
        ),
        '23514',
      );

      // negative actual cost
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              actual_cost_microdollars, cost_status, hard_deadline_at)
           VALUES
             (gen_random_uuid(), $1, $2, $3, 13, $4, 1, '2026-11', 'openai', 'gpt-4o', 'settled', 1000,
              -50, 'confirmed', clock_timestamp())`,
          [REQUEST_ID, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
        ),
        '23514',
      );
    });

    it('rejects direct write to generated column effective_cost_microdollars (428C9)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_attempts
             (attempt_id, request_id, org_id, virtual_key_id, attempt_number, gateway_instance_id,
              gateway_epoch, billing_period, provider, model, status, estimated_cost_microdollars,
              effective_cost_microdollars, cost_status, hard_deadline_at)
           VALUES
             (gen_random_uuid(), $1, $2, $3, 14, $4, 1, '2026-11', 'openai', 'gpt-4o', 'reserved', 1000,
              9999, 'estimated', clock_timestamp())`,
          [REQUEST_ID, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID],
        ),
        '428C9',
      );

      await expectSqlState(
        pool.query(
          `UPDATE provider_attempts SET effective_cost_microdollars = 9999 WHERE attempt_id = $1`,
          [ATTEMPT_ID],
        ),
        '428C9',
      );
    });

    it('rejects mismatched delta in provider_cost_adjustments (23514)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_cost_adjustments
             (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
              delta_microdollars, source, source_reference)
           VALUES
             (gen_random_uuid(), $1, $2, 4000, 3500, 500, 'manual_review', NULL)`, // delta should be -500, not +500
          [ATTEMPT_ID, ORG_A],
        ),
        '23514',
      );

      await expectSqlState(
        pool.query(
          `INSERT INTO provider_cost_adjustments
             (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
              delta_microdollars, source, source_reference)
           VALUES
             (gen_random_uuid(), $1, $2, 4000, 3500, 0, 'manual_review', NULL)`, // delta is 0 instead of -500
          [ATTEMPT_ID, ORG_A],
        ),
        '23514',
      );
    });

    it('rejects invalid source in provider_cost_adjustments (23514)', async () => {
      await expectSqlState(
        pool.query(
          `INSERT INTO provider_cost_adjustments
             (adjustment_id, attempt_id, org_id, previous_cost_microdollars, corrected_cost_microdollars,
              delta_microdollars, source, source_reference)
           VALUES
             (gen_random_uuid(), $1, $2, 4000, 3500, -500, 'external_audit', NULL)`,
          [ATTEMPT_ID, ORG_A],
        ),
        '23514',
      );
    });

    it('enforces ON DELETE RESTRICT on financial hierarchy and ON DELETE CASCADE on trace payloads', async () => {
      // 1. Attempting to delete organizations(id) when gateway_requests exists fails with 23503
      await expectSqlState(pool.query('DELETE FROM organizations WHERE id = $1', [ORG_A]), '23503');

      // 2. Attempting to delete virtual_keys(id, org_id) when gateway_requests exists fails with 23503
      await expectSqlState(
        pool.query('DELETE FROM virtual_keys WHERE id = $1 AND org_id = $2', [
          VIRTUAL_KEY_A_ID,
          ORG_A,
        ]),
        '23503',
      );

      // 3. Attempting to delete gateway_requests when provider_attempts exists fails with 23503
      await expectSqlState(
        pool.query('DELETE FROM gateway_requests WHERE request_id = $1', [REQUEST_ID]),
        '23503',
      );

      // 4. Attempting to delete provider_attempts when provider_cost_adjustments exists fails with 23503
      await expectSqlState(
        pool.query('DELETE FROM provider_attempts WHERE attempt_id = $1', [ATTEMPT_ID]),
        '23503',
      );

      // 5. Deleting a request that has ONLY trace_payloads cascades cleanly
      const reqCascade = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
      await pool.query(
        `INSERT INTO gateway_requests
           (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
            billing_period, status, cache_status, admitted_at, deadline_at)
         VALUES
           ($1, $2, $3, $4, 1, 'gpt-4o', '2026-11', 'completed', 'exact_hit', $5, $5::timestamptz + interval '30 seconds')`,
        [reqCascade, ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, ADMITTED_NOV_2026],
      );

      await pool.query(
        `INSERT INTO trace_payloads (request_id, org_id, expires_at)
         VALUES ($1, $2, clock_timestamp() + interval '7 days')`,
        [reqCascade, ORG_A],
      );

      // Delete request_id -> verify trace_payloads is cascaded
      const del = await pool.query('DELETE FROM gateway_requests WHERE request_id = $1', [
        reqCascade,
      ]);
      expect(del.rowCount).toBe(1);

      const { rows: traceCheck } = await pool.query<{ count: number }>(
        'SELECT count(*)::int AS count FROM trace_payloads WHERE request_id = $1',
        [reqCascade],
      );
      expect(traceCheck[0]?.count).toBe(0);
    });

    it('uses idx_provider_cost_adjustments_attempt for canonical cost lookup (query plan evidence)', async () => {
      // Opportunistic DB-21 remediation: enforce index selection without Seq Scan ambiguity
      await pool.query('SET LOCAL enable_seqscan = off');
      const { rows } = await pool.query<{ 'QUERY PLAN': string }>(
        `EXPLAIN (COSTS OFF)
         SELECT SUM(delta_microdollars)
         FROM provider_cost_adjustments
         WHERE attempt_id = $1 AND org_id = $2`,
        [ATTEMPT_ID, ORG_A],
      );
      const planText = rows.map((r) => r['QUERY PLAN']).join('\n');
      expect(planText).toContain('idx_provider_cost_adjustments_attempt');
    });
  });

  describe('PostgreSQL role least privilege under real authenticated sessions', () => {
    it('enforces least-privilege grants and RLS on financial tables across runtime roles (42501)', async () => {
      const app = await connectAs(fresh, 'gateway_app');
      const worker = await connectAs(fresh, 'gateway_worker');
      const startup = await connectAs(fresh, 'gateway_startup');

      const clients = [app, worker, startup];
      try {
        // 1. gateway_startup is denied all operations on all financial tables
        for (const table of FINANCIAL_TABLES) {
          await expectSqlState(startup.query(`SELECT * FROM ${table}`), '42501');
          await expectSqlState(startup.query(`INSERT INTO ${table} DEFAULT VALUES`), '42501');
          await expectSqlState(startup.query(`UPDATE ${table} SET org_id = org_id`), '42501');
          await expectSqlState(startup.query(`DELETE FROM ${table}`), '42501');
          await expectSqlState(startup.query(`TRUNCATE TABLE ${table}`), '42501');
        }

        // 2. Financial deletion and TRUNCATE are denied to runtime roles
        for (const client of [app, worker]) {
          await expectSqlState(client.query('DELETE FROM gateway_requests'), '42501');
          await expectSqlState(client.query('DELETE FROM provider_attempts'), '42501');
          await expectSqlState(client.query('DELETE FROM provider_cost_adjustments'), '42501');
          await expectSqlState(
            client.query('UPDATE provider_cost_adjustments SET delta_microdollars = 0'),
            '42501',
          );
          for (const table of FINANCIAL_TABLES) {
            await expectSqlState(client.query(`TRUNCATE TABLE ${table}`), '42501');
          }
          await expectSqlState(client.query('SET ROLE gateway_owner'), '42501');
        }

        // 3. Without tenant context, SELECT returns 0 rows via RLS
        for (const table of FINANCIAL_TABLES) {
          const { rows: appRows } = await app.query(`SELECT * FROM ${table}`);
          expect(appRows).toHaveLength(0);
          const { rows: workerRows } = await worker.query(`SELECT * FROM ${table}`);
          expect(workerRows).toHaveLength(0);
        }
      } finally {
        for (const client of clients) {
          await client.end().catch(() => undefined);
        }
      }
    });

    it('enforces FORCE RLS default-deny on gateway_owner: sees zero rows and writes fail', async () => {
      const client = await pool.connect();
      try {
        await client.query('SET ROLE gateway_owner');

        // With zero permissive policies, SELECT returns zero rows even though table contains rows
        const { rows: reqs } = await client.query<{ count: number }>(
          'SELECT count(*)::int AS count FROM gateway_requests',
        );
        expect(reqs[0]?.count).toBe(0);

        // INSERT is rejected under default-deny RLS
        await expectSqlState(
          client.query(
            `INSERT INTO gateway_requests
               (request_id, org_id, virtual_key_id, gateway_instance_id, gateway_epoch, requested_model,
                billing_period, status, cache_status, admitted_at, deadline_at)
             VALUES
               (gen_random_uuid(), $1, $2, $3, 1, 'gpt-4o', '2026-11', 'in_progress', 'miss', $4, $4::timestamptz + interval '30 seconds')`,
            [ORG_A, VIRTUAL_KEY_A_ID, GATEWAY_INSTANCE_ID, ADMITTED_NOV_2026],
          ),
          '42501',
        );
      } finally {
        await client.query('RESET ROLE').catch(() => undefined);
        client.release();
      }
    });
  });

  describe('Upgrade and migration idempotency: 0006 to 0007', () => {
    it('applies 0007 on a database at 0006 and preserves existing data', async () => {
      const upgradedDb = await createDatabase('upgrade-test');
      const tempDir = copyMigrationsToTempDir([
        '0001-roles.sql',
        '0002-org-tables.sql',
        '0003-rls-default-deny.sql',
        '0004-gateway-control-privileges.sql',
        '0005-virtual-key-integrity.sql',
        '0006-schema-privilege-hardening.sql',
      ]);

      try {
        // Apply 0001-0006
        const firstRun = await migrate(upgradedDb, tempDir);
        expect(firstRun).toEqual(['0001', '0002', '0003', '0004', '0005', '0006']);

        // Seed data in existing 0006 tables
        const seeder = new pg.Client({ connectionString: upgradedDb.url });
        await seeder.connect();
        try {
          await seeder.query(
            `INSERT INTO organizations
               (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
             VALUES
               ($1, 'Upgrade Org', 5000000, 1, $2, $3, $4)`,
            [ORG_A, Buffer.from('dek'), Buffer.from('iv'), Buffer.from('tag')],
          );
        } finally {
          await seeder.end();
        }

        // Apply remaining migrations using authoritative directory (applies 0007, 0008, 0009, 0010)
        const secondRun = await migrate(upgradedDb);
        expect(secondRun).toEqual(['0007', '0008', '0009', '0010']);

        // Verify seeded data intact
        const verifier = new pg.Client({ connectionString: upgradedDb.url });
        await verifier.connect();
        try {
          const { rows } = await verifier.query<{ name: string }>(
            'SELECT name FROM organizations WHERE id = $1',
            [ORG_A],
          );
          expect(rows[0]?.name).toBe('Upgrade Org');

          // Verify new 0007 table is queryable
          const { rows: reqCount } = await verifier.query<{ count: number }>(
            'SELECT count(*)::int AS count FROM gateway_requests',
          );
          expect(reqCount[0]?.count).toBe(0);
        } finally {
          await verifier.end();
        }

        // Running migrate again is an idempotent no-op
        const thirdRun = await migrate(upgradedDb);
        expect(thirdRun).toEqual([]);
      } finally {
        removeTempDir(tempDir);
      }
    });
  });
});
