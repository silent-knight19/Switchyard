import crypto from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runMigrations } from '../db/migrate.js';
import {
  bootstrapDatabase,
  createDisposableDatabase,
  createRolePasswords,
  roleConnectionString,
  startDisposableCluster,
  type DisposableCluster,
  type DisposableDatabase,
} from '../db/test/disposable-pg.js';
import { withTenant } from '../db/tenant.js';
import {
  type IVirtualKeyRateLimiter,
  VirtualKeyAuthenticatorService,
} from './virtual-key-authenticator.js';
import { VirtualKeyManagementService } from './virtual-key-management.js';

describe('SW-1.6.4: PostgreSQL 16 Virtual Key Revocation, Tenant Isolation & Concurrency Suite', () => {
  let cluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();
  let adminClient: pg.Client;
  let appPool: pg.Pool;
  let workerPool: pg.Pool;
  let managementService: VirtualKeyManagementService;
  let authenticator: VirtualKeyAuthenticatorService;

  const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
  const ORG_B_ID = '22222222-2222-4222-8222-222222222222';
  const CLIENT_IP = '198.51.100.42';

  const mockRateLimiter: IVirtualKeyRateLimiter = {
    assertNotRateLimited: async () => {},
  };

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    db = await createDisposableDatabase(cluster, 'vk_revocation_db_test');
    await bootstrapDatabase(db, passwords);

    // Apply authoritative migrations 0001 through 0011
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

    // Connect admin client for setup and introspection
    adminClient = new pg.Client({ connectionString: db.url });
    await adminClient.connect();

    // Seed test organizations
    await adminClient.query(`
      INSERT INTO public.organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
      VALUES
        ('${ORG_A_ID}', 'Org Alpha', 1000000, 1, '\\x01', '\\x02', '\\x03'),
        ('${ORG_B_ID}', 'Org Beta', 2000000, 1, '\\x04', '\\x05', '\\x06');
    `);

    // Connect runtime gateway_app pool
    appPool = new pg.Pool({
      connectionString: roleConnectionString(db.url, 'gateway_app', passwords.gateway_app),
    });
    appPool.on('error', () => undefined);

    // Connect runtime gateway_worker pool
    workerPool = new pg.Pool({
      connectionString: roleConnectionString(db.url, 'gateway_worker', passwords.gateway_worker),
    });
    workerPool.on('error', () => undefined);

    managementService = new VirtualKeyManagementService({ pool: appPool });
    authenticator = new VirtualKeyAuthenticatorService({
      pool: appPool,
      rateLimiter: mockRateLimiter,
    });
  }, 60000);

  afterAll(async () => {
    await appPool?.end().catch(() => undefined);
    await workerPool?.end().catch(() => undefined);
    await adminClient?.end().catch(() => undefined);
    await db?.drop().catch(() => undefined);
    await cluster?.stop().catch(() => undefined);
  });

  // --- Test-Only Simulated Admission Helper (Section 6.5) ---
  interface SimulatedAdmissionResult {
    readonly admitted: boolean;
    readonly reason: 'ACTIVE' | 'KEY_REVOKED' | 'KEY_NOT_FOUND';
    readonly keyId?: string;
    readonly orgId?: string;
  }

  interface DbQueryClient {
    query<T extends pg.QueryResultRow = pg.QueryResultRow>(
      queryText: string,
      values?: unknown[],
    ): Promise<pg.QueryResult<T>>;
  }

  async function simulateProviderAttemptAdmissionLock(
    client: DbQueryClient,
    keyId: string,
  ): Promise<SimulatedAdmissionResult> {
    const res = await client.query<{ id: string; org_id: string; revoked_at: Date | null }>(
      'SELECT id, org_id, revoked_at FROM public.virtual_keys WHERE id = $1 FOR UPDATE',
      [keyId],
    );
    if (res.rows.length === 0) {
      return { admitted: false, reason: 'KEY_NOT_FOUND' };
    }
    const row = res.rows[0]!;
    if (row.revoked_at !== null) {
      return { admitted: false, reason: 'KEY_REVOKED', keyId: row.id, orgId: row.org_id };
    }
    return { admitted: true, reason: 'ACTIVE', keyId: row.id, orgId: row.org_id };
  }

  describe('Section 5: Revocation Lifecycle Regression Tests (R1–R5, R7)', () => {
    it('Test R1: creates active key, updates policy, and authenticates successfully', async () => {
      const created = await managementService.createKey(ORG_A_ID, 'Active Key R1');
      expect(created.id).toBeDefined();
      expect(created.rawKey).toMatch(/^gw_live_[A-Za-z0-9_-]{11}_[A-Za-z0-9_-]{43}$/);

      // Set explicit allowed models and rate limits
      const updated = await managementService.replacePolicy(ORG_A_ID, created.id, {
        allowedModels: ['gpt-4o', 'claude-3-5-sonnet'],
        rpmLimit: 120,
        tpmLimit: 12000,
        concurrentStreamLimit: 4,
        exactCacheEnabled: false,
        semanticCacheEnabled: false,
        piiRedactionEnabled: true,
        storePayloads: false,
      });
      expect(updated.allowedModels).toEqual(['gpt-4o', 'claude-3-5-sonnet']);

      // Authenticate using the raw key
      const auth = await authenticator.authenticateKey(created.rawKey, CLIENT_IP);
      expect(auth.valid).toBe(true);
      expect(auth.principal).toBeDefined();
      expect(auth.principal?.keyId).toBe(created.id);
      expect(auth.principal?.orgId).toBe(ORG_A_ID);
      expect(auth.principal?.keyPolicy).toBeDefined();
      expect((auth.principal?.keyPolicy as { allowedModels: string[] }).allowedModels).toEqual([
        'gpt-4o',
        'claude-3-5-sonnet',
      ]);
      expect((auth.principal?.keyPolicy as { rpmLimit: number }).rpmLimit).toBe(120);
    });

    it('Test R2: immediate post-revocation authentication fails with KEY_REVOKED', async () => {
      const key = await managementService.createKey(ORG_A_ID, 'Post-Revoke Target R2');

      // Pre-revocation authentication succeeds
      const preAuth = await authenticator.authenticateKey(key.rawKey, CLIENT_IP);
      expect(preAuth.valid).toBe(true);

      // Revoke the key
      await managementService.revokeKey(ORG_A_ID, key.id);

      // Verify row in database has revoked_at set
      const dbRow = await adminClient.query<{ revoked_at: Date }>(
        'SELECT revoked_at FROM public.virtual_keys WHERE id = $1',
        [key.id],
      );
      expect(dbRow.rows[0]!.revoked_at).not.toBeNull();

      // Post-revocation authentication fails fail-closed
      const postAuth = await authenticator.authenticateKey(key.rawKey, CLIENT_IP);
      expect(postAuth.valid).toBe(false);
      expect(postAuth.reason).toBe('KEY_REVOKED');
      expect(postAuth.principal).toBeUndefined();
    });

    it('Test R3: idempotent revocation preserves original revoked_at and row data', async () => {
      const key = await managementService.createKey(ORG_A_ID, 'Idempotent Target R3');

      // Initial revocation
      await managementService.revokeKey(ORG_A_ID, key.id);
      const row1 = await adminClient.query<{ revoked_at: Date; key_hash: Buffer }>(
        'SELECT revoked_at, key_hash FROM public.virtual_keys WHERE id = $1',
        [key.id],
      );
      expect(row1.rows[0]!.revoked_at).not.toBeNull();
      const firstRevocationIso = row1.rows[0]!.revoked_at.toISOString();
      const originalHash = row1.rows[0]!.key_hash;

      // Repeat revocation (idempotent)
      await managementService.revokeKey(ORG_A_ID, key.id);
      const row2 = await adminClient.query<{ revoked_at: Date; key_hash: Buffer }>(
        'SELECT revoked_at, key_hash FROM public.virtual_keys WHERE id = $1',
        [key.id],
      );

      // Invariants: original timestamp preserved, record and verifier NOT deleted or altered
      expect(row2.rows[0]!.revoked_at.toISOString()).toBe(firstRevocationIso);
      expect(row2.rows[0]!.key_hash).toEqual(originalHash);
      expect(row2.rows[0]!.key_hash.length).toBe(32);
    });

    it('Test R4: permanent revocation blocks policy updates and cannot be unrevoked', async () => {
      const key = await managementService.createKey(ORG_A_ID, 'Permanent Revocation R4');
      await managementService.revokeKey(ORG_A_ID, key.id);

      // Policy update fails with KEY_REVOKED
      await expect(
        managementService.replacePolicy(ORG_A_ID, key.id, {
          allowedModels: ['gpt-4o'],
          rpmLimit: 50,
          tpmLimit: 5000,
          concurrentStreamLimit: 2,
          exactCacheEnabled: false,
          semanticCacheEnabled: false,
          piiRedactionEnabled: true,
          storePayloads: false,
        }),
      ).rejects.toThrow('Cannot update policy of a revoked virtual key');

      // Repeated authentication continues to fail
      for (let i = 0; i < 3; i++) {
        const auth = await authenticator.authenticateKey(key.rawKey, CLIENT_IP);
        expect(auth.valid).toBe(false);
        expect(auth.reason).toBe('KEY_REVOKED');
      }

      // Assert row remains revoked in database
      const row = await adminClient.query<{ revoked_at: Date }>(
        'SELECT revoked_at FROM public.virtual_keys WHERE id = $1',
        [key.id],
      );
      expect(row.rows[0]!.revoked_at).not.toBeNull();
    });

    it('Test R5: tenant isolation prevents cross-tenant revocation', async () => {
      const keyA = await managementService.createKey(ORG_A_ID, 'Tenant A Isolation Key');
      const keyB = await managementService.createKey(ORG_B_ID, 'Tenant B Isolation Key');

      // Org A admin attempts to revoke Org B key -> KEY_NOT_FOUND (generic cross-tenant 404)
      await expect(managementService.revokeKey(ORG_A_ID, keyB.id)).rejects.toThrow(
        'Virtual key not found',
      );

      // Org B admin attempts to revoke Org A key -> KEY_NOT_FOUND
      await expect(managementService.revokeKey(ORG_B_ID, keyA.id)).rejects.toThrow(
        'Virtual key not found',
      );

      // Assert neither key was modified
      const rowA = await adminClient.query<{ revoked_at: Date | null }>(
        'SELECT revoked_at FROM public.virtual_keys WHERE id = $1',
        [keyA.id],
      );
      expect(rowA.rows[0]!.revoked_at).toBeNull();

      const rowB = await adminClient.query<{ revoked_at: Date | null }>(
        'SELECT revoked_at FROM public.virtual_keys WHERE id = $1',
        [keyB.id],
      );
      expect(rowB.rows[0]!.revoked_at).toBeNull();

      // Direct query without tenant context yields 0 rows (FORCE RLS)
      const client = await appPool.connect();
      try {
        const countRes = await client.query(
          'SELECT count(*)::int as count FROM public.virtual_keys',
        );
        expect(countRes.rows[0]!.count).toBe(0);
      } finally {
        client.release();
      }
    });

    it('Test R7: authentication outage fails closed and recovers properly', async () => {
      const activeKey = await managementService.createKey(ORG_A_ID, 'Outage Recovery Active Key');
      const revokedKey = await managementService.createKey(ORG_A_ID, 'Outage Recovery Revoked Key');
      await managementService.revokeKey(ORG_A_ID, revokedKey.id);

      // Create broken authenticator pointing at closed/invalid pool to test dependency failure
      const brokenPool = new pg.Pool({
        connectionString: 'postgresql://invalid_user:invalid_pass@127.0.0.1:54329/nonexistent',
      });
      brokenPool.on('error', () => undefined);

      const brokenAuthenticator = new VirtualKeyAuthenticatorService({
        pool: brokenPool,
        rateLimiter: mockRateLimiter,
      });

      // Outage fails closed with SERVICE_UNAVAILABLE error
      await expect(
        brokenAuthenticator.authenticateKey(activeKey.rawKey, CLIENT_IP),
      ).rejects.toMatchObject({
        name: 'VirtualKeyAuthError',
        reason: 'SERVICE_UNAVAILABLE',
      });

      await brokenPool.end().catch(() => undefined);

      // Working authenticator recovers: active key succeeds, revoked key remains rejected
      const recoveredActive = await authenticator.authenticateKey(activeKey.rawKey, CLIENT_IP);
      expect(recoveredActive.valid).toBe(true);

      const recoveredRevoked = await authenticator.authenticateKey(revokedKey.rawKey, CLIENT_IP);
      expect(recoveredRevoked.valid).toBe(false);
      expect(recoveredRevoked.reason).toBe('KEY_REVOKED');
    });

    it('Section 8: rejects missing, empty, or whitespace client IP fail-closed', async () => {
      const activeKey = await managementService.createKey(ORG_A_ID, 'IP Validation Key');

      await expect(
        authenticator.authenticateKey(activeKey.rawKey, undefined),
      ).rejects.toMatchObject({
        name: 'VirtualKeyAuthError',
        reason: 'INVALID_INPUT',
      });

      await expect(authenticator.authenticateKey(activeKey.rawKey, '')).rejects.toMatchObject({
        name: 'VirtualKeyAuthError',
        reason: 'INVALID_INPUT',
      });

      await expect(authenticator.authenticateKey(activeKey.rawKey, '   ')).rejects.toMatchObject({
        name: 'VirtualKeyAuthError',
        reason: 'INVALID_INPUT',
      });
    });
  });

  describe('Section 6: Deterministic Concurrency & Row-Lock Verification (Phase 2 Seam)', () => {
    it('Scenario A: Revocation wins row lock — blocks admission and admission rejects fail-closed', async () => {
      const key = await managementService.createKey(ORG_A_ID, 'Scenario A Race Key');

      const clientR = await appPool.connect();
      const clientA = await appPool.connect();

      try {
        // 1. Transaction R begins and acquires exclusive row lock
        await clientR.query('BEGIN');
        await clientR.query(`SET LOCAL app.current_org_id = '${ORG_A_ID}'`);
        const lockR = await clientR.query<{ id: string }>(
          'SELECT id FROM public.virtual_keys WHERE id = $1 FOR UPDATE',
          [key.id],
        );
        expect(lockR.rows.length).toBe(1);

        // 2. Transaction R updates revoked_at (not yet committed)
        await clientR.query(
          'UPDATE public.virtual_keys SET revoked_at = clock_timestamp() WHERE id = $1',
          [key.id],
        );

        // 3. Transaction A starts admission check in tenant context, attempting SELECT ... FOR UPDATE
        let admissionCompleted = false;
        let admissionResult: SimulatedAdmissionResult | null = null;
        let admissionError: unknown = null;

        await clientA.query('BEGIN');
        await clientA.query(`SET LOCAL app.current_org_id = '${ORG_A_ID}'`);

        const admissionPromise = (async () => {
          try {
            admissionResult = await simulateProviderAttemptAdmissionLock(clientA, key.id);
          } catch (err) {
            admissionError = err;
          } finally {
            admissionCompleted = true;
          }
        })();

        // 4. Poll pg_locks deterministically to verify clientA is blocked waiting for clientR's row lock
        let blocked = false;
        for (let i = 0; i < 50; i++) {
          const locksRes = await adminClient.query<{ count: number }>(`
            SELECT count(*)::int as count
            FROM pg_locks
            WHERE NOT granted
          `);
          if (locksRes.rows[0]!.count > 0) {
            blocked = true;
            break;
          }
          await new Promise((resolve) => setTimeout(resolve, 20));
        }

        expect(blocked).toBe(true);
        expect(admissionCompleted).toBe(false);

        // 5. Transaction R commits
        await clientR.query('COMMIT');

        // 6. Transaction A unblocks and receives the updated row
        await admissionPromise;
        expect(admissionCompleted).toBe(true);
        expect(admissionError).toBeNull();
        expect(admissionResult).not.toBeNull();

        // 7. Admission decision rejects because revoked_at IS NOT NULL
        expect(admissionResult!.admitted).toBe(false);
        expect(admissionResult!.reason).toBe('KEY_REVOKED');

        // 8. Rollback admission transaction without inserting provider attempt
        await clientA.query('ROLLBACK');
      } finally {
        clientR.release();
        clientA.release();
      }
    });

    it('Scenario B: Admission lock wins row lock — blocks revocation until admission commits', async () => {
      const key = await managementService.createKey(ORG_A_ID, 'Scenario B Race Key');

      const clientA = await appPool.connect();
      const clientR = await appPool.connect();

      try {
        // 1. Transaction A begins and acquires admission row lock
        await clientA.query('BEGIN');
        await clientA.query(`SET LOCAL app.current_org_id = '${ORG_A_ID}'`);
        const admissionResult = await simulateProviderAttemptAdmissionLock(clientA, key.id);

        // 2. Admission confirms key is active while holding lock
        expect(admissionResult.admitted).toBe(true);
        expect(admissionResult.reason).toBe('ACTIVE');

        // 3. Transaction R begins revocation attempt, attempting SELECT ... FOR UPDATE
        let revocationCompleted = false;
        let revocationError: unknown = null;

        await clientR.query('BEGIN');
        await clientR.query(`SET LOCAL app.current_org_id = '${ORG_A_ID}'`);

        const revocationPromise = (async () => {
          try {
            await clientR.query('SELECT id FROM public.virtual_keys WHERE id = $1 FOR UPDATE', [
              key.id,
            ]);
            await clientR.query(
              'UPDATE public.virtual_keys SET revoked_at = clock_timestamp() WHERE id = $1',
              [key.id],
            );
            await clientR.query('COMMIT');
          } catch (err) {
            revocationError = err;
            await clientR.query('ROLLBACK').catch(() => undefined);
          } finally {
            revocationCompleted = true;
          }
        })();

        // 4. Poll pg_locks deterministically to verify clientR is blocked by clientA
        let blocked = false;
        for (let i = 0; i < 50; i++) {
          const locksRes = await adminClient.query<{ count: number }>(`
            SELECT count(*)::int as count
            FROM pg_locks
            WHERE NOT granted
          `);
          if (locksRes.rows[0]!.count > 0) {
            blocked = true;
            break;
          }
          await new Promise((resolve) => setTimeout(resolve, 20));
        }

        expect(blocked).toBe(true);
        expect(revocationCompleted).toBe(false);

        // 5. Transaction A commits its admission (simulating attempt insertion commitment)
        await clientA.query('COMMIT');

        // 6. Transaction R unblocks, revokes key, and commits
        await revocationPromise;
        expect(revocationCompleted).toBe(true);
        expect(revocationError).toBeNull();

        // 7. Verify the key is now revoked in PostgreSQL
        const dbRow = await adminClient.query<{ revoked_at: Date }>(
          'SELECT revoked_at FROM public.virtual_keys WHERE id = $1',
          [key.id],
        );
        expect(dbRow.rows[0]!.revoked_at).not.toBeNull();

        // 8. Subsequent admission transaction (Transaction A2) sees revoked state and rejects
        await withTenant(appPool, ORG_A_ID, async (clientA2) => {
          const recheck = await simulateProviderAttemptAdmissionLock(clientA2, key.id);
          expect(recheck.admitted).toBe(false);
          expect(recheck.reason).toBe('KEY_REVOKED');
        });
      } finally {
        clientA.release();
        clientR.release();
      }
    });

    it('Scenario C: Stale authenticated principal cannot bypass admission-time row check', async () => {
      // 1. Authenticate an active key successfully
      const key = await managementService.createKey(ORG_A_ID, 'Stale Principal Target Key');
      const initialAuth = await authenticator.authenticateKey(key.rawKey, CLIENT_IP);
      expect(initialAuth.valid).toBe(true);
      expect(initialAuth.principal).toBeDefined();

      // 2. Retain the authenticated principal in memory (simulating request in flight)
      const stalePrincipal = initialAuth.principal!;
      expect(stalePrincipal.keyId).toBe(key.id);
      expect(stalePrincipal.orgId).toBe(ORG_A_ID);

      // 3. Revoke the key in PostgreSQL and confirm commit
      await managementService.revokeKey(ORG_A_ID, key.id);

      // 4. Attempt admission using the retained principal's verified keyId & orgId
      await withTenant(appPool, stalePrincipal.orgId, async (admissionClient) => {
        const admissionResult = await simulateProviderAttemptAdmissionLock(
          admissionClient,
          stalePrincipal.keyId,
        );

        // 5. Invariant: Admission MUST reject because PostgreSQL row lock observes revocation
        expect(admissionResult.admitted).toBe(false);
        expect(admissionResult.reason).toBe('KEY_REVOKED');
      });
    });
  });

  describe('Section 10 & 11: Worker Role Least-Privilege Verification', () => {
    it('proves gateway_worker role is denied INSERT, UPDATE, REVOKE, DELETE, and lookup_virtual_key_by_hash', async () => {
      const key = await managementService.createKey(ORG_A_ID, 'Worker Privilege Audit Key');

      const workerClient = await workerPool.connect();
      try {
        // Can read non-secret virtual key attribution columns under tenant context
        await workerClient.query(`SET app.current_org_id = '${ORG_A_ID}'`);
        const selectRes = await workerClient.query(
          'SELECT id, org_id, name, key_prefix, created_at, revoked_at FROM public.virtual_keys WHERE id = $1',
          [key.id],
        );
        expect(selectRes.rows.length).toBe(1);

        // Cannot INSERT (SQLSTATE 42501)
        await expect(
          workerClient.query(
            `INSERT INTO public.virtual_keys (id, org_id, name, key_prefix, key_hash, allowed_models, rpm_limit, tpm_limit, concurrent_stream_limit)
             VALUES ('${crypto.randomUUID()}', '${ORG_A_ID}', 'Worker Fake Key', 'gw_live_00000000000', '\\x01', '{}', 1, 1, 1)`,
          ),
        ).rejects.toThrow(/permission denied for table virtual_keys/);

        // Cannot UPDATE policy columns (SQLSTATE 42501)
        await expect(
          workerClient.query('UPDATE public.virtual_keys SET rpm_limit = 50 WHERE id = $1', [
            key.id,
          ]),
        ).rejects.toThrow(/permission denied for table virtual_keys/);

        // Cannot revoke key (UPDATE revoked_at) (SQLSTATE 42501)
        await expect(
          workerClient.query(
            'UPDATE public.virtual_keys SET revoked_at = clock_timestamp() WHERE id = $1',
            [key.id],
          ),
        ).rejects.toThrow(/permission denied for table virtual_keys/);

        // Cannot DELETE row (SQLSTATE 42501)
        await expect(
          workerClient.query('DELETE FROM public.virtual_keys WHERE id = $1', [key.id]),
        ).rejects.toThrow(/permission denied for table virtual_keys/);

        // Cannot execute restricted pre-tenant lookup app_private.lookup_virtual_key_by_hash (SQLSTATE 42501)
        await expect(
          workerClient.query('SELECT * FROM app_private.lookup_virtual_key_by_hash($1::bytea)', [
            Buffer.alloc(32),
          ]),
        ).rejects.toThrow(/permission denied for function lookup_virtual_key_by_hash/);
      } finally {
        workerClient.release();
      }
    });
  });
});
