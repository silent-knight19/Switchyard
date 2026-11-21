import crypto from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runMigrations } from '../db/migrate.js';
import { withTenant } from '../db/tenant.js';
import {
  bootstrapDatabase,
  createDisposableDatabase,
  createRolePasswords,
  roleConnectionString,
  startDisposableCluster,
  type DisposableCluster,
  type DisposableDatabase,
} from '../db/test/disposable-pg.js';
import { hashSecret, SessionService } from './session.js';
import { SessionError } from './types.js';

describe('SW-1.5.2: Server-Side Web Sessions PostgreSQL 16 Integration Suite', () => {
  let cluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();
  let adminClient: pg.Client;
  let appPool: pg.Pool;
  let sessionService: SessionService;

  const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
  const ORG_B_ID = '22222222-2222-4222-8222-222222222222';
  const USER_A_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const USER_B_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

  interface CausalLockEvidence {
    validatorPid: number;
    lockerPid: number;
    datname: string;
    waitEventType: string;
    waitEvent: string;
    query: string;
    blockingPids: number[];
  }

  /**
   * Positively establishes via PostgreSQL lock manager that the specific validator backend
   * is blocked by the specific controlled locker backend on the session validation query (AUTH-11).
   */
  async function waitForAttributedLock(
    admin: pg.Client,
    validatorPid: number,
    lockerPid: number,
    expectedDbName: string,
    timeoutMs = 5000,
  ): Promise<CausalLockEvidence> {
    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      const res = await admin.query<{
        validator_pid: number;
        datname: string;
        wait_event_type: string;
        wait_event: string;
        query: string;
        blocking_pids: number[];
      }>(
        `SELECT
          a.pid AS validator_pid,
          a.datname,
          a.wait_event_type,
          a.wait_event,
          a.query,
          pg_blocking_pids(a.pid) AS blocking_pids
        FROM pg_stat_activity a
        WHERE a.pid = $1
          AND a.datname = $2
          AND a.wait_event_type = 'Lock'
          AND a.query LIKE '%web_sessions%FOR UPDATE OF ws%'
          AND $3 = ANY(pg_blocking_pids(a.pid));`,
        [validatorPid, expectedDbName, lockerPid],
      );

      if (res.rows.length > 0 && res.rows[0]) {
        const row = res.rows[0];
        return {
          validatorPid: row.validator_pid,
          lockerPid,
          datname: row.datname,
          waitEventType: row.wait_event_type,
          waitEvent: row.wait_event,
          query: row.query,
          blockingPids: row.blocking_pids,
        };
      }
      await new Promise((r) => setTimeout(r, 10));
    }
    throw new Error(
      `Timeout after ${timeoutMs}ms waiting for validator PID ${validatorPid} to be blocked by locker PID ${lockerPid} on session validation in database "${expectedDbName}"`,
    );
  }

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    db = await createDisposableDatabase(cluster, 'session_service_test');
    await bootstrapDatabase(db, passwords);

    // Apply migrations 0001 through 0011
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

    // Connect admin superuser client for fixture seeding and database inspection
    adminClient = new pg.Client({ connectionString: db.url });
    await adminClient.connect();

    // Seed test organizations and users
    await adminClient.query(`
      INSERT INTO public.organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
      VALUES
        ('${ORG_A_ID}', 'Org Alpha', 1000000, 1, '\\x01', '\\x02', '\\x03'),
        ('${ORG_B_ID}', 'Org Beta', 2000000, 1, '\\x04', '\\x05', '\\x06');

      INSERT INTO public.users (id, org_id, email_normalized, password_hash, role)
      VALUES
        ('${USER_A_ID}', '${ORG_A_ID}', 'user.a@alpha.com', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$dGVzdA', 'admin'),
        ('${USER_B_ID}', '${ORG_B_ID}', 'user.b@beta.com', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$dGVzdA', 'member');
    `);

    // Connect runtime gateway_app pool
    appPool = new pg.Pool({
      connectionString: roleConnectionString(db.url, 'gateway_app', passwords.gateway_app),
    });

    sessionService = new SessionService({
      pool: appPool,
      cookieOptions: { isProduction: true },
    });
  }, 60000);

  afterAll(async () => {
    if (appPool) await appPool.end();
    if (adminClient) await adminClient.end();
    if (db) await db.drop();
    if (cluster) await cluster.stop();
  }, 30000);

  describe('1. Session Creation & Hash-Only Persistence', () => {
    it('creates a session with a 256-bit opaque secret and stores only its SHA-256 verifier', async () => {
      const { secret, csrfToken, session } = await sessionService.createSession(
        ORG_A_ID,
        USER_A_ID,
      );

      expect(typeof secret).toBe('string');
      expect(secret.length).toBe(43); // 32 bytes in base64url

      expect(typeof csrfToken).toBe('string');
      expect(csrfToken.length).toBe(43);

      expect(session.userId).toBe(USER_A_ID);
      expect(session.orgId).toBe(ORG_A_ID);
      expect(session.revokedAt).toBeNull();

      // Verify database row contains only SHA-256 verifiers, NEVER the raw secret or raw csrfToken
      const secretBytes = Buffer.from(secret, 'base64url');
      const expectedSessionHash = hashSecret(secretBytes);

      const csrfBytes = Buffer.from(csrfToken, 'base64url');
      const expectedCsrfHash = hashSecret(csrfBytes);

      const { rows } = await adminClient.query<{
        session_id_hash: Buffer;
        csrf_token_hash: Buffer;
      }>('SELECT session_id_hash, csrf_token_hash FROM web_sessions WHERE session_id_hash = $1', [
        expectedSessionHash,
      ]);

      expect(rows).toHaveLength(1);
      expect(rows[0]?.session_id_hash).toEqual(expectedSessionHash);
      expect(rows[0]?.csrf_token_hash).toEqual(expectedCsrfHash);

      // Verify raw secret text does NOT appear anywhere in the database row
      const rawRowDump = JSON.stringify(rows[0]);
      expect(rawRowDump).not.toContain(secret);
      expect(rawRowDump).not.toContain(csrfToken);
    });
  });

  describe('2. Pre-Tenant Session Resolution & Validation', () => {
    it('resolves and validates a valid active session via opaque cookie', async () => {
      const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

      const validation = await sessionService.resolveAndValidateSession(secret);

      expect(validation.valid).toBe(true);
      expect(validation.user?.id).toBe(USER_A_ID);
      expect(validation.user?.orgId).toBe(ORG_A_ID);
      expect(validation.user?.role).toBe('admin');
      expect(validation.user?.emailNormalized).toBe('user.a@alpha.com');
      expect(validation.session?.revokedAt).toBeNull();
    });

    it('rejects an unknown or malformed session secret', async () => {
      // Malformed secret length
      const malformedRes = await sessionService.resolveAndValidateSession('too-short');
      expect(malformedRes.valid).toBe(false);
      expect(malformedRes.reason).toBe('MALFORMED_SECRET');

      // Random non-existent 32-byte secret
      const randomSecret = crypto.randomBytes(32).toString('base64url');
      const unknownRes = await sessionService.resolveAndValidateSession(randomSecret);
      expect(unknownRes.valid).toBe(false);
      expect(unknownRes.reason).toBe('SESSION_NOT_FOUND');
    });

    it('renews idle expiration upon validation, strictly bounded by absolute expiration', async () => {
      const { secret, session: initialSession } = await sessionService.createSession(
        ORG_A_ID,
        USER_A_ID,
      );

      // Artificially age the session's last_seen_at by 30 minutes in database
      const initialHash = initialSession.sessionIdHash;
      await adminClient.query(
        `UPDATE web_sessions
         SET last_seen_at = clock_timestamp() - interval '30 minutes',
             idle_expires_at = clock_timestamp() + interval '90 minutes'
         WHERE session_id_hash = $1;`,
        [initialHash],
      );

      // Validate session -> triggers touch/renewal
      const validation = await sessionService.resolveAndValidateSession(secret);
      expect(validation.valid).toBe(true);

      const updatedRow = await adminClient.query<{
        last_seen_at: Date;
        idle_expires_at: Date;
        absolute_expires_at: Date;
      }>(
        'SELECT last_seen_at, idle_expires_at, absolute_expires_at FROM web_sessions WHERE session_id_hash = $1',
        [initialHash],
      );

      const lastSeen = updatedRow.rows[0]!.last_seen_at.getTime();
      const idleExp = updatedRow.rows[0]!.idle_expires_at.getTime();
      const absExp = updatedRow.rows[0]!.absolute_expires_at.getTime();

      // idle_expires_at should be approximately lastSeen + 2 hours
      const diffMs = idleExp - lastSeen;
      expect(diffMs).toBeGreaterThanOrEqual(7190 * 1000);
      expect(diffMs).toBeLessThanOrEqual(7210 * 1000);

      // idle_expires_at must never exceed absolute_expires_at
      expect(idleExp).toBeLessThanOrEqual(absExp);
    });

    it('rejects an idle-expired session with SESSION_EXPIRED_IDLE', async () => {
      const { secret, session } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

      // Force idle expiration (idle_expires_at set in the past)
      await adminClient.query(
        `UPDATE web_sessions
         SET idle_expires_at = clock_timestamp() - interval '1 second'
         WHERE session_id_hash = $1;`,
        [session.sessionIdHash],
      );

      const validation = await sessionService.resolveAndValidateSession(secret);
      expect(validation.valid).toBe(false);
      expect(validation.reason).toBe('SESSION_EXPIRED_IDLE');
    });

    it('rejects an absolutely expired session with SESSION_EXPIRED_ABSOLUTE', async () => {
      const { secret, session } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

      // Force absolute expiration
      await adminClient.query(
        `UPDATE web_sessions
         SET absolute_expires_at = clock_timestamp() - interval '1 second'
         WHERE session_id_hash = $1;`,
        [session.sessionIdHash],
      );

      const validation = await sessionService.resolveAndValidateSession(secret);
      expect(validation.valid).toBe(false);
      expect(validation.reason).toBe('SESSION_EXPIRED_ABSOLUTE');
    });

    it('returns committed renewed timestamps upon successful validation without exposing stale values (Section 8)', async () => {
      const { secret, session } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

      // Artificially age the session's last_seen_at by 15 minutes
      await adminClient.query(
        `UPDATE web_sessions
         SET
           last_seen_at = clock_timestamp() - interval '15 minutes',
           idle_expires_at = clock_timestamp() + interval '105 minutes'
         WHERE session_id_hash = $1;`,
        [session.sessionIdHash],
      );

      const beforeValidation = await adminClient.query<{ last_seen_at: Date }>(
        'SELECT last_seen_at FROM web_sessions WHERE session_id_hash = $1',
        [session.sessionIdHash],
      );
      const staleLastSeen = beforeValidation.rows[0]!.last_seen_at;

      // Validate session: triggers atomic renewal
      const validation = await sessionService.resolveAndValidateSession(secret);
      expect(validation.valid).toBe(true);
      expect(validation.session).toBeDefined();

      const returnedSession = validation.session!;
      // Returned lastSeenAt must be strictly greater than the aged timestamp before validation
      expect(returnedSession.lastSeenAt.getTime()).toBeGreaterThan(staleLastSeen.getTime());

      // Query committed row from database to verify exact match
      const dbRow = await adminClient.query<{ last_seen_at: Date; idle_expires_at: Date }>(
        'SELECT last_seen_at, idle_expires_at FROM web_sessions WHERE session_id_hash = $1',
        [session.sessionIdHash],
      );
      expect(returnedSession.lastSeenAt.getTime()).toBe(dbRow.rows[0]!.last_seen_at.getTime());
      expect(returnedSession.idleExpiresAt.getTime()).toBe(
        dbRow.rows[0]!.idle_expires_at.getTime(),
      );
    });
  });

  describe('3. Session Revocation & Logout', () => {
    it('revokes session on explicit logout and prevents subsequent authentication', async () => {
      const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

      // First validation succeeds
      const beforeLogout = await sessionService.resolveAndValidateSession(secret);
      expect(beforeLogout.valid).toBe(true);

      // Explicit logout
      const revoked = await sessionService.revokeSession(secret);
      expect(revoked).toBe(true);

      // Repeated logout is safe (idempotent)
      const repeatRevoke = await sessionService.revokeSession(secret);
      expect(repeatRevoke).toBe(false);

      // Subsequent validation fails with SESSION_REVOKED
      const afterLogout = await sessionService.resolveAndValidateSession(secret);
      expect(afterLogout.valid).toBe(false);
      expect(afterLogout.reason).toBe('SESSION_REVOKED');
    });

    it('revokes all active sessions for a user upon security-sensitive change', async () => {
      const s1 = await sessionService.createSession(ORG_A_ID, USER_A_ID);
      const s2 = await sessionService.createSession(ORG_A_ID, USER_A_ID);
      const otherUserSession = await sessionService.createSession(ORG_B_ID, USER_B_ID);

      // Revoke all sessions for USER_A_ID
      const count = await sessionService.revokeAllUserSessions(ORG_A_ID, USER_A_ID);
      expect(count).toBeGreaterThanOrEqual(2);

      // User A sessions must now be revoked
      expect((await sessionService.resolveAndValidateSession(s1.secret)).valid).toBe(false);
      expect((await sessionService.resolveAndValidateSession(s2.secret)).valid).toBe(false);

      // User B session in Org B must remain untouched
      expect((await sessionService.resolveAndValidateSession(otherUserSession.secret)).valid).toBe(
        true,
      );
    });
  });

  describe('4. Session Rotation & Concurrency Invariants', () => {
    it('rotates session secret atomically, invalidating the old secret immediately', async () => {
      const { secret: oldSecret } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

      // Rotate session
      const { newSecret } = await sessionService.rotateSession(oldSecret);

      expect(newSecret).not.toBe(oldSecret);
      expect(newSecret.length).toBe(43);

      // Old secret must cease to be valid
      const oldCheck = await sessionService.resolveAndValidateSession(oldSecret);
      expect(oldCheck.valid).toBe(false);
      expect(oldCheck.reason).toBe('SESSION_REVOKED');

      // New secret must be valid
      const newCheck = await sessionService.resolveAndValidateSession(newSecret);
      expect(newCheck.valid).toBe(true);
      expect(newCheck.user?.id).toBe(USER_A_ID);
    });

    it('rotation shortly before absolute expiry preserves absolute expiry and bounds idle expiry (AUTH-03)', async () => {
      const { secret: oldSecret, session: oldSession } = await sessionService.createSession(
        ORG_A_ID,
        USER_A_ID,
      );

      // Set old session to expire absolutely in 10 minutes, and idle in 5 minutes
      await adminClient.query(
        `UPDATE web_sessions
         SET
           absolute_expires_at = clock_timestamp() + interval '10 minutes',
           idle_expires_at = clock_timestamp() + interval '5 minutes'
         WHERE session_id_hash = $1;`,
        [oldSession.sessionIdHash],
      );

      const oldRow = await adminClient.query<{ absolute_expires_at: Date }>(
        'SELECT absolute_expires_at FROM web_sessions WHERE session_id_hash = $1',
        [oldSession.sessionIdHash],
      );
      const inheritedAbsoluteExpiry = oldRow.rows[0]!.absolute_expires_at;

      // Rotate session: must preserve inherited absolute expiry and cap idle expiry to absolute expiry
      const { newSecret, session: rotatedSession } = await sessionService.rotateSession(oldSecret);
      expect(typeof newSecret).toBe('string');
      expect(newSecret.length).toBe(43);

      // Verify returned session attributes
      expect(rotatedSession.absoluteExpiresAt.getTime()).toBe(inheritedAbsoluteExpiry.getTime());
      // Idle expiry must not exceed absolute expiry: LEAST(now + 2 hours, absolute_expires_at)
      expect(rotatedSession.idleExpiresAt.getTime()).toBeLessThanOrEqual(
        rotatedSession.absoluteExpiresAt.getTime(),
      );
      expect(rotatedSession.idleExpiresAt.getTime()).toBe(
        rotatedSession.absoluteExpiresAt.getTime(),
      );

      // Verify persistent database row
      const newRow = await adminClient.query<{
        absolute_expires_at: Date;
        idle_expires_at: Date;
      }>(
        'SELECT absolute_expires_at, idle_expires_at FROM web_sessions WHERE session_id_hash = $1',
        [rotatedSession.sessionIdHash],
      );
      expect(newRow.rows[0]!.absolute_expires_at.getTime()).toBe(inheritedAbsoluteExpiry.getTime());
      expect(newRow.rows[0]!.idle_expires_at.getTime()).toBe(
        newRow.rows[0]!.absolute_expires_at.getTime(),
      );
    });

    it('rejects rotation of revoked or expired sessions', async () => {
      // 1. Revoked session
      const { secret: s1 } = await sessionService.createSession(ORG_A_ID, USER_A_ID);
      await sessionService.revokeSession(s1);
      await expect(sessionService.rotateSession(s1)).rejects.toThrow(SessionError);

      // 2. Idle expired session
      const { secret: s2, session: sess2 } = await sessionService.createSession(
        ORG_A_ID,
        USER_A_ID,
      );
      await adminClient.query(
        `UPDATE web_sessions SET idle_expires_at = clock_timestamp() - interval '1 second' WHERE session_id_hash = $1`,
        [sess2.sessionIdHash],
      );
      await expect(sessionService.rotateSession(s2)).rejects.toThrow(SessionError);

      // 3. Absolute expired session
      const { secret: s3, session: sess3 } = await sessionService.createSession(
        ORG_A_ID,
        USER_A_ID,
      );
      await adminClient.query(
        `UPDATE web_sessions SET absolute_expires_at = clock_timestamp() - interval '1 second' WHERE session_id_hash = $1`,
        [sess3.sessionIdHash],
      );
      await expect(sessionService.rotateSession(s3)).rejects.toThrow(SessionError);
    });

    it('concurrency invariant: two concurrent rotations of the same old session cannot both succeed', async () => {
      const { secret: oldSecret } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

      // Launch two concurrent rotations of the exact same old secret
      const results = await Promise.allSettled([
        sessionService.rotateSession(oldSecret),
        sessionService.rotateSession(oldSecret),
      ]);

      const fulfilled = results.filter((r) => r.status === 'fulfilled');
      const rejected = results.filter((r) => r.status === 'rejected');

      // Exactly ONE rotation must succeed, the other MUST fail!
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);

      const err = (rejected[0] as PromiseRejectedResult).reason;
      expect(err).toBeInstanceOf(SessionError);
      expect((err as SessionError).reason).toBe('SESSION_REVOKED');

      // Old token cannot authenticate
      const oldCheck = await sessionService.resolveAndValidateSession(oldSecret);
      expect(oldCheck.valid).toBe(false);
      expect(oldCheck.reason).toBe('SESSION_REVOKED');

      // Winning new token remains valid
      const winning = (fulfilled[0] as PromiseFulfilledResult<{ newSecret: string }>).value;
      const newCheck = await sessionService.resolveAndValidateSession(winning.newSecret);
      expect(newCheck.valid).toBe(true);
      expect(newCheck.user?.id).toBe(USER_A_ID);
    });

    it('deterministic Ordering A — Revocation first: controlled lock establishes wait state with verified PID attribution, revocation commits, validation fails with SESSION_REVOKED (AUTH-11)', async () => {
      // 1. Create session
      const { secret, session } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

      // Dedicated isolated pool for the validator operation (AUTH-11)
      const validatorPool = new pg.Pool({
        connectionString: roleConnectionString(db.url, 'gateway_app', passwords.gateway_app),
        max: 1,
      });

      // Obtain exact backend PID of the dedicated validator connection
      const valProbe = await validatorPool.connect();
      const valPidRes = await valProbe.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
      const validatorPid = valPidRes.rows[0]?.pid;
      if (!validatorPid) throw new Error('Failed to obtain validator backend PID');
      valProbe.release();

      const validatorService = new SessionService({
        pool: validatorPool,
        cookieOptions: { isProduction: true },
      });

      // 2. Acquire a controlled database lock and capture locker PID
      const client1 = await appPool.connect();
      const lockerPidRes = await client1.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
      const lockerPid = lockerPidRes.rows[0]?.pid;
      if (!lockerPid) throw new Error('Failed to obtain locker backend PID');

      let committed = false;
      try {
        await client1.query('BEGIN');
        await client1.query('SET LOCAL rls.enable_tenant = on');
        await client1.query("SELECT set_config('app.current_org_id', $1, true)", [ORG_A_ID]);
        await client1.query('SELECT 1 FROM web_sessions WHERE session_id_hash = $1 FOR UPDATE', [
          session.sessionIdHash,
        ]);

        // 3. Start validation (blocks on FOR UPDATE of ws using validatorPool)
        const validationPromise = validatorService.resolveAndValidateSession(secret);

        // 4. Positively establish that validatorPid is waiting, blocked by lockerPid, on session validation in this database
        const causalEvidence = await waitForAttributedLock(
          adminClient,
          validatorPid,
          lockerPid,
          db.name,
          5000,
        );
        expect(causalEvidence.validatorPid).toBe(validatorPid);
        expect(causalEvidence.lockerPid).toBe(lockerPid);
        expect(causalEvidence.datname).toBe(db.name);
        expect(causalEvidence.waitEventType).toBe('Lock');
        expect(causalEvidence.blockingPids).toContain(lockerPid);
        expect(causalEvidence.query).toContain('FOR UPDATE OF ws');

        // 5. Revoke session and commit transaction
        await client1.query(
          'UPDATE web_sessions SET revoked_at = clock_timestamp() WHERE session_id_hash = $1',
          [session.sessionIdHash],
        );
        await client1.query('COMMIT');
        committed = true;

        // 6 & 7. Blocked validation releases and fails closed with SESSION_REVOKED
        const validationResult = await validationPromise;
        expect(validationResult.valid).toBe(false);
        expect(validationResult.reason).toBe('SESSION_REVOKED');
      } finally {
        if (!committed) {
          try {
            await client1.query('ROLLBACK');
          } catch {
            // ignore rollback error on test failure
          }
        }
        client1.release();
        await validatorPool.end();
      }
    });

    it('deterministic Ordering B — Validation first: validation completes and commits before revocation, subsequent validation fails (AUTH-08)', async () => {
      // 1. Create session
      const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

      // 2. Permit validation to complete and commit
      const validation1 = await sessionService.resolveAndValidateSession(secret);
      expect(validation1.valid).toBe(true);
      expect(validation1.user?.id).toBe(USER_A_ID);
      expect(validation1.user?.orgId).toBe(ORG_A_ID);

      // 3. Revoke and commit
      const revoked = await sessionService.revokeSession(secret);
      expect(revoked).toBe(true);

      // 4. Verify subsequent validation fails
      const validation2 = await sessionService.resolveAndValidateSession(secret);
      expect(validation2.valid).toBe(false);
      expect(validation2.reason).toBe('SESSION_REVOKED');
    });
  });

  describe('5. Cross-Tenant Isolation under RLS', () => {
    it('prevents cross-tenant access to web_sessions via withTenant RLS', async () => {
      const sessionB = await sessionService.createSession(ORG_B_ID, USER_B_ID);

      // When running inside Org A tenant context, web_sessions for Org B is invisible
      await withTenant(appPool, ORG_A_ID, async (client) => {
        const { rows } = await client.query(
          'SELECT * FROM public.web_sessions WHERE session_id_hash = $1',
          [sessionB.session.sessionIdHash],
        );
        expect(rows).toHaveLength(0);
      });

      // When running inside Org B tenant context, session B is visible
      await withTenant(appPool, ORG_B_ID, async (client) => {
        const { rows } = await client.query(
          'SELECT * FROM public.web_sessions WHERE session_id_hash = $1',
          [sessionB.session.sessionIdHash],
        );
        expect(rows).toHaveLength(1);
      });
    });

    it('denies all reads to web_sessions when no tenant context is set', async () => {
      const sessionA = await sessionService.createSession(ORG_A_ID, USER_A_ID);

      // Direct query without withTenant returns 0 rows due to RLS default-deny
      const client = await appPool.connect();
      try {
        const { rows } = await client.query(
          'SELECT * FROM public.web_sessions WHERE session_id_hash = $1',
          [sessionA.session.sessionIdHash],
        );
        expect(rows).toHaveLength(0);
      } finally {
        client.release();
      }
    });
  });

  describe('6. Pre-Tenant Lookup Error Handling (AUTHZ-05)', () => {
    it('returns null when session row does not exist in pre-tenant lookup', async () => {
      const nonexistentBytes = crypto.randomBytes(32);
      const orgId = await sessionService.lookupSessionOrgId(nonexistentBytes);
      expect(orgId).toBeNull();
    });

    it('throws SessionError DATABASE_ERROR when underlying pool.query throws', async () => {
      const faultyPool = {
        query: async () => {
          throw new Error('pg_pool query error');
        },
      } as unknown as pg.Pool;

      const testService = new SessionService({ pool: faultyPool });
      const testSecretBytes = crypto.randomBytes(32);

      await expect(testService.lookupSessionOrgId(testSecretBytes)).rejects.toThrowError(
        expect.objectContaining({
          name: 'SessionError',
          reason: 'DATABASE_ERROR',
          message: 'Database error during session lookup',
        }),
      );
    });
  });
});
