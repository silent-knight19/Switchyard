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
import { hashCsrfToken } from './csrf.js';
import { SessionError } from './types.js';

describe('SW-1.5.3: Session-Bound CSRF Protection PostgreSQL 16 Integration Suite', () => {
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

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    db = await createDisposableDatabase(cluster, 'csrf_service_test');
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

  it('1. Existing session has a stored CSRF verifier upon creation', async () => {
    const { session, csrfToken } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

    expect(session.csrfTokenHash).toBeDefined();
    expect(Buffer.isBuffer(session.csrfTokenHash)).toBe(true);
    expect(session.csrfTokenHash.length).toBe(32);
    expect(csrfToken.length).toBe(43);
  });

  it('2. Only the verifier hash is persisted in the database, never the plaintext CSRF token', async () => {
    const { session, csrfToken } = await sessionService.createSession(ORG_A_ID, USER_A_ID);
    const csrfBytes = Buffer.from(csrfToken, 'base64url');
    const expectedHash = hashCsrfToken(csrfBytes);

    const { rows } = await adminClient.query<{ csrf_token_hash: Buffer }>(
      'SELECT csrf_token_hash FROM public.web_sessions WHERE session_id_hash = $1',
      [session.sessionIdHash],
    );

    expect(rows.length).toBe(1);
    expect(rows[0]?.csrf_token_hash).toEqual(expectedHash);

    // Verify plaintext token string is nowhere in the table row
    const rawDump = await adminClient.query(
      'SELECT * FROM public.web_sessions WHERE session_id_hash = $1',
      [session.sessionIdHash],
    );
    expect(JSON.stringify(rawDump.rows)).not.toContain(csrfToken);
  });

  it('3. Correct token verifies for the corresponding session', async () => {
    const { secret, csrfToken } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

    const res = await sessionService.resolveAndValidateSessionWithCsrf(secret, csrfToken);
    expect(res.valid).toBe(true);
    expect(res.session?.userId).toBe(USER_A_ID);
    expect(res.user?.emailNormalized).toBe('user.a@alpha.com');
  });

  it('4. Wrong or forged token is rejected with CSRF_TOKEN_MISMATCH', async () => {
    const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ID);
    const forgedToken = crypto.randomBytes(32).toString('base64url');

    const res = await sessionService.resolveAndValidateSessionWithCsrf(secret, forgedToken);
    expect(res.valid).toBe(false);
    expect(res.reason).toBe('CSRF_TOKEN_MISMATCH');
  });

  it('5. Token from Session A fails against Session B', async () => {
    const sessionA = await sessionService.createSession(ORG_A_ID, USER_A_ID);
    const sessionB = await sessionService.createSession(ORG_A_ID, USER_A_ID);

    const res = await sessionService.resolveAndValidateSessionWithCsrf(
      sessionB.secret,
      sessionA.csrfToken,
    );
    expect(res.valid).toBe(false);
    expect(res.reason).toBe('CSRF_TOKEN_MISMATCH');
  });

  it('6. Cross-tenant token replay fails under RLS isolation', async () => {
    const sessionA = await sessionService.createSession(ORG_A_ID, USER_A_ID);
    const sessionB = await sessionService.createSession(ORG_B_ID, USER_B_ID);

    // Using Org A's token with Org B's session secret
    const res = await sessionService.resolveAndValidateSessionWithCsrf(
      sessionB.secret,
      sessionA.csrfToken,
    );
    expect(res.valid).toBe(false);
    expect(res.reason).toBe('CSRF_TOKEN_MISMATCH');
  });

  it('7. Token issuance (reissueCsrfToken) updates only the intended session', async () => {
    const s1 = await sessionService.createSession(ORG_A_ID, USER_A_ID);
    const s2 = await sessionService.createSession(ORG_A_ID, USER_A_ID);

    const reissued = await sessionService.reissueCsrfToken(s1.secret);
    expect(reissued.csrfToken).toBeDefined();
    expect(reissued.csrfToken).not.toBe(s1.csrfToken);

    // Check database: s1 is updated, s2 is unchanged
    const { rows: rows1 } = await adminClient.query<{ csrf_token_hash: Buffer }>(
      'SELECT csrf_token_hash FROM public.web_sessions WHERE session_id_hash = $1',
      [s1.session.sessionIdHash],
    );
    const { rows: rows2 } = await adminClient.query<{ csrf_token_hash: Buffer }>(
      'SELECT csrf_token_hash FROM public.web_sessions WHERE session_id_hash = $1',
      [s2.session.sessionIdHash],
    );

    expect(rows1[0]?.csrf_token_hash).toEqual(
      hashCsrfToken(Buffer.from(reissued.csrfToken, 'base64url')),
    );
    expect(rows2[0]?.csrf_token_hash).toEqual(s2.session.csrfTokenHash);
  });

  it('8. Old token fails after committed reissue', async () => {
    const { secret, csrfToken: oldToken } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

    await sessionService.reissueCsrfToken(secret);

    const oldCheck = await sessionService.resolveAndValidateSessionWithCsrf(secret, oldToken);
    expect(oldCheck.valid).toBe(false);
    expect(oldCheck.reason).toBe('CSRF_TOKEN_MISMATCH');
  });

  it('9. New token succeeds after committed reissue', async () => {
    const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

    const { csrfToken: newToken } = await sessionService.reissueCsrfToken(secret);

    const newCheck = await sessionService.resolveAndValidateSessionWithCsrf(secret, newToken);
    expect(newCheck.valid).toBe(true);
    expect(newCheck.user?.id).toBe(USER_A_ID);
  });

  it('10. Concurrent issuance follows last-committed-wins behavior', async () => {
    const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

    // Concurrently reissue two tokens for the same session
    const [res1, res2] = await Promise.all([
      sessionService.reissueCsrfToken(secret),
      sessionService.reissueCsrfToken(secret),
    ]);

    expect(res1.csrfToken).not.toBe(res2.csrfToken);

    // One of the two tokens is the last-committed winner
    const check1 = await sessionService.resolveAndValidateSessionWithCsrf(secret, res1.csrfToken);
    const check2 = await sessionService.resolveAndValidateSessionWithCsrf(secret, res2.csrfToken);

    const winCount = (check1.valid ? 1 : 0) + (check2.valid ? 1 : 0);
    expect(winCount).toBe(1);

    if (check1.valid) {
      expect(check2.reason).toBe('CSRF_TOKEN_MISMATCH');
    } else {
      expect(check1.reason).toBe('CSRF_TOKEN_MISMATCH');
    }
  });

  it('11. Revoked session cannot issue or verify tokens', async () => {
    const { secret, csrfToken } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

    // Revoke session
    await sessionService.revokeSession(secret);

    // Reissue fails
    await expect(sessionService.reissueCsrfToken(secret)).rejects.toThrow(SessionError);
    try {
      await sessionService.reissueCsrfToken(secret);
    } catch (err) {
      expect(err).toBeInstanceOf(SessionError);
      expect((err as SessionError).reason).toBe('SESSION_REVOKED');
    }

    // Validation fails with SESSION_REVOKED
    const valRes = await sessionService.resolveAndValidateSessionWithCsrf(secret, csrfToken);
    expect(valRes.valid).toBe(false);
    expect(valRes.reason).toBe('SESSION_REVOKED');
  });

  it('12. Idle-expired session cannot issue or verify tokens', async () => {
    const { secret, csrfToken, session } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

    // Manually expire idle timestamp
    await adminClient.query(
      `UPDATE public.web_sessions
      SET idle_expires_at = clock_timestamp() - interval '1 minute'
      WHERE session_id_hash = $1`,
      [session.sessionIdHash],
    );

    // Reissue fails
    await expect(sessionService.reissueCsrfToken(secret)).rejects.toThrow(SessionError);
    try {
      await sessionService.reissueCsrfToken(secret);
    } catch (err) {
      expect(err).toBeInstanceOf(SessionError);
      expect((err as SessionError).reason).toBe('SESSION_EXPIRED_IDLE');
    }

    // Validation fails
    const valRes = await sessionService.resolveAndValidateSessionWithCsrf(secret, csrfToken);
    expect(valRes.valid).toBe(false);
    expect(valRes.reason).toBe('SESSION_EXPIRED_IDLE');
  });

  it('13. Absolutely expired session cannot issue or verify tokens', async () => {
    const { secret, csrfToken, session } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

    // Manually expire absolute timestamp
    await adminClient.query(
      `UPDATE public.web_sessions
      SET absolute_expires_at = clock_timestamp() - interval '1 minute'
      WHERE session_id_hash = $1`,
      [session.sessionIdHash],
    );

    // Reissue fails
    await expect(sessionService.reissueCsrfToken(secret)).rejects.toThrow(SessionError);
    try {
      await sessionService.reissueCsrfToken(secret);
    } catch (err) {
      expect(err).toBeInstanceOf(SessionError);
      expect((err as SessionError).reason).toBe('SESSION_EXPIRED_ABSOLUTE');
    }

    // Validation fails
    const valRes = await sessionService.resolveAndValidateSessionWithCsrf(secret, csrfToken);
    expect(valRes.valid).toBe(false);
    expect(valRes.reason).toBe('SESSION_EXPIRED_ABSOLUTE');
  });

  it('14. Session rotation invalidates old-session authority and issues fresh CSRF token', async () => {
    const { secret: oldSecret, csrfToken: oldToken } = await sessionService.createSession(
      ORG_A_ID,
      USER_A_ID,
    );

    const rotated = await sessionService.rotateSession(oldSecret);

    expect(rotated.newCsrfToken).toBeDefined();
    expect(rotated.newCsrfToken).not.toBe(oldToken);

    // Old secret + old token fails with SESSION_REVOKED
    const checkOld = await sessionService.resolveAndValidateSessionWithCsrf(oldSecret, oldToken);
    expect(checkOld.valid).toBe(false);
    expect(checkOld.reason).toBe('SESSION_REVOKED');

    // New secret + old token fails with CSRF_TOKEN_MISMATCH
    const checkMixed = await sessionService.resolveAndValidateSessionWithCsrf(
      rotated.newSecret,
      oldToken,
    );
    expect(checkMixed.valid).toBe(false);
    expect(checkMixed.reason).toBe('CSRF_TOKEN_MISMATCH');

    // New secret + new token succeeds
    const checkNew = await sessionService.resolveAndValidateSessionWithCsrf(
      rotated.newSecret,
      rotated.newCsrfToken,
    );
    expect(checkNew.valid).toBe(true);
    expect(checkNew.user?.id).toBe(USER_A_ID);
  });

  it('15. Token issuance transaction rollback leaves prior committed verifier intact', async () => {
    const {
      secret,
      csrfToken: originalToken,
      session,
    } = await sessionService.createSession(ORG_A_ID, USER_A_ID);

    // Simulate an aborted transaction directly under withTenant
    try {
      await withTenant(appPool, ORG_A_ID, async (client) => {
        const candidateHash = hashCsrfToken(crypto.randomBytes(32));
        await client.query(
          'UPDATE public.web_sessions SET csrf_token_hash = $1 WHERE session_id_hash = $2',
          [candidateHash, session.sessionIdHash],
        );
        // Force error to trigger withTenant automatic ROLLBACK
        throw new Error('Simulated failure during reissue');
      });
    } catch {
      // Expected error from callback
    }

    // Original token still validates successfully after rollback
    const checkRes = await sessionService.resolveAndValidateSessionWithCsrf(secret, originalToken);
    expect(checkRes.valid).toBe(true);
  });

  it('16. Pooled connections do not leak tenant context', async () => {
    const { secret, csrfToken } = await sessionService.createSession(ORG_A_ID, USER_A_ID);
    await sessionService.resolveAndValidateSessionWithCsrf(secret, csrfToken);

    // Verify tenant setting is not retained on a client from the pool
    const client = await appPool.connect();
    try {
      const res = await client.query(
        "SELECT current_setting('app.current_org_id', true) AS org_id",
      );
      expect(res.rows[0]?.org_id).toBe('');
    } finally {
      client.release();
    }
  });

  it('17. Direct cross-tenant access remains denied under RLS', async () => {
    const sessionB = await sessionService.createSession(ORG_B_ID, USER_B_ID);

    // Connect under Org A context and attempt to read or modify Org B's session
    await withTenant(appPool, ORG_A_ID, async (client) => {
      const selectRes = await client.query(
        'SELECT * FROM public.web_sessions WHERE session_id_hash = $1',
        [sessionB.session.sessionIdHash],
      );
      expect(selectRes.rows.length).toBe(0);

      const updateRes = await client.query(
        'UPDATE public.web_sessions SET csrf_token_hash = $1 WHERE session_id_hash = $2',
        [Buffer.from('faked_hash'), sessionB.session.sessionIdHash],
      );
      expect(updateRes.rowCount).toBe(0);
    });
  });

  it('18. No-context access remains denied under RLS', async () => {
    const sessionA = await sessionService.createSession(ORG_A_ID, USER_A_ID);

    const client = await appPool.connect();
    try {
      const res = await client.query(
        'SELECT * FROM public.web_sessions WHERE session_id_hash = $1',
        [sessionA.session.sessionIdHash],
      );
      expect(res.rows.length).toBe(0);
    } finally {
      client.release();
    }
  });

  it('19. Existing pre-tenant privileged function remains restricted', async () => {
    const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ID);
    const secretBytes = Buffer.from(secret, 'base64url');
    const sessionIdHash = hashSecret(secretBytes);

    // Function resolves org_id for gateway_app
    const orgId = await sessionService.lookupSessionOrgId(secretBytes);
    expect(orgId).toBe(ORG_A_ID);

    // Verify return type contains ONLY org_id (no secrets or hashes)
    const { rows } = await appPool.query(
      'SELECT * FROM app_private.lookup_session_org_by_hash($1)',
      [sessionIdHash],
    );
    expect(rows.length).toBe(1);
    expect(Object.keys(rows[0] as object)).toEqual(['org_id']);
  });

  it('20. Runtime role permissions remain restricted (no DDL, no bypass)', async () => {
    const client = await appPool.connect();
    try {
      // Cannot alter tables
      await expect(
        client.query('ALTER TABLE public.web_sessions ADD COLUMN temp_test INT'),
      ).rejects.toThrow();

      // Cannot drop tables
      await expect(client.query('DROP TABLE public.web_sessions')).rejects.toThrow();
    } finally {
      client.release();
    }
  });
});
