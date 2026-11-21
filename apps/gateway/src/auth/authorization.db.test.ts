import crypto from 'node:crypto';
import fastify, { type FastifyRequest } from 'fastify';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
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
import { type AuthorizedPrincipal, installAuthorizationBoundary } from './authorization.js';

describe('SW-1.5.4: Real PostgreSQL 16 Browser Authorization & RBAC Suite (Section 14)', () => {
  let cluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();
  let adminClient: pg.Client;
  let appPool: pg.Pool;
  let sessionService: SessionService;
  let cookieName: string;

  const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
  const ORG_B_ID = '22222222-2222-4222-8222-222222222222';
  const USER_A_MEMBER_ID = 'aaaaaaaa-1111-4aaa-8aaa-aaaaaaaaaaaa';
  const USER_A_ADMIN_ID = 'aaaaaaaa-2222-4aaa-8aaa-aaaaaaaaaaaa';
  const USER_B_MEMBER_ID = 'bbbbbbbb-1111-4bbb-8bbb-bbbbbbbbbbbb';

  const TRUSTED_ORIGIN = 'https://app.switchyard.internal';

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    db = await createDisposableDatabase(cluster, 'authz_db_test');
    await bootstrapDatabase(db, passwords);

    // Run authoritative migrations 0001 through 0011
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

    // Connect admin client for test seeding
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
        ('${USER_A_MEMBER_ID}', '${ORG_A_ID}', 'member@alpha.com', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$dGVzdA', 'member'),
        ('${USER_A_ADMIN_ID}', '${ORG_A_ID}', 'admin@alpha.com', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$dGVzdA', 'admin'),
        ('${USER_B_MEMBER_ID}', '${ORG_B_ID}', 'member@beta.com', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$dGVzdA', 'member');
    `);

    // Connect runtime gateway_app pool
    appPool = new pg.Pool({
      connectionString: roleConnectionString(db.url, 'gateway_app', passwords.gateway_app),
    });

    sessionService = new SessionService({
      pool: appPool,
      cookieOptions: { isProduction: true },
    });
    cookieName = sessionService.getCookieName();
  }, 60000);

  afterAll(async () => {
    if (appPool) await appPool.end();
    if (adminClient) await adminClient.end();
    if (db) await db.drop();
    if (cluster) await cluster.stop();
  }, 30000);

  function cookieHeader(secret: string): { cookie: string } {
    return { cookie: `${cookieName}=${secret}` };
  }

  /**
   * Helper to build a test Fastify app wired to the real sessionService and authorization boundary
   */
  async function createTestApp() {
    const app = fastify();
    installAuthorizationBoundary(app, {
      sessionService,
      trustedOrigin: TRUSTED_ORIGIN,
    });

    // Register test routes
    app.get(
      '/test/member-only',
      { config: { authz: { principal: 'browser', minRole: 'member' } } },
      async (req: FastifyRequest) => ({
        allowed: true,
        principal: req.principal,
      }),
    );

    app.get(
      '/test/admin-only',
      { config: { authz: { principal: 'browser', minRole: 'admin' } } },
      async (req: FastifyRequest) => ({
        allowed: true,
        principal: req.principal,
      }),
    );

    await app.ready();
    return app;
  }

  it('1. Member session authenticates via real PostgreSQL session validation', async () => {
    const { secret, session } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);
    const res = await sessionService.resolveAndValidateSession(secret);

    expect(res.valid).toBe(true);
    expect(res.user?.id).toBe(USER_A_MEMBER_ID);
    expect(res.user?.orgId).toBe(ORG_A_ID);
    expect(res.user?.role).toBe('member');
    expect(res.session?.sessionIdHash).toEqual(session.sessionIdHash);
  });

  it('2. Admin session authenticates via real PostgreSQL session validation', async () => {
    const { secret, session } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);
    const res = await sessionService.resolveAndValidateSession(secret);

    expect(res.valid).toBe(true);
    expect(res.user?.id).toBe(USER_A_ADMIN_ID);
    expect(res.user?.orgId).toBe(ORG_A_ID);
    expect(res.user?.role).toBe('admin');
    expect(res.session?.sessionIdHash).toEqual(session.sessionIdHash);
  });

  it('3. Member accesses member-required route successfully', async () => {
    const app = await createTestApp();
    const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

    const res = await app.inject({
      method: 'GET',
      url: '/test/member-only',
      headers: cookieHeader(secret),
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.allowed).toBe(true);
    expect(body.principal).toEqual({
      type: 'browser',
      userId: USER_A_MEMBER_ID,
      orgId: ORG_A_ID,
      role: 'member',
    });
    await app.close();
  });

  it('4. Admin accesses member-required route successfully (role hierarchy)', async () => {
    const app = await createTestApp();
    const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

    const res = await app.inject({
      method: 'GET',
      url: '/test/member-only',
      headers: cookieHeader(secret),
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.allowed).toBe(true);
    expect(body.principal.role).toBe('admin');
    await app.close();
  });

  it('5. Admin accesses admin-required route successfully', async () => {
    const app = await createTestApp();
    const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

    const res = await app.inject({
      method: 'GET',
      url: '/test/admin-only',
      headers: cookieHeader(secret),
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.allowed).toBe(true);
    expect(body.principal).toEqual({
      type: 'browser',
      userId: USER_A_ADMIN_ID,
      orgId: ORG_A_ID,
      role: 'admin',
    });
    await app.close();
  });

  it('6. Member fails admin-required route with 403 Forbidden', async () => {
    const app = await createTestApp();
    const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

    const res = await app.inject({
      method: 'GET',
      url: '/test/admin-only',
      headers: cookieHeader(secret),
    });

    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({
      statusCode: 403,
      error: 'Forbidden',
      message: 'Forbidden',
    });
    await app.close();
  });

  it('7. Missing session cookie fails with 401 Unauthorized', async () => {
    const app = await createTestApp();
    const res = await app.inject({
      method: 'GET',
      url: '/test/member-only',
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().message).toBe('Authentication required');
    await app.close();
  });

  it('8. Malformed session cookie fails with 401 Unauthorized', async () => {
    const app = await createTestApp();
    const res = await app.inject({
      method: 'GET',
      url: '/test/member-only',
      headers: {
        cookie: `${cookieName}=invalid-not-43-chars`,
      },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().message).toBe('Authentication required');
    await app.close();
  });

  it('9. Unknown (nonexistent) session secret fails with 401 Unauthorized', async () => {
    const app = await createTestApp();
    // Valid 43 base64url characters representing 32 random bytes, not in DB
    const randomSecret = crypto.randomBytes(32).toString('base64url');

    const res = await app.inject({
      method: 'GET',
      url: '/test/member-only',
      headers: cookieHeader(randomSecret),
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().message).toBe('Authentication required');
    await app.close();
  });

  it('10. Revoked session fails with 401 Unauthorized', async () => {
    const app = await createTestApp();
    const { secret, session } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

    // Revoke session in PostgreSQL
    await adminClient.query(
      'UPDATE public.web_sessions SET revoked_at = clock_timestamp() WHERE session_id_hash = $1',
      [session.sessionIdHash],
    );

    const res = await app.inject({
      method: 'GET',
      url: '/test/member-only',
      headers: cookieHeader(secret),
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().message).toBe('Authentication required');
    await app.close();
  });

  it('11. Idle-expired session fails with 401 Unauthorized', async () => {
    const app = await createTestApp();
    const { secret, session } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

    // Set idle_expires_at to 1 hour in the past
    await adminClient.query(
      "UPDATE public.web_sessions SET idle_expires_at = clock_timestamp() - interval '1 hour' WHERE session_id_hash = $1",
      [session.sessionIdHash],
    );

    const res = await app.inject({
      method: 'GET',
      url: '/test/member-only',
      headers: cookieHeader(secret),
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().message).toBe('Authentication required');
    await app.close();
  });

  it('12. Absolutely expired session fails with 401 Unauthorized', async () => {
    const app = await createTestApp();
    const { secret, session } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

    // Set absolute_expires_at to 1 hour in the past
    await adminClient.query(
      "UPDATE public.web_sessions SET absolute_expires_at = clock_timestamp() - interval '1 hour' WHERE session_id_hash = $1",
      [session.sessionIdHash],
    );

    const res = await app.inject({
      method: 'GET',
      url: '/test/member-only',
      headers: cookieHeader(secret),
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().message).toBe('Authentication required');
    await app.close();
  });

  it('13. Deleted session row fails with 401 Unauthorized', async () => {
    const app = await createTestApp();
    const { secret, session } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

    // Delete session from DB
    await adminClient.query('DELETE FROM public.web_sessions WHERE session_id_hash = $1', [
      session.sessionIdHash,
    ]);

    const res = await app.inject({
      method: 'GET',
      url: '/test/member-only',
      headers: cookieHeader(secret),
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().message).toBe('Authentication required');
    await app.close();
  });

  it('14. Role is obtained directly from current PostgreSQL user state on every request', async () => {
    const app = await createTestApp();
    const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

    const resBefore = await app.inject({
      method: 'GET',
      url: '/test/admin-only',
      headers: cookieHeader(secret),
    });
    expect(resBefore.statusCode).toBe(403);

    // Promote member to admin in PostgreSQL
    await adminClient.query(
      "UPDATE public.users SET role = 'admin' WHERE id = $1 AND org_id = $2",
      [USER_A_MEMBER_ID, ORG_A_ID],
    );

    // Next request immediately reflects the promoted role from DB without caching
    const resAfter = await app.inject({
      method: 'GET',
      url: '/test/admin-only',
      headers: cookieHeader(secret),
    });
    expect(resAfter.statusCode).toBe(200);
    expect(resAfter.json().allowed).toBe(true);

    // Restore member role
    await adminClient.query(
      "UPDATE public.users SET role = 'member' WHERE id = $1 AND org_id = $2",
      [USER_A_MEMBER_ID, ORG_A_ID],
    );

    // Verify role demotion is immediately effective
    const resRestored = await app.inject({
      method: 'GET',
      url: '/test/admin-only',
      headers: cookieHeader(secret),
    });
    expect(resRestored.statusCode).toBe(403);
    await app.close();
  });

  it('15. A stale member role is not trusted after a database role change', async () => {
    const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

    const val1 = await sessionService.resolveAndValidateSession(secret);
    expect(val1.user?.role).toBe('member');

    // Update in DB
    await adminClient.query(
      "UPDATE public.users SET role = 'admin' WHERE id = $1 AND org_id = $2",
      [USER_A_MEMBER_ID, ORG_A_ID],
    );

    const val2 = await sessionService.resolveAndValidateSession(secret);
    expect(val2.user?.role).toBe('admin');

    // Revert
    await adminClient.query(
      "UPDATE public.users SET role = 'member' WHERE id = $1 AND org_id = $2",
      [USER_A_MEMBER_ID, ORG_A_ID],
    );
  });

  it('16. Security-sensitive role-change revocation invalidates prior sessions', async () => {
    const app = await createTestApp();
    const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

    // Active session before revocation
    const resBefore = await app.inject({
      method: 'GET',
      url: '/test/member-only',
      headers: cookieHeader(secret),
    });
    expect(resBefore.statusCode).toBe(200);

    // Trigger revocation of all user sessions across the organization
    const count = await sessionService.revokeAllUserSessions(ORG_A_ID, USER_A_MEMBER_ID);
    expect(count).toBeGreaterThan(0);

    // Request with prior session must fail 401
    const resAfter = await app.inject({
      method: 'GET',
      url: '/test/member-only',
      headers: cookieHeader(secret),
    });
    expect(resAfter.statusCode).toBe(401);
    await app.close();
  });

  it('17. Session user ID and organization ID must agree (composite FK & application verification)', async () => {
    // 1. PostgreSQL composite foreign key strictly prevents storing mismatched user_id and org_id
    const fakeSecretBytes = crypto.randomBytes(32);
    const fakeHash = hashSecret(fakeSecretBytes);
    const fakeCsrfHash = crypto.randomBytes(32);

    await expect(
      adminClient.query(
        `INSERT INTO public.web_sessions (session_id_hash, user_id, org_id, csrf_token_hash, last_seen_at, idle_expires_at, absolute_expires_at)
         VALUES ($1, $2, $3, $4, clock_timestamp(), clock_timestamp() + interval '2 hours', clock_timestamp() + interval '7 days')`,
        [fakeHash, USER_A_MEMBER_ID, ORG_B_ID, fakeCsrfHash],
      ),
    ).rejects.toThrow(/violates foreign key constraint/i);

    // 2. An unknown secret that cannot resolve matching user returns invalid
    const randomSecret = crypto.randomBytes(32).toString('base64url');
    const res = await sessionService.resolveAndValidateSession(randomSecret);
    expect(res.valid).toBe(false);
  });

  it('18. Cross-organization principal spoofing fails', async () => {
    const app = await createTestApp();
    // Create valid session for User B in Org Beta
    const { secret } = await sessionService.createSession(ORG_B_ID, USER_B_MEMBER_ID);

    // User B calls route with Org A spoofing headers
    const res = await app.inject({
      method: 'GET',
      url: '/test/member-only',
      headers: {
        ...cookieHeader(secret),
        'x-org-id': ORG_A_ID,
        'x-tenant-id': ORG_A_ID,
      },
    });

    expect(res.statusCode).toBe(200);
    const principal: AuthorizedPrincipal = res.json().principal;
    // Principal MUST resolve to Org B (from DB session), never Org A
    expect(principal.type).toBe('browser');
    if (principal.type === 'browser') {
      expect(principal.orgId).toBe(ORG_B_ID);
      expect(principal.userId).toBe(USER_B_MEMBER_ID);
    }
    await app.close();
  });

  it('19. User-controlled organization headers are completely ignored for authorization', async () => {
    const app = await createTestApp();
    const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

    const res = await app.inject({
      method: 'GET',
      url: '/test/admin-only',
      headers: {
        ...cookieHeader(secret),
        'x-org-id': '99999999-9999-4999-8999-999999999999',
        'x-tenant-id': '99999999-9999-4999-8999-999999999999',
      },
    });

    expect(res.statusCode).toBe(200);
    const principal = res.json().principal;
    expect(principal.orgId).toBe(ORG_A_ID);
    await app.close();
  });

  it('20. No-context and cross-tenant SQL access remain strictly denied by FORCE RLS', async () => {
    // Ensure at least one active session exists
    const { session } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

    // 1. Direct SELECT query on gateway_app connection without withTenant returns 0 rows due to RLS filter
    const rawClient = await appPool.connect();
    try {
      const { rows } = await rawClient.query('SELECT * FROM public.web_sessions');
      expect(rows.length).toBe(0);

      // Direct INSERT without tenant context violates RLS policy check
      const fakeSecretBytes = crypto.randomBytes(32);
      const fakeHash = hashSecret(fakeSecretBytes);
      const fakeCsrf = crypto.randomBytes(32);
      await expect(
        rawClient.query(
          `INSERT INTO public.web_sessions (session_id_hash, user_id, org_id, csrf_token_hash, last_seen_at, idle_expires_at, absolute_expires_at)
           VALUES ($1, $2, $3, $4, clock_timestamp(), clock_timestamp() + interval '2 hours', clock_timestamp() + interval '7 days')`,
          [fakeHash, USER_A_MEMBER_ID, ORG_A_ID, fakeCsrf],
        ),
      ).rejects.toThrow(/violates row-level security policy/i);
    } finally {
      rawClient.release();
    }

    // 2. Query under Org B tenant context cannot see Org A sessions
    await withTenant(appPool, ORG_B_ID, async (tenantClient) => {
      const { rows } = await tenantClient.query(
        'SELECT * FROM public.web_sessions WHERE session_id_hash = $1',
        [session.sessionIdHash],
      );
      expect(rows.length).toBe(0);
    });
  });

  it('21. Database failure does not authenticate (fails closed with safe 5xx)', async () => {
    const app = await createTestApp();
    const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

    // Simulate database failure during session resolution
    const dbSpy = vi
      .spyOn(sessionService, 'resolveAndValidateSession')
      .mockRejectedValueOnce(new Error('PostgreSQL pool connection timeout'));

    const res = await app.inject({
      method: 'GET',
      url: '/test/member-only',
      headers: cookieHeader(secret),
    });

    expect(res.statusCode).toBe(503);
    expect(res.json()).toEqual({
      statusCode: 503,
      error: 'Service Unavailable',
      message: 'Authentication service unavailable',
    });

    dbSpy.mockRestore();
    await app.close();
  });

  it('22. Pooled connections do not leak tenant context across invocations', async () => {
    // Run tenant A query
    await withTenant(appPool, ORG_A_ID, async (client) => {
      const { rows } = await client.query('SELECT current_setting($1, true) as org', [
        'app.current_org_id',
      ]);
      expect(rows[0]?.org).toBe(ORG_A_ID);
    });

    // Acquire raw connection from pool and verify tenant context was completely cleared
    const rawClient = await appPool.connect();
    try {
      const { rows } = await rawClient.query('SELECT current_setting($1, true) as org', [
        'app.current_org_id',
      ]);
      expect(rows[0]?.org === '' || rows[0]?.org === null).toBe(true);
    } finally {
      rawClient.release();
    }
  });
});
