import crypto from 'node:crypto';
import fastify, { type FastifyRequest } from 'fastify';
import pg from 'pg';
import pino from 'pino';
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
import { SessionService } from './session.js';
import { SessionError } from './types.js';
import {
  type AuthorizedPrincipal,
  type VirtualKeyAuthenticator,
  installAuthorizationBoundary,
} from './authorization.js';
import { buildApp } from '../app.js';
import { loadConfig } from '../config/index.js';

describe('SW-1.5.4: HTTP Authorization, Principal Separation & RBAC Suite (Sections 15, 16, 17)', () => {
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

  const ALLOWED_ORIGIN = 'https://app.switchyard.internal';
  const DISALLOWED_ORIGIN = 'https://evil.attacker.com';

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    db = await createDisposableDatabase(cluster, 'authz_http_test');
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

    // Connect admin client for test fixtures
    adminClient = new pg.Client({ connectionString: db.url });
    await adminClient.connect();

    // Seed organizations and users
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

    // Connect gateway_app pool
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

  // Helper for session cookies
  function makeCookieHeader(secret: string): string {
    return `${cookieName}=${secret}`;
  }

  // Test harness creating Fastify app with test route fixtures representing matrix categories
  interface TestAppSetup {
    app: ReturnType<typeof fastify>;
    vkAuthenticator: VirtualKeyAuthenticator;
    getMemberMutationCount: () => number;
    getAdminMutationCount: () => number;
  }

  function setupTestApp(): TestAppSetup {
    const app = fastify();

    let memberMutationCount = 0;
    let adminMutationCount = 0;

    const vkAuthenticator: VirtualKeyAuthenticator = {
      authenticateKey: async (rawKey: string) => {
        if (rawKey === 'valid_test_virtual_key_secret_token') {
          return {
            valid: true,
            principal: {
              type: 'virtual_key',
              keyId: 'vk-12345',
              orgId: ORG_A_ID,
            },
          };
        }
        return { valid: false, reason: 'INVALID_VIRTUAL_KEY' };
      },
    };

    installAuthorizationBoundary(app, {
      sessionService,
      trustedOrigin: ALLOWED_ORIGIN,
      virtualKeyAuthenticator: vkAuthenticator,
    });

    // 1. Anonymous health GET
    app.get('/health/live', { config: { authz: { principal: 'anonymous' } } }, async () => ({
      status: 'ok',
    }));

    // 2. Member browser GET (read)
    app.get(
      '/api/profile',
      { config: { authz: { principal: 'browser', minRole: 'member' } } },
      async (req: FastifyRequest) => ({
        profile: 'user_profile',
        principal: req.principal,
      }),
    );

    // 3. Admin browser GET (read)
    app.get(
      '/api/audit/logs',
      { config: { authz: { principal: 'browser', minRole: 'admin' } } },
      async (req: FastifyRequest) => ({
        logs: ['log1'],
        principal: req.principal,
      }),
    );

    // 4. Member browser POST (mutation)
    app.post(
      '/api/profile/update',
      { config: { authz: { principal: 'browser', minRole: 'member' } } },
      async (req: FastifyRequest) => {
        memberMutationCount++;
        return { updated: true, principal: req.principal };
      },
    );

    // 5. Admin browser POST (mutation)
    app.post(
      '/api/org/settings',
      { config: { authz: { principal: 'browser', minRole: 'admin' } } },
      async (req: FastifyRequest) => {
        adminMutationCount++;
        return { updated: true, principal: req.principal };
      },
    );

    // 6. Virtual-key POST (data plane inference)
    app.post(
      '/v1/chat/completions',
      { config: { authz: { principal: 'virtual_key' } } },
      async (req: FastifyRequest) => ({
        id: 'chatcmpl-1',
        principal: req.principal,
      }),
    );

    // 7. Browser route with OPTIONS method for testing unsupported method rejection
    app.route({
      method: 'OPTIONS',
      url: '/api/browser/options',
      config: { authz: { principal: 'browser', minRole: 'member' } },
      handler: async () => ({ ok: true }),
    });

    return {
      app,
      vkAuthenticator,
      getMemberMutationCount: () => memberMutationCount,
      getAdminMutationCount: () => adminMutationCount,
    };
  }

  describe('Section 15: CSRF + RBAC Composition Matrix (Exact 10 Rows)', () => {
    it('Row 1: Valid admin | Valid origin | Valid CSRF | Admin required -> Allow (200)', async () => {
      const { app, getAdminMutationCount } = setupTestApp();
      await app.ready();
      const { secret, csrfToken } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

      const res = await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookieHeader(secret),
          'x-csrf-token': csrfToken,
        },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json().updated).toBe(true);
      expect(getAdminMutationCount()).toBe(1);
      await app.close();
    });

    it('Row 2: Valid member | Valid origin | Valid CSRF | Member required -> Allow (200)', async () => {
      const { app, getMemberMutationCount } = setupTestApp();
      await app.ready();
      const { secret, csrfToken } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

      const res = await app.inject({
        method: 'POST',
        url: '/api/profile/update',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookieHeader(secret),
          'x-csrf-token': csrfToken,
        },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json().updated).toBe(true);
      expect(getMemberMutationCount()).toBe(1);
      await app.close();
    });

    it('Row 3: Valid member | Valid origin | Valid CSRF | Admin required -> Deny (403 Forbidden)', async () => {
      const { app, getAdminMutationCount } = setupTestApp();
      await app.ready();
      const { secret, csrfToken } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

      const res = await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookieHeader(secret),
          'x-csrf-token': csrfToken,
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json()).toEqual({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Forbidden',
      });
      expect(getAdminMutationCount()).toBe(0);
      await app.close();
    });

    it('Row 4: Valid admin | Missing origin | Valid CSRF | Admin required -> Deny (403 Invalid or missing Origin)', async () => {
      const { app, getAdminMutationCount } = setupTestApp();
      await app.ready();
      const { secret, csrfToken } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

      const res = await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: {
          cookie: makeCookieHeader(secret),
          'x-csrf-token': csrfToken,
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().message).toBe('Invalid or missing Origin');
      expect(getAdminMutationCount()).toBe(0);
      await app.close();
    });

    it('Row 5: Valid admin | Wrong origin | Valid CSRF | Admin required -> Deny (403 Invalid or missing Origin)', async () => {
      const { app, getAdminMutationCount } = setupTestApp();
      await app.ready();
      const { secret, csrfToken } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

      const res = await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: {
          origin: DISALLOWED_ORIGIN,
          cookie: makeCookieHeader(secret),
          'x-csrf-token': csrfToken,
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().message).toBe('Invalid or missing Origin');
      expect(getAdminMutationCount()).toBe(0);
      await app.close();
    });

    it('Row 6: Valid admin | Valid origin | Missing CSRF | Admin required -> Deny (403 Invalid or missing CSRF token)', async () => {
      const { app, getAdminMutationCount } = setupTestApp();
      await app.ready();
      const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

      const res = await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookieHeader(secret),
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().message).toBe('Invalid or missing CSRF token');
      expect(getAdminMutationCount()).toBe(0);
      await app.close();
    });

    it('Row 7: Valid admin | Valid origin | Forged CSRF | Admin required -> Deny (403 Invalid or missing CSRF token)', async () => {
      const { app, getAdminMutationCount } = setupTestApp();
      await app.ready();
      const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);
      const forgedCsrf = crypto.randomBytes(32).toString('base64url');

      const res = await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookieHeader(secret),
          'x-csrf-token': forgedCsrf,
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().message).toBe('Invalid or missing CSRF token');
      expect(getAdminMutationCount()).toBe(0);
      await app.close();
    });

    it('Row 8: Revoked admin | Valid origin | Valid CSRF | Admin required -> Deny (401 Authentication required)', async () => {
      const { app, getAdminMutationCount } = setupTestApp();
      await app.ready();
      const { secret, csrfToken, session } = await sessionService.createSession(
        ORG_A_ID,
        USER_A_ADMIN_ID,
      );

      // Revoke session
      await adminClient.query(
        'UPDATE public.web_sessions SET revoked_at = clock_timestamp() WHERE session_id_hash = $1',
        [session.sessionIdHash],
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookieHeader(secret),
          'x-csrf-token': csrfToken,
        },
      });

      expect(res.statusCode).toBe(401);
      expect(res.json().message).toBe('Authentication required');
      expect(getAdminMutationCount()).toBe(0);
      await app.close();
    });

    it('Row 9: Expired admin | Valid origin | Valid CSRF | Admin required -> Deny (401 Authentication required)', async () => {
      const { app, getAdminMutationCount } = setupTestApp();
      await app.ready();
      const { secret, csrfToken, session } = await sessionService.createSession(
        ORG_A_ID,
        USER_A_ADMIN_ID,
      );

      // Expire session
      await adminClient.query(
        "UPDATE public.web_sessions SET idle_expires_at = clock_timestamp() - interval '10 minutes' WHERE session_id_hash = $1",
        [session.sessionIdHash],
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookieHeader(secret),
          'x-csrf-token': csrfToken,
        },
      });

      expect(res.statusCode).toBe(401);
      expect(res.json().message).toBe('Authentication required');
      expect(getAdminMutationCount()).toBe(0);
      await app.close();
    });

    it('Row 10: No session | Valid origin | Valid CSRF | Admin required -> Deny (401 Authentication required)', async () => {
      const { app, getAdminMutationCount } = setupTestApp();
      await app.ready();
      const csrf = crypto.randomBytes(32).toString('base64url');

      const res = await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: {
          origin: ALLOWED_ORIGIN,
          'x-csrf-token': csrf,
        },
      });

      expect(res.statusCode).toBe(401);
      expect(res.json().message).toBe('Authentication required');
      expect(getAdminMutationCount()).toBe(0);
      await app.close();
    });

    it('Row 11: Unsupported browser method -> fails closed (405)', async () => {
      const { app } = setupTestApp();
      await app.ready();
      const res = await app.inject({
        method: 'OPTIONS',
        url: '/api/browser/options',
      });
      expect(res.statusCode).toBe(405);
      expect(res.json().error).toBe('Method Not Allowed');
      await app.close();
    });

    it('Row 12: PostgreSQL failure during session validation -> safe 5xx', async () => {
      const brokenSessionService = {
        getCookieName: () => cookieName,
        extractSessionSecretFromCookieHeader: (cookieHeader?: string) =>
          sessionService.extractSessionSecretFromCookieHeader(cookieHeader),
        resolveAndValidateSession: async () => {
          throw new Error('Database connection reset');
        },
        resolveAndValidateSessionWithCsrf: async () => {
          throw new Error('Database connection reset');
        },
      } as unknown as SessionService;

      const app = fastify();
      let handlerCalled = false;
      installAuthorizationBoundary(app, {
        sessionService: brokenSessionService,
        trustedOrigin: ALLOWED_ORIGIN,
      });

      app.get(
        '/api/test-db-failure',
        { config: { authz: { principal: 'browser', minRole: 'member' } } },
        async () => {
          handlerCalled = true;
          return { ok: true };
        },
      );

      app.post(
        '/api/test-db-failure-mutation',
        { config: { authz: { principal: 'browser', minRole: 'member' } } },
        async () => {
          handlerCalled = true;
          return { ok: true };
        },
      );

      await app.ready();
      const secret = crypto.randomBytes(32).toString('base64url');

      // Safe read with DB error -> 503
      const getRes = await app.inject({
        method: 'GET',
        url: '/api/test-db-failure',
        headers: { cookie: makeCookieHeader(secret) },
      });
      expect(getRes.statusCode).toBe(503);
      expect(handlerCalled).toBe(false);

      // Mutation with DB error -> 500
      const postRes = await app.inject({
        method: 'POST',
        url: '/api/test-db-failure-mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookieHeader(secret),
          'x-csrf-token': crypto.randomBytes(32).toString('base64url'),
        },
      });
      expect(postRes.statusCode).toBe(500);
      expect(handlerCalled).toBe(false);

      await app.close();
    });
  });

  describe('Section 16: Mandatory HTTP Security Tests', () => {
    it('Admin can perform allowed admin operation', async () => {
      const { app } = setupTestApp();
      await app.ready();
      const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

      const res = await app.inject({
        method: 'GET',
        url: '/api/audit/logs',
        headers: { cookie: makeCookieHeader(secret) },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json().logs).toEqual(['log1']);
      await app.close();
    });

    it('Member cannot perform admin operation (read or write)', async () => {
      const { app } = setupTestApp();
      await app.ready();
      const { secret, csrfToken } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

      // GET admin read
      const getRes = await app.inject({
        method: 'GET',
        url: '/api/audit/logs',
        headers: { cookie: makeCookieHeader(secret) },
      });
      expect(getRes.statusCode).toBe(403);

      // POST admin write
      const postRes = await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookieHeader(secret),
          'x-csrf-token': csrfToken,
        },
      });
      expect(postRes.statusCode).toBe(403);
      await app.close();
    });

    it('Member can perform allowed read operation', async () => {
      const { app } = setupTestApp();
      await app.ready();
      const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

      const res = await app.inject({
        method: 'GET',
        url: '/api/profile',
        headers: { cookie: makeCookieHeader(secret) },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json().profile).toBe('user_profile');
      await app.close();
    });

    it('Missing cookie rejects browser route with 401', async () => {
      const { app } = setupTestApp();
      await app.ready();

      const res = await app.inject({
        method: 'GET',
        url: '/api/profile',
      });

      expect(res.statusCode).toBe(401);
      expect(res.json().message).toBe('Authentication required');
      await app.close();
    });

    it('Virtual-key bearer cannot authorize browser route (401)', async () => {
      const { app } = setupTestApp();
      await app.ready();

      const res = await app.inject({
        method: 'GET',
        url: '/api/profile',
        headers: {
          authorization: 'Bearer valid_test_virtual_key_secret_token',
        },
      });

      expect(res.statusCode).toBe(401);
      expect(res.json().message).toBe('Authentication required');
      await app.close();
    });

    it('Browser cookie cannot authorize virtual-key route (401)', async () => {
      const { app } = setupTestApp();
      await app.ready();
      const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

      const res = await app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        headers: {
          cookie: makeCookieHeader(secret),
        },
      });

      expect(res.statusCode).toBe(401);
      expect(res.json().message).toBe('Authentication required');
      await app.close();
    });

    it('Mixed bearer and cookie credentials reject on protected routes (401 fail-closed)', async () => {
      const { app } = setupTestApp();
      await app.ready();
      const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

      // On browser route: bearer + cookie
      const browserRes = await app.inject({
        method: 'GET',
        url: '/api/profile',
        headers: {
          cookie: makeCookieHeader(secret),
          authorization: 'Bearer valid_test_virtual_key_secret_token',
        },
      });
      expect(browserRes.statusCode).toBe(401);

      // On virtual-key route: bearer + cookie
      const vkRes = await app.inject({
        method: 'POST',
        url: '/v1/chat/completions',
        headers: {
          cookie: makeCookieHeader(secret),
          authorization: 'Bearer valid_test_virtual_key_secret_token',
        },
      });
      expect(vkRes.statusCode).toBe(401);
      await app.close();
    });

    it('Anonymous requests cannot access protected routes', async () => {
      const { app } = setupTestApp();
      await app.ready();

      const res = await app.inject({
        method: 'GET',
        url: '/api/profile',
      });
      expect(res.statusCode).toBe(401);

      const postRes = await app.inject({
        method: 'POST',
        url: '/api/org/settings',
      });
      expect(postRes.statusCode).toBe(403); // Origin check blocks before session
      await app.close();
    });

    it('Forged user/role/organization headers do not affect authorization', async () => {
      const { app } = setupTestApp();
      await app.ready();
      const { secret } = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

      // Member attempts to forge role=admin and org=orgB via headers
      const res = await app.inject({
        method: 'GET',
        url: '/api/profile',
        headers: {
          cookie: makeCookieHeader(secret),
          'x-role': 'admin',
          'x-user-role': 'admin',
          'x-org-id': ORG_B_ID,
          'x-tenant-id': ORG_B_ID,
        },
      });

      expect(res.statusCode).toBe(200);
      const principal: AuthorizedPrincipal = res.json().principal;
      expect(principal.type).toBe('browser');
      if (principal.type === 'browser') {
        expect(principal.role).toBe('member');
        expect(principal.orgId).toBe(ORG_A_ID);
        expect(principal.userId).toBe(USER_A_MEMBER_ID);
      }
      await app.close();
    });

    it('Duplicate Origin headers fail with 403', async () => {
      const { app, getAdminMutationCount } = setupTestApp();
      await app.ready();
      const { secret, csrfToken } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

      const res = await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: {
          origin: `${ALLOWED_ORIGIN}, ${ALLOWED_ORIGIN}`,
          cookie: makeCookieHeader(secret),
          'x-csrf-token': csrfToken,
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().message).toBe('Invalid or missing Origin');
      expect(getAdminMutationCount()).toBe(0);
      await app.close();
    });

    it('Duplicate CSRF headers fail with 403', async () => {
      const { app, getAdminMutationCount } = setupTestApp();
      await app.ready();
      const { secret, csrfToken } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

      const res = await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookieHeader(secret),
          'x-csrf-token': `${csrfToken}, ${csrfToken}`,
        },
      });

      expect(res.statusCode).toBe(403);
      expect(res.json().message).toBe('Invalid or missing CSRF token');
      expect(getAdminMutationCount()).toBe(0);
      await app.close();
    });

    it('Valid same-origin browser mutation succeeds', async () => {
      const { app, getAdminMutationCount } = setupTestApp();
      await app.ready();
      const { secret, csrfToken } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

      const res = await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookieHeader(secret),
          'x-csrf-token': csrfToken,
        },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json().updated).toBe(true);
      expect(getAdminMutationCount()).toBe(1);
      await app.close();
    });

    it('Protected handler is never invoked after authorization rejection', async () => {
      const { app, getAdminMutationCount } = setupTestApp();
      await app.ready();

      // Rejected on origin
      await app.inject({ method: 'POST', url: '/api/org/settings' });
      // Rejected on unauthenticated
      await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: { origin: ALLOWED_ORIGIN },
      });
      // Rejected on invalid role
      const { secret: memberSecret, csrfToken: memberCsrf } = await sessionService.createSession(
        ORG_A_ID,
        USER_A_MEMBER_ID,
      );
      await app.inject({
        method: 'POST',
        url: '/api/org/settings',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookieHeader(memberSecret),
          'x-csrf-token': memberCsrf,
        },
      });

      expect(getAdminMutationCount()).toBe(0);
      await app.close();
    });

    it('Request principals do not leak between concurrent requests', async () => {
      const { app } = setupTestApp();
      await app.ready();

      const { secret: adminSecret } = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);
      const { secret: memberSecret } = await sessionService.createSession(
        ORG_B_ID,
        USER_B_MEMBER_ID,
      );

      const [resAdmin, resMember, resAnon] = await Promise.all([
        app.inject({
          method: 'GET',
          url: '/api/profile',
          headers: { cookie: makeCookieHeader(adminSecret) },
        }),
        app.inject({
          method: 'GET',
          url: '/api/profile',
          headers: { cookie: makeCookieHeader(memberSecret) },
        }),
        app.inject({
          method: 'GET',
          url: '/health/live',
        }),
      ]);

      expect(resAdmin.statusCode).toBe(200);
      expect(resAdmin.json().principal).toEqual({
        type: 'browser',
        userId: USER_A_ADMIN_ID,
        orgId: ORG_A_ID,
        role: 'admin',
      });

      expect(resMember.statusCode).toBe(200);
      expect(resMember.json().principal).toEqual({
        type: 'browser',
        userId: USER_B_MEMBER_ID,
        orgId: ORG_B_ID,
        role: 'member',
      });

      expect(resAnon.statusCode).toBe(200);
      await app.close();
    });

    it('The actual production buildApp() exposes NO test-only business endpoints (Section 18)', async () => {
      const nullLogger = pino({ enabled: false });
      const mockLifecycle = {
        getState: () => 'READY',
        isReady: () => true,
        isShuttingDown: () => false,
        assertHealthy: () => {},
      } as unknown as Parameters<typeof buildApp>[0]['lifecycle'];

      const mockRedis = {
        checkReadiness: async () => ({ ok: true, policy: 'noeviction' }),
        close: async () => {},
      } as unknown as Parameters<typeof buildApp>[0]['redis'];

      const prodApp = await buildApp({
        postgres: {
          pool: appPool,
          checkReadiness: async () => ({ ok: true }),
          close: async () => {},
        },
        redis: mockRedis,
        lifecycle: mockLifecycle,
        logger: nullLogger,
        config: loadConfig({
          NODE_ENV: 'test',
          BROWSER_ORIGIN: ALLOWED_ORIGIN,
        }),
      });

      try {
        // Only health endpoints exist
        const liveRes = await prodApp.inject({ method: 'GET', url: '/health/live' });
        expect(liveRes.statusCode).toBe(200);

        const readyRes = await prodApp.inject({ method: 'GET', url: '/health/ready' });
        expect(readyRes.statusCode).toBe(200);

        // All test routes are strictly 404
        const profileRes = await prodApp.inject({ method: 'GET', url: '/api/profile' });
        expect(profileRes.statusCode).toBe(404);

        const orgRes = await prodApp.inject({ method: 'POST', url: '/api/org/settings' });
        expect(orgRes.statusCode).toBe(404);

        const chatRes = await prodApp.inject({ method: 'POST', url: '/v1/chat/completions' });
        expect(chatRes.statusCode).toBe(404);
      } finally {
        await prodApp.close();
      }
    });
  });

  describe('Section 17: Secret Privacy and Logging Tests', () => {
    it('proves canary credentials never leak into Pino logs or HTTP responses', async () => {
      const logRecords: string[] = [];
      const testLogger = pino(
        { level: 'trace' },
        {
          write: (chunk: string) => {
            logRecords.push(chunk);
          },
        },
      );

      const CANARY_SESSION_SECRET = 'canary_session_secret_999999999999999999999';
      const CANARY_CSRF_TOKEN = 'canary_csrf_token_8888888888888888888888888';
      const CANARY_VIRTUAL_KEY = 'canary_virtual_key_777777777777777777777777';

      const app = fastify({ loggerInstance: testLogger });
      const mockVkAuthenticator: VirtualKeyAuthenticator = {
        authenticateKey: async () => ({ valid: false, reason: 'INVALID_CANARY_KEY' }),
      };

      installAuthorizationBoundary(app, {
        sessionService,
        trustedOrigin: ALLOWED_ORIGIN,
        virtualKeyAuthenticator: mockVkAuthenticator,
      });

      app.post(
        '/canary/mutation',
        { config: { authz: { principal: 'browser', minRole: 'admin' } } },
        async () => ({ ok: true }),
      );

      app.post(
        '/canary/inference',
        { config: { authz: { principal: 'virtual_key' } } },
        async () => ({ ok: true }),
      );

      await app.ready();

      // 1. Submit failed browser mutation carrying canary credentials
      const res1 = await app.inject({
        method: 'POST',
        url: '/canary/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: `${cookieName}=${CANARY_SESSION_SECRET}`,
          'x-csrf-token': CANARY_CSRF_TOKEN,
        },
      });

      expect(res1.statusCode).toBe(401);
      expect(res1.body).not.toContain(CANARY_SESSION_SECRET);
      expect(res1.body).not.toContain(CANARY_CSRF_TOKEN);

      // 2. Submit failed virtual key inference carrying canary virtual key
      const res2 = await app.inject({
        method: 'POST',
        url: '/canary/inference',
        headers: {
          authorization: `Bearer ${CANARY_VIRTUAL_KEY}`,
        },
      });

      expect(res2.statusCode).toBe(401);
      expect(res2.body).not.toContain(CANARY_VIRTUAL_KEY);

      // 3. Inspect all logged output from Pino
      const combinedLogs = logRecords.join('\n');
      expect(combinedLogs).not.toContain(CANARY_SESSION_SECRET);
      expect(combinedLogs).not.toContain(CANARY_CSRF_TOKEN);
      expect(combinedLogs).not.toContain(CANARY_VIRTUAL_KEY);

      await app.close();
    });
  });

  describe('Section 18: AUTHZ-05 Pre-Tenant Session Lookup Error Classification & Propagation', () => {
    // Test A — Unknown session
    it('Test A — Unknown session: zero matching rows returns null, SESSION_NOT_FOUND, and 401', async () => {
      const unknownSecret = crypto.randomBytes(32).toString('base64url');
      const unknownSecretBytes = Buffer.from(unknownSecret, 'base64url');

      // 1. Pre-tenant lookup returns null
      const orgId = await sessionService.lookupSessionOrgId(unknownSecretBytes);
      expect(orgId).toBeNull();

      // 2. Session validation returns SESSION_NOT_FOUND
      const validation = await sessionService.resolveAndValidateSession(unknownSecret);
      expect(validation.valid).toBe(false);
      expect(validation.reason).toBe('SESSION_NOT_FOUND');

      const csrfValidation = await sessionService.resolveAndValidateSessionWithCsrf(
        unknownSecret,
        crypto.randomBytes(32).toString('base64url'),
      );
      expect(csrfValidation.valid).toBe(false);
      expect(csrfValidation.reason).toBe('SESSION_NOT_FOUND');

      // 3. Browser route responds 401
      const { app } = setupTestApp();
      await app.ready();
      try {
        const getRes = await app.inject({
          method: 'GET',
          url: '/api/profile',
          headers: { cookie: makeCookieHeader(unknownSecret) },
        });
        expect(getRes.statusCode).toBe(401);
        expect(getRes.json().message).toBe('Authentication required');
      } finally {
        await app.close();
      }
    });

    // Test B — Database lookup error
    it('Test B — Database lookup error: pool.query rejection raises SessionError DATABASE_ERROR without leaking SQL', async () => {
      const failingPool = {
        query: async (queryText: unknown) => {
          if (typeof queryText === 'string' && queryText.includes('lookup_session_org_by_hash')) {
            throw new Error('connection closed by foreign host');
          }
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          return appPool.query(queryText as any);
        },
      } as unknown as pg.Pool;

      const failingService = new SessionService({
        pool: failingPool,
        cookieOptions: { isProduction: true },
      });

      const secretBytes = crypto.randomBytes(32);
      try {
        await failingService.lookupSessionOrgId(secretBytes);
        expect.fail('Expected lookupSessionOrgId to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(SessionError);
        const sessionErr = err as SessionError;
        expect(sessionErr.reason).toBe('DATABASE_ERROR');
        expect(sessionErr.message).toBe('Database error during session lookup');
        expect(sessionErr.message).not.toContain('SELECT');
        expect(sessionErr.message).not.toContain('lookup_session_org_by_hash');
        expect(sessionErr.message).not.toContain('postgres');
      }
    });

    // Test C — Browser read request
    it('Test C — Browser read request: PostgreSQL lookup failure produces HTTP 503 and zero handler executions', async () => {
      let readHandlerCalled = false;
      const failingPool = {
        query: async () => {
          throw new Error('connection timeout during pre-tenant lookup');
        },
      } as unknown as pg.Pool;

      const failingService = new SessionService({
        pool: failingPool,
        cookieOptions: { isProduction: true },
      });

      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: failingService,
        trustedOrigin: ALLOWED_ORIGIN,
      });

      app.get(
        '/api/profile/failing-read',
        { config: { authz: { principal: 'browser', minRole: 'member' } } },
        async () => {
          readHandlerCalled = true;
          return { secret: 'leak' };
        },
      );

      await app.ready();
      try {
        const secret = crypto.randomBytes(32).toString('base64url');
        const res = await app.inject({
          method: 'GET',
          url: '/api/profile/failing-read',
          headers: { cookie: makeCookieHeader(secret) },
        });

        expect(res.statusCode).toBe(503);
        expect(res.json()).toEqual({
          statusCode: 503,
          error: 'Service Unavailable',
          message: 'Authentication service unavailable',
        });
        expect(readHandlerCalled).toBe(false);
      } finally {
        await app.close();
      }
    });

    // Test D — Browser mutation request
    it('Test D — Browser mutation request: PostgreSQL lookup failure produces controlled 500 and zero handler executions', async () => {
      let mutationHandlerCalled = false;
      const failingPool = {
        query: async () => {
          throw new Error('database connection reset by peer');
        },
      } as unknown as pg.Pool;

      const failingService = new SessionService({
        pool: failingPool,
        cookieOptions: { isProduction: true },
      });

      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: failingService,
        trustedOrigin: ALLOWED_ORIGIN,
      });

      app.post(
        '/api/profile/failing-mutation',
        { config: { authz: { principal: 'browser', minRole: 'member' } } },
        async () => {
          mutationHandlerCalled = true;
          return { modified: true };
        },
      );

      await app.ready();
      try {
        const secret = crypto.randomBytes(32).toString('base64url');
        const csrfToken = crypto.randomBytes(32).toString('base64url');
        const res = await app.inject({
          method: 'POST',
          url: '/api/profile/failing-mutation',
          headers: {
            origin: ALLOWED_ORIGIN,
            cookie: makeCookieHeader(secret),
            'x-csrf-token': csrfToken,
          },
        });

        expect(res.statusCode).toBe(500);
        expect(res.json()).toEqual({
          statusCode: 500,
          error: 'Internal Server Error',
          message: 'Internal server error',
        });
        expect(mutationHandlerCalled).toBe(false);
      } finally {
        await app.close();
      }
    });

    // Test E — Recovery
    it('Test E — Recovery: after restoring normal query behavior, active sessions and mutations succeed while invalid sessions remain rejected', async () => {
      let failQueries = true;
      const recoverablePool = Object.create(appPool) as pg.Pool;
      recoverablePool.query = (async (queryText: unknown, values: unknown) => {
        if (
          failQueries &&
          typeof queryText === 'string' &&
          queryText.includes('lookup_session_org_by_hash')
        ) {
          throw new Error('transient database outage');
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return appPool.query(queryText as any, values as any);
      }) as unknown as pg.Pool['query'];

      const recoverableService = new SessionService({
        pool: recoverablePool,
        cookieOptions: { isProduction: true },
      });

      const app = fastify();
      let mutationCount = 0;
      installAuthorizationBoundary(app, {
        sessionService: recoverableService,
        trustedOrigin: ALLOWED_ORIGIN,
      });

      app.get(
        '/api/recoverable/read',
        { config: { authz: { principal: 'browser', minRole: 'member' } } },
        async () => ({ ok: true }),
      );

      app.post(
        '/api/recoverable/mutate',
        { config: { authz: { principal: 'browser', minRole: 'member' } } },
        async () => {
          mutationCount++;
          return { mutated: true };
        },
      );

      await app.ready();
      try {
        const { secret, csrfToken, session } = await sessionService.createSession(
          ORG_A_ID,
          USER_A_MEMBER_ID,
        );

        // 1. Under failure -> 503 on read, 500 on mutation
        const failRead = await app.inject({
          method: 'GET',
          url: '/api/recoverable/read',
          headers: { cookie: makeCookieHeader(secret) },
        });
        expect(failRead.statusCode).toBe(503);

        const failMutate = await app.inject({
          method: 'POST',
          url: '/api/recoverable/mutate',
          headers: {
            origin: ALLOWED_ORIGIN,
            cookie: makeCookieHeader(secret),
            'x-csrf-token': csrfToken,
          },
        });
        expect(failMutate.statusCode).toBe(500);
        expect(mutationCount).toBe(0);

        // 2. Restore normal query behavior
        failQueries = false;

        // 3. Valid active session authenticates (200)
        const okRead = await app.inject({
          method: 'GET',
          url: '/api/recoverable/read',
          headers: { cookie: makeCookieHeader(secret) },
        });
        expect(okRead.statusCode).toBe(200);

        // 4. Valid CSRF-protected mutation succeeds (200)
        const okMutate = await app.inject({
          method: 'POST',
          url: '/api/recoverable/mutate',
          headers: {
            origin: ALLOWED_ORIGIN,
            cookie: makeCookieHeader(secret),
            'x-csrf-token': csrfToken,
          },
        });
        expect(okMutate.statusCode).toBe(200);
        expect(mutationCount).toBe(1);

        // 5. Unknown session remains rejected with 401
        const unknownSecret = crypto.randomBytes(32).toString('base64url');
        const unknownRead = await app.inject({
          method: 'GET',
          url: '/api/recoverable/read',
          headers: { cookie: makeCookieHeader(unknownSecret) },
        });
        expect(unknownRead.statusCode).toBe(401);

        // 6. Revoked session remains rejected with 401
        await adminClient.query(
          'UPDATE public.web_sessions SET revoked_at = clock_timestamp() WHERE session_id_hash = $1',
          [session.sessionIdHash],
        );
        const revokedRead = await app.inject({
          method: 'GET',
          url: '/api/recoverable/read',
          headers: { cookie: makeCookieHeader(secret) },
        });
        expect(revokedRead.statusCode).toBe(401);
      } finally {
        await app.close();
      }
    });

    // Test F — No information leakage
    it('Test F — No information leakage: injected connection-string/SQL canary does not leak in responses, logs, or public errors', async () => {
      const CANARY_CONNECTION_STRING =
        'postgresql://gateway_app:super_secret_password_canary@db.switchyard.internal:5432/switchyard_prod?sslmode=require';
      const CANARY_SQL_FRAGMENT = 'SELECT * FROM secret_financial_keys WHERE canary = TRUE';

      const logRecords: string[] = [];
      const testLogger = pino(
        { level: 'trace' },
        {
          write: (chunk: string) => {
            logRecords.push(chunk);
          },
        },
      );

      const leakingPool = {
        query: async () => {
          throw new Error(
            `Connection error to ${CANARY_CONNECTION_STRING}: query failed on ${CANARY_SQL_FRAGMENT}`,
          );
        },
      } as unknown as pg.Pool;

      const leakingService = new SessionService({
        pool: leakingPool,
        cookieOptions: { isProduction: true },
      });

      const app = fastify({ loggerInstance: testLogger });
      installAuthorizationBoundary(app, {
        sessionService: leakingService,
        trustedOrigin: ALLOWED_ORIGIN,
      });

      app.get(
        '/api/canary/read',
        { config: { authz: { principal: 'browser', minRole: 'member' } } },
        async () => ({ ok: true }),
      );

      app.post(
        '/api/canary/mutate',
        { config: { authz: { principal: 'browser', minRole: 'member' } } },
        async () => ({ ok: true }),
      );

      await app.ready();
      try {
        const secret = crypto.randomBytes(32).toString('base64url');
        const csrfToken = crypto.randomBytes(32).toString('base64url');

        // 1. Browser read request
        const resRead = await app.inject({
          method: 'GET',
          url: '/api/canary/read',
          headers: { cookie: makeCookieHeader(secret) },
        });
        expect(resRead.statusCode).toBe(503);
        expect(resRead.body).not.toContain(CANARY_CONNECTION_STRING);
        expect(resRead.body).not.toContain(CANARY_SQL_FRAGMENT);
        expect(resRead.body).not.toContain('super_secret_password_canary');

        // 2. Browser mutation request
        const resMutate = await app.inject({
          method: 'POST',
          url: '/api/canary/mutate',
          headers: {
            origin: ALLOWED_ORIGIN,
            cookie: makeCookieHeader(secret),
            'x-csrf-token': csrfToken,
          },
        });
        expect(resMutate.statusCode).toBe(500);
        expect(resMutate.body).not.toContain(CANARY_CONNECTION_STRING);
        expect(resMutate.body).not.toContain(CANARY_SQL_FRAGMENT);
        expect(resMutate.body).not.toContain('super_secret_password_canary');

        // 3. Serialized public error assertions
        try {
          await leakingService.lookupSessionOrgId(Buffer.from(secret, 'base64url'));
          expect.fail('Expected lookupSessionOrgId to throw');
        } catch (err) {
          const sessionErr = err as SessionError;
          expect(sessionErr.message).not.toContain(CANARY_CONNECTION_STRING);
          expect(sessionErr.message).not.toContain(CANARY_SQL_FRAGMENT);
          expect(sessionErr.message).not.toContain('super_secret_password_canary');
        }

        // 4. Pino log inspection
        const combinedLogs = logRecords.join('\n');
        expect(combinedLogs).not.toContain(CANARY_CONNECTION_STRING);
        expect(combinedLogs).not.toContain(CANARY_SQL_FRAGMENT);
        expect(combinedLogs).not.toContain('super_secret_password_canary');
      } finally {
        await app.close();
      }
    });
  });
});
