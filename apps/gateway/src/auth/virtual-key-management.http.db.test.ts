import fastify from 'fastify';
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
import { installAuthorizationBoundary } from './authorization.js';
import { registerVirtualKeyRoutes } from '../routes/virtual-keys.js';

describe('SW-1.6.3: HTTP Authorization, CSRF, RBAC & Secret Canary Suite', () => {
  let cluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();
  let adminClient: pg.Client;
  let appPool: pg.Pool;
  let sessionService: SessionService;
  let cookieName: string;
  let app: ReturnType<typeof fastify>;
  let logOutput: string[] = [];

  const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
  const ORG_B_ID = '22222222-2222-4222-8222-222222222222';
  const USER_A_ADMIN_ID = 'aaaaaaaa-1111-4aaa-8aaa-aaaaaaaaaaaa';
  const USER_A_MEMBER_ID = 'aaaaaaaa-2222-4aaa-8aaa-aaaaaaaaaaaa';
  const USER_B_ADMIN_ID = 'bbbbbbbb-1111-4bbb-8bbb-bbbbbbbbbbbb';

  const ALLOWED_ORIGIN = 'https://app.switchyard.internal';
  const DISALLOWED_ORIGIN = 'https://evil.attacker.com';

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    db = await createDisposableDatabase(cluster, 'vk_mgmt_http_test');
    await bootstrapDatabase(db, passwords);

    // Run migrations 0001 through 0011
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

    // Connect admin client for fixture setup
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
        ('${USER_A_ADMIN_ID}', '${ORG_A_ID}', 'admin@alpha.com', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$dGVzdA', 'admin'),
        ('${USER_A_MEMBER_ID}', '${ORG_A_ID}', 'member@alpha.com', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$dGVzdA', 'member'),
        ('${USER_B_ADMIN_ID}', '${ORG_B_ID}', 'admin@beta.com', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$dGVzdA', 'admin');
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

    // Logger stream capture for security canary test
    const customStream = {
      write: (msg: string) => {
        logOutput.push(msg);
      },
    };
    const testLogger = pino({ level: 'info' }, customStream);

    app = fastify({ loggerInstance: testLogger });

    installAuthorizationBoundary(app, {
      sessionService,
      trustedOrigin: ALLOWED_ORIGIN,
    });

    await registerVirtualKeyRoutes(app, { pool: appPool });
    await app.ready();
  }, 60000);

  afterAll(async () => {
    await app?.close();
    await appPool?.end();
    await adminClient?.end();
    await db?.drop();
  });

  function makeCookie(secret: string): string {
    return `${cookieName}=${secret}`;
  }

  describe('Section 12.1: Full Authorization Matrix (Admin, Member, Anonymous, Virtual-Key)', () => {
    let tenantAAdminSession: { secret: string; csrfToken: string };
    let tenantAMemberSession: { secret: string; csrfToken: string };
    let tenantBAdminSession: { secret: string; csrfToken: string };
    let activeKeyAId: string;
    let activeKeyARaw: string;

    beforeAll(async () => {
      tenantAAdminSession = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);
      tenantAMemberSession = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);
      tenantBAdminSession = await sessionService.createSession(ORG_B_ID, USER_B_ADMIN_ID);

      // Create an active key in Tenant A for test fixtures
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(tenantAAdminSession.secret),
          'x-csrf-token': tenantAAdminSession.csrfToken,
        },
        payload: { name: 'Alpha Fixture Key' },
      });
      expect(createRes.statusCode).toBe(201);
      const json = createRes.json();
      activeKeyAId = json.id;
      activeKeyARaw = json.rawKey;
    });

    it('Valid Tenant A admin: Allow on all 4 endpoints (201, 200, 200, 204)', async () => {
      // 1. Create
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(tenantAAdminSession.secret),
          'x-csrf-token': tenantAAdminSession.csrfToken,
        },
        payload: { name: 'Alpha Matrix Key' },
      });
      expect(createRes.statusCode).toBe(201);
      expect(createRes.headers['cache-control']).toBe('no-store');
      expect(createRes.headers['pragma']).toBe('no-cache');
      const keyId = createRes.json().id;

      // 2. List
      const listRes = await app.inject({
        method: 'GET',
        url: '/api/keys',
        headers: {
          cookie: makeCookie(tenantAAdminSession.secret),
        },
      });
      expect(listRes.statusCode).toBe(200);
      expect(listRes.headers['cache-control']).toBe('no-store');
      expect(listRes.json().items.some((k: { id: string }) => k.id === keyId)).toBe(true);

      // 3. Update Policy
      const updateRes = await app.inject({
        method: 'PUT',
        url: `/api/keys/${keyId}/policy`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(tenantAAdminSession.secret),
          'x-csrf-token': tenantAAdminSession.csrfToken,
        },
        payload: {
          allowedModels: ['gpt-4o'],
          rpmLimit: 120,
          tpmLimit: 12000,
          concurrentStreamLimit: 5,
          exactCacheEnabled: false,
          semanticCacheEnabled: false,
          piiRedactionEnabled: true,
          storePayloads: false,
        },
      });
      expect(updateRes.statusCode).toBe(200);
      expect(updateRes.headers['cache-control']).toBe('no-store');
      expect(updateRes.json().rpmLimit).toBe(120);

      // 4. Revoke
      const revokeRes = await app.inject({
        method: 'DELETE',
        url: `/api/keys/${keyId}`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(tenantAAdminSession.secret),
          'x-csrf-token': tenantAAdminSession.csrfToken,
        },
      });
      expect(revokeRes.statusCode).toBe(204);
      expect(revokeRes.headers['cache-control']).toBe('no-store');
    });

    it('Tenant B admin on Tenant A key: 404 on policy update, 404 on revoke, own-tenant only on list', async () => {
      // Attempt policy update on Tenant A's key
      const updateRes = await app.inject({
        method: 'PUT',
        url: `/api/keys/${activeKeyAId}/policy`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(tenantBAdminSession.secret),
          'x-csrf-token': tenantBAdminSession.csrfToken,
        },
        payload: {
          allowedModels: ['gpt-4o'],
          rpmLimit: 999,
          tpmLimit: 9999,
          concurrentStreamLimit: 9,
          exactCacheEnabled: false,
          semanticCacheEnabled: false,
          piiRedactionEnabled: true,
          storePayloads: false,
        },
      });
      expect(updateRes.statusCode).toBe(404);
      expect(updateRes.json().message).toBe('Virtual key not found');

      // Attempt revoke on Tenant A's key
      const revokeRes = await app.inject({
        method: 'DELETE',
        url: `/api/keys/${activeKeyAId}`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(tenantBAdminSession.secret),
          'x-csrf-token': tenantBAdminSession.csrfToken,
        },
      });
      expect(revokeRes.statusCode).toBe(404);
      expect(revokeRes.json().message).toBe('Virtual key not found');

      // List returns only Tenant B's keys
      const listRes = await app.inject({
        method: 'GET',
        url: '/api/keys',
        headers: {
          cookie: makeCookie(tenantBAdminSession.secret),
        },
      });
      expect(listRes.statusCode).toBe(200);
      expect(listRes.json().items.some((k: { id: string }) => k.id === activeKeyAId)).toBe(false);
    });

    it('Valid Member: 403 Forbidden across all 4 endpoints', async () => {
      // 1. Create -> 403
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(tenantAMemberSession.secret),
          'x-csrf-token': tenantAMemberSession.csrfToken,
        },
        payload: { name: 'Member Key Attempt' },
      });
      expect(createRes.statusCode).toBe(403);

      // 2. List -> 403
      const listRes = await app.inject({
        method: 'GET',
        url: '/api/keys',
        headers: {
          cookie: makeCookie(tenantAMemberSession.secret),
        },
      });
      expect(listRes.statusCode).toBe(403);

      // 3. Update Policy -> 403
      const updateRes = await app.inject({
        method: 'PUT',
        url: `/api/keys/${activeKeyAId}/policy`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(tenantAMemberSession.secret),
          'x-csrf-token': tenantAMemberSession.csrfToken,
        },
        payload: {
          allowedModels: ['gpt-4o'],
          rpmLimit: 120,
          tpmLimit: 12000,
          concurrentStreamLimit: 5,
          exactCacheEnabled: false,
          semanticCacheEnabled: false,
          piiRedactionEnabled: true,
          storePayloads: false,
        },
      });
      expect(updateRes.statusCode).toBe(403);

      // 4. Revoke -> 403
      const revokeRes = await app.inject({
        method: 'DELETE',
        url: `/api/keys/${activeKeyAId}`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(tenantAMemberSession.secret),
          'x-csrf-token': tenantAMemberSession.csrfToken,
        },
      });
      expect(revokeRes.statusCode).toBe(403);
    });

    it('Anonymous (no session): 401 Unauthorized across all 4 endpoints', async () => {
      expect(
        (
          await app.inject({
            method: 'POST',
            url: '/api/keys',
            headers: { origin: ALLOWED_ORIGIN },
            payload: { name: 'Anon Key' },
          })
        ).statusCode,
      ).toBe(401);

      expect((await app.inject({ method: 'GET', url: '/api/keys' })).statusCode).toBe(401);

      expect(
        (
          await app.inject({
            method: 'PUT',
            url: `/api/keys/${activeKeyAId}/policy`,
            headers: { origin: ALLOWED_ORIGIN },
            payload: {},
          })
        ).statusCode,
      ).toBe(401);

      expect(
        (
          await app.inject({
            method: 'DELETE',
            url: `/api/keys/${activeKeyAId}`,
            headers: { origin: ALLOWED_ORIGIN },
          })
        ).statusCode,
      ).toBe(401);
    });

    it('Expired session: 401 Unauthorized across all 4 endpoints', async () => {
      const expiredSession = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);
      // Force session absolute expiration in DB
      await adminClient.query(
        "UPDATE public.web_sessions SET absolute_expires_at = clock_timestamp() - interval '1 hour'",
      );

      expect(
        (
          await app.inject({
            method: 'POST',
            url: '/api/keys',
            headers: {
              origin: ALLOWED_ORIGIN,
              cookie: makeCookie(expiredSession.secret),
              'x-csrf-token': expiredSession.csrfToken,
            },
            payload: { name: 'Expired Test' },
          })
        ).statusCode,
      ).toBe(401);

      expect(
        (
          await app.inject({
            method: 'GET',
            url: '/api/keys',
            headers: { cookie: makeCookie(expiredSession.secret) },
          })
        ).statusCode,
      ).toBe(401);
    });

    it('Revoked session: 401 Unauthorized across all 4 endpoints', async () => {
      const freshSession = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);
      await sessionService.revokeSession(freshSession.secret);

      expect(
        (
          await app.inject({
            method: 'POST',
            url: '/api/keys',
            headers: {
              origin: ALLOWED_ORIGIN,
              cookie: makeCookie(freshSession.secret),
              'x-csrf-token': freshSession.csrfToken,
            },
            payload: { name: 'Revoked Session Test' },
          })
        ).statusCode,
      ).toBe(401);

      expect(
        (
          await app.inject({
            method: 'GET',
            url: '/api/keys',
            headers: { cookie: makeCookie(freshSession.secret) },
          })
        ).statusCode,
      ).toBe(401);
    });

    it('Virtual API key bearer used on browser route: 401 Unauthorized', async () => {
      // Principal separation: Authorization header on browser route fails closed with 401
      const res = await app.inject({
        method: 'GET',
        url: '/api/keys',
        headers: {
          authorization: `Bearer ${activeKeyARaw}`,
        },
      });
      expect(res.statusCode).toBe(401);
    });

    it('Conflicting credentials (cookie + Authorization bearer): 401 Unauthorized', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/keys',
        headers: {
          cookie: makeCookie(tenantAAdminSession.secret),
          authorization: `Bearer ${activeKeyARaw}`,
        },
      });
      expect(res.statusCode).toBe(401);
    });

    it('rejects unsupported query parameters across all 4 endpoints (400 Bad Request)', async () => {
      const queryTestAdminSession = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

      // 1. POST /api/keys?orgId=... -> 400
      const postRes = await app.inject({
        method: 'POST',
        url: '/api/keys?orgId=' + ORG_B_ID,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(queryTestAdminSession.secret),
          'x-csrf-token': queryTestAdminSession.csrfToken,
        },
        payload: { name: 'Query Param Attempt' },
      });
      expect(postRes.statusCode).toBe(400);
      expect(postRes.json().message).toContain('Query parameters are not permitted');

      // 2. GET /api/keys?orgId=... -> 400
      const getOrgIdRes = await app.inject({
        method: 'GET',
        url: '/api/keys?orgId=' + ORG_B_ID,
        headers: {
          cookie: makeCookie(queryTestAdminSession.secret),
        },
      });
      expect(getOrgIdRes.statusCode).toBe(400);
      expect(getOrgIdRes.json().message).toContain('Unexpected query parameter "orgId"');

      // GET /api/keys?tenantId=... -> 400
      const getTenantIdRes = await app.inject({
        method: 'GET',
        url: '/api/keys?tenantId=' + ORG_B_ID,
        headers: {
          cookie: makeCookie(queryTestAdminSession.secret),
        },
      });
      expect(getTenantIdRes.statusCode).toBe(400);
      expect(getTenantIdRes.json().message).toContain('Unexpected query parameter "tenantId"');

      // GET /api/keys?role=admin -> 400
      const getRoleRes = await app.inject({
        method: 'GET',
        url: '/api/keys?role=admin',
        headers: {
          cookie: makeCookie(queryTestAdminSession.secret),
        },
      });
      expect(getRoleRes.statusCode).toBe(400);
      expect(getRoleRes.json().message).toContain('Unexpected query parameter "role"');

      // 3. PUT /api/keys/:id/policy?orgId=... -> 400
      const putRes = await app.inject({
        method: 'PUT',
        url: `/api/keys/${activeKeyAId}/policy?orgId=${ORG_B_ID}`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(queryTestAdminSession.secret),
          'x-csrf-token': queryTestAdminSession.csrfToken,
        },
        payload: {
          allowedModels: ['gpt-4o'],
          rpmLimit: 120,
          tpmLimit: 12000,
          concurrentStreamLimit: 5,
          exactCacheEnabled: false,
          semanticCacheEnabled: false,
          piiRedactionEnabled: true,
          storePayloads: false,
        },
      });
      expect(putRes.statusCode).toBe(400);
      expect(putRes.json().message).toContain('Query parameters are not permitted');

      // 4. DELETE /api/keys/:id?foo=bar -> 400
      const deleteRes = await app.inject({
        method: 'DELETE',
        url: `/api/keys/${activeKeyAId}?foo=bar`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(queryTestAdminSession.secret),
          'x-csrf-token': queryTestAdminSession.csrfToken,
        },
      });
      expect(deleteRes.statusCode).toBe(400);
      expect(deleteRes.json().message).toContain('Query parameters are not permitted');
    });
  });

  describe('Section 12.2: CSRF & Origin Enforcement on Mutations', () => {
    let adminSession: { secret: string; csrfToken: string };

    beforeAll(async () => {
      adminSession = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);
    });

    it('rejects mutation with missing CSRF token', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
        },
        payload: { name: 'CSRF Missing' },
      });
      expect(res.statusCode).toBe(403);
    });

    it('rejects mutation with invalid CSRF token', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': 'invalid_csrf_token_material',
        },
        payload: { name: 'CSRF Invalid' },
      });
      expect(res.statusCode).toBe(403);
    });

    it('rejects mutation with CSRF token from another session', async () => {
      const otherSession = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);
      const res = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': otherSession.csrfToken,
        },
        payload: { name: 'CSRF Other Session' },
      });
      expect(res.statusCode).toBe(403);
    });

    it('rejects mutation with missing Origin', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': adminSession.csrfToken,
        },
        payload: { name: 'Origin Missing' },
      });
      expect(res.statusCode).toBe(403);
    });

    it('rejects mutation with wrong / disallowed Origin', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: DISALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': adminSession.csrfToken,
        },
        payload: { name: 'Origin Evil' },
      });
      expect(res.statusCode).toBe(403);
    });

    it('rejects mutation with spoofed Origin prefix/suffix', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: `${ALLOWED_ORIGIN}.attacker.com`,
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': adminSession.csrfToken,
        },
        payload: { name: 'Origin Spoof' },
      });
      expect(res.statusCode).toBe(403);
    });
  });

  describe('Section 13: Secret Containment & Logging Canary', () => {
    it('discloses rawKey once on create, excludes from list/update/revoke, and verifies no secret leakage in logs', async () => {
      logOutput = []; // Reset log capture
      const adminSession = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);

      // 1. Create key
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': adminSession.csrfToken,
        },
        payload: { name: 'Canary Test Key' },
      });
      expect(createRes.statusCode).toBe(201);
      expect(createRes.headers['cache-control']).toBe('no-store');
      expect(createRes.headers['pragma']).toBe('no-cache');

      const createJson = createRes.json();
      const rawKey: string = createJson.rawKey;
      expect(rawKey).toMatch(/^gw_live_[A-Za-z0-9_-]{11}_[A-Za-z0-9_-]{43}$/);
      const secret = rawKey.slice(20);
      expect(secret.length).toBe(43);
      expect(createJson.keyHash).toBeUndefined();
      expect(createJson.key_hash).toBeUndefined();

      const keyId = createJson.id;

      // 2. List keys
      const listRes = await app.inject({
        method: 'GET',
        url: '/api/keys',
        headers: {
          cookie: makeCookie(adminSession.secret),
        },
      });
      expect(listRes.statusCode).toBe(200);
      const listJson = listRes.json();
      const listStr = JSON.stringify(listJson);
      expect(listStr).not.toContain(rawKey);
      expect(listStr).not.toContain(secret);
      expect(listStr).not.toContain('keyHash');
      expect(listStr).not.toContain('key_hash');

      // 3. Update Policy
      const updateRes = await app.inject({
        method: 'PUT',
        url: `/api/keys/${keyId}/policy`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': adminSession.csrfToken,
        },
        payload: {
          allowedModels: ['gpt-4o'],
          rpmLimit: 60,
          tpmLimit: 6000,
          concurrentStreamLimit: 2,
          exactCacheEnabled: false,
          semanticCacheEnabled: false,
          piiRedactionEnabled: true,
          storePayloads: false,
        },
      });
      expect(updateRes.statusCode).toBe(200);
      const updateJson = updateRes.json();
      const updateStr = JSON.stringify(updateJson);
      expect(updateStr).not.toContain(rawKey);
      expect(updateStr).not.toContain(secret);
      expect(updateStr).not.toContain('keyHash');
      expect(updateStr).not.toContain('key_hash');

      // 4. Revoke
      const revokeRes = await app.inject({
        method: 'DELETE',
        url: `/api/keys/${keyId}`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': adminSession.csrfToken,
        },
      });
      expect(revokeRes.statusCode).toBe(204);

      // 5. Assert structured logs: NO log contains rawKey, secret, session secret, or DB credentials
      const combinedLogs = logOutput.join('\n');
      expect(combinedLogs).not.toContain(rawKey);
      expect(combinedLogs).not.toContain(secret);
      expect(combinedLogs).not.toContain(adminSession.secret);
      expect(combinedLogs).not.toContain(passwords.gateway_app);
      expect(combinedLogs).not.toContain('postgres://');
    });
  });
});
