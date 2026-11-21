import crypto from 'node:crypto';
import fastify, { type FastifyRequest } from 'fastify';
import { Redis } from 'ioredis';
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
import { registerVirtualKeyRoutes } from '../routes/virtual-keys.js';
import { installAuthorizationBoundary, type VirtualKeyAuthenticator } from './authorization.js';
import { SessionService } from './session.js';
import { startDisposableRedis, type DisposableRedisCluster } from './test/disposable-redis.js';
import { VirtualKeyService } from './virtual-key.js';
import { VirtualKeyAuthenticatorService } from './virtual-key-authenticator.js';
import { VirtualKeyManagementService } from './virtual-key-management.js';
import { VirtualKeyRateLimiter } from './virtual-key-rate-limiter.js';

describe('SW-1.6.4: Real HTTP Virtual Key Security, Error Equivalence & Secret Secrecy Suite', () => {
  let pgCluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();
  let adminClient: pg.Client;
  let appPool: pg.Pool;

  let redisCluster: DisposableRedisCluster;
  let appRedis: Redis;
  let adminRedis: Redis;

  let sessionService: SessionService;
  let issuanceService: VirtualKeyService;
  let managementService: VirtualKeyManagementService;
  let vkRateLimiter: VirtualKeyRateLimiter;
  let vkAuthenticator: VirtualKeyAuthenticatorService;
  let activeAuthenticator: VirtualKeyAuthenticator;

  let app: ReturnType<typeof fastify>;
  let inferenceExecutionCount = 0;
  let capturedLogLines: string[] = [];

  const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
  const ORG_B_ID = '22222222-2222-4222-8222-222222222222';
  const USER_A_ADMIN_ID = 'aaaaaaaa-1111-4aaa-8aaa-aaaaaaaaaaaa';
  const USER_A_MEMBER_ID = 'aaaaaaaa-2222-4aaa-8aaa-aaaaaaaaaaaa';
  const USER_B_ADMIN_ID = 'bbbbbbbb-1111-4bbb-8bbb-bbbbbbbbbbbb';

  const ALLOWED_ORIGIN = 'https://app.switchyard.internal';
  const DISALLOWED_ORIGIN = 'https://evil.attacker.com';
  let cookieName: string;

  const EXPECTED_GENERIC_401 = {
    statusCode: 401,
    error: 'Unauthorized',
    message: 'Authentication required',
  };

  beforeAll(async () => {
    // 1. PostgreSQL 16 Disposable Setup
    pgCluster = await startDisposableCluster();
    db = await createDisposableDatabase(pgCluster, 'vk_sec_http_test');
    await bootstrapDatabase(db, passwords);

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

    adminClient = new pg.Client({ connectionString: db.url });
    await adminClient.connect();

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

    appPool = new pg.Pool({
      connectionString: roleConnectionString(db.url, 'gateway_app', passwords.gateway_app),
    });
    appPool.on('error', () => undefined);

    // 2. Redis 7 Disposable Setup
    redisCluster = await startDisposableRedis();
    appRedis = new Redis({
      host: redisCluster.host,
      port: redisCluster.port,
      username: redisCluster.appUsername,
      password: redisCluster.appPassword,
      maxRetriesPerRequest: 1,
      lazyConnect: true,
    });
    await appRedis.connect();

    adminRedis = new Redis({
      host: redisCluster.host,
      port: redisCluster.port,
      password: redisCluster.adminPassword,
      maxRetriesPerRequest: 1,
      lazyConnect: true,
    });
    await adminRedis.connect();

    // 3. Domain Services Setup
    sessionService = new SessionService({
      pool: appPool,
      environment: 'development',
      cookieOptions: { secure: false, isProduction: false },
    });
    cookieName = sessionService.getCookieName();

    issuanceService = new VirtualKeyService(appPool);
    managementService = new VirtualKeyManagementService({ pool: appPool });
    vkRateLimiter = new VirtualKeyRateLimiter(appRedis, {
      ipLimit: 30,
      ipWindowSeconds: 900,
    });
    vkAuthenticator = new VirtualKeyAuthenticatorService({
      pool: appPool,
      rateLimiter: vkRateLimiter,
    });
    activeAuthenticator = vkAuthenticator;
    const delegatingAuthenticator: VirtualKeyAuthenticator = {
      authenticateKey: (rawKey: string, clientIp?: string) =>
        activeAuthenticator.authenticateKey(rawKey, clientIp),
    };

    // 4. Fastify Server Setup with Logging Stream Capture
    const logStream = {
      write: (line: string) => {
        capturedLogLines.push(line);
      },
    };
    const testLogger = pino({ level: 'trace' }, logStream);

    app = fastify({ loggerInstance: testLogger });

    installAuthorizationBoundary(app, {
      sessionService,
      trustedOrigin: ALLOWED_ORIGIN,
      virtualKeyAuthenticator: delegatingAuthenticator,
    });

    // Data-plane virtual-key test route
    app.post(
      '/v1/test-inference',
      { config: { authz: { principal: 'virtual_key' } } },
      async (req: FastifyRequest) => {
        inferenceExecutionCount++;
        return { ok: true, principal: req.principal };
      },
    );

    // Register admin virtual-key management routes
    await registerVirtualKeyRoutes(app, { pool: appPool, service: managementService });
    await app.ready();
  }, 60000);

  afterAll(async () => {
    if (app) await app.close().catch(() => undefined);
    if (appRedis) await appRedis.quit().catch(() => undefined);
    if (adminRedis) await adminRedis.quit().catch(() => undefined);
    if (redisCluster) await redisCluster.stop().catch(() => undefined);
    if (appPool) await appPool.end().catch(() => undefined);
    if (adminClient) await adminClient.end().catch(() => undefined);
    if (db) await db.drop().catch(() => undefined);
    if (pgCluster) await pgCluster.stop().catch(() => undefined);
  });

  function makeCookie(secret: string): string {
    return `${cookieName}=${secret}`;
  }

  describe('Section 4: Uniform External HTTP 401 Authentication Error Equivalence', () => {
    let activeKey: { id: string; rawKey: string };
    let revokedKey: { id: string; rawKey: string };
    let sessionA: { secret: string; csrfToken: string };

    beforeAll(async () => {
      activeKey = await issuanceService.createKey({
        orgId: ORG_A_ID,
        name: 'Active Equivalence Key',
      });
      revokedKey = await issuanceService.createKey({
        orgId: ORG_A_ID,
        name: 'Revoked Equivalence Key',
      });
      await managementService.revokeKey(ORG_A_ID, revokedKey.id);
      sessionA = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);
    });

    const negativeCases: Array<{
      name: string;
      headers: Record<string, string>;
    }> = [
      {
        name: '1. Missing Authorization header',
        headers: {},
      },
      {
        name: '2. Empty Authorization header',
        headers: { authorization: '' },
      },
      {
        name: '3. Unsupported authorization scheme (Basic)',
        headers: { authorization: 'Basic dXNlcjpwYXNz' },
      },
      {
        name: '4. Missing Bearer value (Bearer only)',
        headers: { authorization: 'Bearer ' },
      },
      {
        name: '5. Incorrect key prefix (sk_live_...)',
        headers: {
          authorization: 'Bearer sk_live_12345678901_1234567890123456789012345678901234567890123',
        },
      },
      {
        name: '6. Incorrect key length (62 chars)',
        headers: {
          authorization: `Bearer gw_live_${'A'.repeat(11)}_${'B'.repeat(42)}`,
        },
      },
      {
        name: '7. Invalid base64url characters (contains + and /)',
        headers: {
          authorization: `Bearer gw_live_${'A'.repeat(11)}_${'A'.repeat(41)}+/`,
        },
      },
      {
        name: '8. Noncanonical base64url padding bits',
        headers: {
          authorization: `Bearer gw_live_${'A'.repeat(11)}_${'A'.repeat(42)}B`,
        },
      },
      {
        name: '9. Well-formed unknown key',
        headers: {
          authorization: `Bearer gw_live_${crypto.randomBytes(8).toString('base64url')}_${crypto.randomBytes(32).toString('base64url')}`,
        },
      },
      {
        name: '10. Previously valid, now revoked key',
        headers: {
          get authorization() {
            return `Bearer ${revokedKey.rawKey}`;
          },
        },
      },
      {
        name: '11. Browser session cookie on a virtual-key route',
        headers: {
          get cookie() {
            return makeCookie(sessionA.secret);
          },
        },
      },
      {
        name: '12. Conflicting browser cookie and Bearer token',
        headers: {
          get cookie() {
            return makeCookie(sessionA.secret);
          },
          get authorization() {
            return `Bearer ${activeKey.rawKey}`;
          },
        },
      },
    ];

    it.each(negativeCases)(
      'evaluates $name: produces exact 401, identical JSON body, zero handler execution, and no secret leakage',
      async ({ headers }) => {
        const initialCount = inferenceExecutionCount;

        const res = await app.inject({
          method: 'POST',
          url: '/v1/test-inference',
          headers,
        });

        // Exact HTTP status and body contract
        expect(res.statusCode).toBe(401);
        expect(res.json()).toEqual(EXPECTED_GENERIC_401);

        // Zero protected handler execution
        expect(inferenceExecutionCount).toBe(initialCount);

        // No sensitive credential info in response body or headers
        const bodyStr = res.body;
        expect(bodyStr).not.toContain('KEY_REVOKED');
        expect(bodyStr).not.toContain('KEY_NOT_FOUND');
        expect(bodyStr).not.toContain('MALFORMED_KEY');
        expect(bodyStr).not.toContain(ORG_A_ID);
        expect(bodyStr).not.toContain(activeKey.id);
        expect(bodyStr).not.toContain(revokedKey.id);
        expect(res.headers['www-authenticate']).toBeUndefined();
      },
    );
  });

  describe('Section 4 & 8: Distinct Failure Categories & Rate Limiter Responses', () => {
    it('returns generic 429 when per-IP abuse rate limit is exceeded', async () => {
      const abuseLimiter = new VirtualKeyRateLimiter(appRedis, {
        ipLimit: 3,
        ipWindowSeconds: 60,
      });
      const abuseAuth = new VirtualKeyAuthenticatorService({
        pool: appPool,
        rateLimiter: abuseLimiter,
      });

      const abuseApp = fastify();
      installAuthorizationBoundary(abuseApp, {
        sessionService,
        trustedOrigin: ALLOWED_ORIGIN,
        virtualKeyAuthenticator: abuseAuth,
      });
      abuseApp.post(
        '/v1/abuse-test',
        { config: { authz: { principal: 'virtual_key' } } },
        async () => ({ ok: true }),
      );

      const abuseIp = '198.51.100.99';
      await abuseLimiter.reset(abuseIp);
      const dummyKey = `gw_live_${crypto.randomBytes(8).toString('base64url')}_${crypto.randomBytes(32).toString('base64url')}`;

      // Consume IP limit (3 requests)
      for (let i = 0; i < 3; i++) {
        const res = await abuseApp.inject({
          method: 'POST',
          url: '/v1/abuse-test',
          remoteAddress: abuseIp,
          headers: {
            authorization: `Bearer ${dummyKey}`,
          },
        });
        expect(res.statusCode).toBe(401);
      }

      // 4th request triggers rate limiter
      const limitedRes = await abuseApp.inject({
        method: 'POST',
        url: '/v1/abuse-test',
        remoteAddress: abuseIp,
        headers: {
          authorization: `Bearer ${dummyKey}`,
        },
      });

      expect(limitedRes.statusCode).toBe(429);
      expect(limitedRes.json()).toEqual({
        statusCode: 429,
        error: 'Too Many Requests',
        message: 'Too many authentication attempts from this IP address. Please try again later.',
      });

      await abuseApp.close().catch(() => undefined);
    });

    it('returns controlled generic 503 when Redis rate limiter experiences an outage', async () => {
      const brokenRedis = new Redis({
        host: '127.0.0.1',
        port: 54328,
        connectTimeout: 50,
        maxRetriesPerRequest: 0,
        lazyConnect: true,
      });

      const brokenLimiter = new VirtualKeyRateLimiter(brokenRedis, {
        ipLimit: 30,
        ipWindowSeconds: 900,
      });

      const brokenAuthenticator = new VirtualKeyAuthenticatorService({
        pool: appPool,
        rateLimiter: brokenLimiter,
      });

      const testApp = fastify();
      installAuthorizationBoundary(testApp, {
        sessionService,
        trustedOrigin: ALLOWED_ORIGIN,
        virtualKeyAuthenticator: brokenAuthenticator,
      });
      testApp.post(
        '/v1/outage-test',
        { config: { authz: { principal: 'virtual_key' } } },
        async () => ({ ok: true }),
      );

      const res = await testApp.inject({
        method: 'POST',
        url: '/v1/outage-test',
        remoteAddress: '198.51.100.101',
        headers: {
          authorization: `Bearer gw_live_${crypto.randomBytes(8).toString('base64url')}_${crypto.randomBytes(32).toString('base64url')}`,
        },
      });

      expect(res.statusCode).toBe(503);
      expect(res.json()).toEqual({
        statusCode: 503,
        error: 'Service Unavailable',
        message: 'Authentication service unavailable',
      });

      await brokenRedis.quit().catch(() => undefined);
      await testApp.close().catch(() => undefined);
    });

    it('returns controlled generic 503 when PostgreSQL lookup experiences an outage', async () => {
      const brokenPool = new pg.Pool({
        connectionString: 'postgresql://invalid:invalid@127.0.0.1:54329/nonexistent',
      });
      brokenPool.on('error', () => undefined);

      const brokenAuthenticator = new VirtualKeyAuthenticatorService({
        pool: brokenPool,
        rateLimiter: { assertNotRateLimited: async () => {} },
      });

      const testApp = fastify();
      installAuthorizationBoundary(testApp, {
        sessionService,
        trustedOrigin: ALLOWED_ORIGIN,
        virtualKeyAuthenticator: brokenAuthenticator,
      });
      testApp.post(
        '/v1/db-outage-test',
        { config: { authz: { principal: 'virtual_key' } } },
        async () => ({ ok: true }),
      );

      const res = await testApp.inject({
        method: 'POST',
        url: '/v1/db-outage-test',
        remoteAddress: '198.51.100.102',
        headers: {
          authorization: `Bearer gw_live_${crypto.randomBytes(8).toString('base64url')}_${crypto.randomBytes(32).toString('base64url')}`,
        },
      });

      expect(res.statusCode).toBe(503);
      expect(res.json()).toEqual({
        statusCode: 503,
        error: 'Service Unavailable',
        message: 'Authentication service unavailable',
      });

      await brokenPool.end().catch(() => undefined);
      await testApp.close().catch(() => undefined);
    });
  });

  describe('Section 5 & 10: Browser Role Restrictions & Principal Separation (R6)', () => {
    let adminSession: { secret: string; csrfToken: string };
    let memberSession: { secret: string; csrfToken: string };
    let activeKeyId: string;
    let activeRawKey: string;

    beforeAll(async () => {
      adminSession = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);
      memberSession = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);

      const createRes = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': adminSession.csrfToken,
        },
        payload: { name: 'Role Audit Key' },
      });
      expect(createRes.statusCode).toBe(201);
      const json = createRes.json();
      activeKeyId = json.id;
      activeRawKey = json.rawKey;
    });

    it('Admin session: full authorized management operations succeed', async () => {
      // 1. Create key
      const create = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': adminSession.csrfToken,
        },
        payload: { name: 'Admin Allowed Key' },
      });
      expect(create.statusCode).toBe(201);
      const createdKeyId = create.json().id;

      // 2. List keys
      const list = await app.inject({
        method: 'GET',
        url: '/api/keys',
        headers: { cookie: makeCookie(adminSession.secret) },
      });
      expect(list.statusCode).toBe(200);

      // 3. Update policy
      const update = await app.inject({
        method: 'PUT',
        url: `/api/keys/${createdKeyId}/policy`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': adminSession.csrfToken,
        },
        payload: {
          allowedModels: ['gpt-4o'],
          rpmLimit: 100,
          tpmLimit: 1000,
          concurrentStreamLimit: 2,
          exactCacheEnabled: false,
          semanticCacheEnabled: false,
          piiRedactionEnabled: true,
          storePayloads: false,
        },
      });
      expect(update.statusCode).toBe(200);

      // 4. Revoke key
      const revoke = await app.inject({
        method: 'DELETE',
        url: `/api/keys/${createdKeyId}`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': adminSession.csrfToken,
        },
      });
      expect(revoke.statusCode).toBe(204);

      // 5. Repeat revoke (idempotent)
      const repeatRevoke = await app.inject({
        method: 'DELETE',
        url: `/api/keys/${createdKeyId}`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': adminSession.csrfToken,
        },
      });
      expect(repeatRevoke.statusCode).toBe(204);
    });

    it('Member session: all virtual-key management endpoints are denied with 403 Forbidden', async () => {
      // 1. Create
      const create = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(memberSession.secret),
          'x-csrf-token': memberSession.csrfToken,
        },
        payload: { name: 'Member Forbidden Key' },
      });
      expect(create.statusCode).toBe(403);

      // 2. List
      const list = await app.inject({
        method: 'GET',
        url: '/api/keys',
        headers: { cookie: makeCookie(memberSession.secret) },
      });
      expect(list.statusCode).toBe(403);

      // 3. Update Policy
      const update = await app.inject({
        method: 'PUT',
        url: `/api/keys/${activeKeyId}/policy`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(memberSession.secret),
          'x-csrf-token': memberSession.csrfToken,
        },
        payload: {
          allowedModels: ['gpt-4o'],
          rpmLimit: 10,
          tpmLimit: 100,
          concurrentStreamLimit: 1,
          exactCacheEnabled: false,
          semanticCacheEnabled: false,
          piiRedactionEnabled: true,
          storePayloads: false,
        },
      });
      expect(update.statusCode).toBe(403);

      // 4. Revoke
      const revoke = await app.inject({
        method: 'DELETE',
        url: `/api/keys/${activeKeyId}`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(memberSession.secret),
          'x-csrf-token': memberSession.csrfToken,
        },
      });
      expect(revoke.statusCode).toBe(403);
    });

    it('Anonymous caller (no cookie): management endpoints rejected with 401 Unauthorized', async () => {
      const endpoints: Array<{ method: 'GET' | 'POST' | 'PUT' | 'DELETE'; url: string }> = [
        { method: 'POST', url: '/api/keys' },
        { method: 'GET', url: '/api/keys' },
        { method: 'PUT', url: `/api/keys/${activeKeyId}/policy` },
        { method: 'DELETE', url: `/api/keys/${activeKeyId}` },
      ];

      for (const ep of endpoints) {
        const injectOpts: {
          method: 'GET' | 'POST' | 'PUT' | 'DELETE';
          url: string;
          headers: Record<string, string>;
          payload?: Record<string, unknown>;
        } = {
          method: ep.method,
          url: ep.url,
          headers: { origin: ALLOWED_ORIGIN },
        };
        if (ep.method === 'POST' || ep.method === 'PUT') {
          injectOpts.payload = {};
        }
        const res = await app.inject(injectOpts);
        expect(res.statusCode).toBe(401);
        expect(JSON.parse(res.body)).toEqual(EXPECTED_GENERIC_401);
      }
    });

    it('Virtual-key Bearer credential: cannot access management routes (401 Unauthorized)', async () => {
      const endpoints: Array<{ method: 'GET' | 'POST' | 'PUT' | 'DELETE'; url: string }> = [
        { method: 'POST', url: '/api/keys' },
        { method: 'GET', url: '/api/keys' },
        { method: 'PUT', url: `/api/keys/${activeKeyId}/policy` },
        { method: 'DELETE', url: `/api/keys/${activeKeyId}` },
      ];

      for (const ep of endpoints) {
        const injectOpts: {
          method: 'GET' | 'POST' | 'PUT' | 'DELETE';
          url: string;
          headers: Record<string, string>;
          payload?: Record<string, unknown>;
        } = {
          method: ep.method,
          url: ep.url,
          headers: {
            origin: ALLOWED_ORIGIN,
            authorization: `Bearer ${activeRawKey}`,
          },
        };
        if (ep.method === 'POST' || ep.method === 'PUT') {
          injectOpts.payload = {};
        }
        const res = await app.inject(injectOpts);
        expect(res.statusCode).toBe(401);
        expect(JSON.parse(res.body)).toEqual(EXPECTED_GENERIC_401);
      }
    });

    it('Missing or invalid CSRF token rejects mutations with 403 Forbidden', async () => {
      // 1. Missing CSRF
      const missingCsrf = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
        },
        payload: { name: 'Missing CSRF' },
      });
      expect(missingCsrf.statusCode).toBe(403);

      // 2. Invalid CSRF
      const invalidCsrf = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': 'invalid_forged_csrf_token',
        },
        payload: { name: 'Invalid CSRF' },
      });
      expect(invalidCsrf.statusCode).toBe(403);
    });

    it('Missing or invalid Origin header rejects mutations with 403 Forbidden', async () => {
      // 1. Missing Origin
      const missingOrigin = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': adminSession.csrfToken,
        },
        payload: { name: 'Missing Origin' },
      });
      expect(missingOrigin.statusCode).toBe(403);

      // 2. Disallowed Origin
      const wrongOrigin = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: DISALLOWED_ORIGIN,
          cookie: makeCookie(adminSession.secret),
          'x-csrf-token': adminSession.csrfToken,
        },
        payload: { name: 'Wrong Origin' },
      });
      expect(wrongOrigin.statusCode).toBe(403);
    });
  });

  describe('Section 7: Secret-Leakage Regression Matrix & Canary Verification', () => {
    it('executes all 14 operations and verifies zero secret leakage into logs, responses, Redis, or DB metadata', async () => {
      capturedLogLines = [];

      const canaryAdminSession = await sessionService.createSession(ORG_A_ID, USER_A_ADMIN_ID);
      const canaryMemberSession = await sessionService.createSession(ORG_A_ID, USER_A_MEMBER_ID);
      const canaryOrgBAdminSession = await sessionService.createSession(ORG_B_ID, USER_B_ADMIN_ID);

      const canaryUniqueToken = crypto.randomBytes(8).toString('hex');

      // Op 1: Key Creation (discloses rawKey once, sets no-store/no-cache, zero verifier disclosure)
      const createRes = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(canaryAdminSession.secret),
          'x-csrf-token': canaryAdminSession.csrfToken,
        },
        payload: { name: 'Canary Matrix Key' },
      });
      expect(createRes.statusCode).toBe(201);
      const createJson = createRes.json();
      const canaryRawKey: string = createJson.rawKey;
      const canaryKeyId: string = createJson.id;
      const canarySecret: string = canaryRawKey.slice(20);

      // Assert creation response: contains rawKey, Cache-Control: no-store, Pragma: no-cache, but NEVER key_hash
      expect(canaryRawKey).toMatch(/^gw_live_[A-Za-z0-9_-]{11}_[A-Za-z0-9_-]{43}$/);
      expect(canarySecret.length).toBe(43);
      expect(createJson.keyHash).toBeUndefined();
      expect(createJson.key_hash).toBeUndefined();
      expect(createRes.headers['cache-control']).toBe('no-store');
      expect(createRes.headers['pragma']).toBe('no-cache');

      // Op 2: Metadata Listing
      const listRes = await app.inject({
        method: 'GET',
        url: '/api/keys',
        headers: { cookie: makeCookie(canaryAdminSession.secret) },
      });
      expect(listRes.statusCode).toBe(200);

      // Op 3: Policy Replacement
      const updateRes = await app.inject({
        method: 'PUT',
        url: `/api/keys/${canaryKeyId}/policy`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(canaryAdminSession.secret),
          'x-csrf-token': canaryAdminSession.csrfToken,
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

      // Op 4: Key Revocation
      const revokeRes = await app.inject({
        method: 'DELETE',
        url: `/api/keys/${canaryKeyId}`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(canaryAdminSession.secret),
          'x-csrf-token': canaryAdminSession.csrfToken,
        },
      });
      expect(revokeRes.statusCode).toBe(204);

      // Op 5: Repeat Revocation (idempotent)
      const repeatRevokeRes = await app.inject({
        method: 'DELETE',
        url: `/api/keys/${canaryKeyId}`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(canaryAdminSession.secret),
          'x-csrf-token': canaryAdminSession.csrfToken,
        },
      });
      expect(repeatRevokeRes.statusCode).toBe(204);

      // Op 6: Successful virtual-key authentication (using a newly created active key)
      const MATRIX_TEST_IP = '198.51.100.77';
      const freshKey = await issuanceService.createKey({
        orgId: ORG_A_ID,
        name: 'Fresh Active Key',
      });
      const authSuccessRes = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        remoteAddress: MATRIX_TEST_IP,
        headers: { authorization: `Bearer ${freshKey.rawKey}` },
      });
      expect(authSuccessRes.statusCode).toBe(200);

      // Op 7: Unknown-key authentication
      const unknownKey = `gw_live_${crypto.randomBytes(8).toString('base64url')}_${crypto.randomBytes(32).toString('base64url')}`;
      const authUnknownRes = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        remoteAddress: MATRIX_TEST_IP,
        headers: { authorization: `Bearer ${unknownKey}` },
      });
      expect(authUnknownRes.statusCode).toBe(401);

      // Op 8: Malformed-key authentication
      const authMalformedRes = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        remoteAddress: MATRIX_TEST_IP,
        headers: { authorization: 'Bearer gw_live_bad_short' },
      });
      expect(authMalformedRes.statusCode).toBe(401);

      // Op 9: Revoked-key authentication
      const authRevokedRes = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        remoteAddress: MATRIX_TEST_IP,
        headers: { authorization: `Bearer ${canaryRawKey}` },
      });
      expect(authRevokedRes.statusCode).toBe(401);

      // Op 10: Unauthorized member management attempt
      const memberRes = await app.inject({
        method: 'POST',
        url: '/api/keys',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(canaryMemberSession.secret),
          'x-csrf-token': canaryMemberSession.csrfToken,
        },
        payload: { name: 'Member Unauthorized Key' },
      });
      expect(memberRes.statusCode).toBe(403);

      // Op 11: Cross-tenant key management attempt (Tenant B attempts to update Tenant A key)
      const crossTenantRes = await app.inject({
        method: 'PUT',
        url: `/api/keys/${canaryKeyId}/policy`,
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: makeCookie(canaryOrgBAdminSession.secret),
          'x-csrf-token': canaryOrgBAdminSession.csrfToken,
        },
        payload: {
          allowedModels: ['gpt-4o'],
          rpmLimit: 10,
          tpmLimit: 100,
          concurrentStreamLimit: 1,
          exactCacheEnabled: false,
          semanticCacheEnabled: false,
          piiRedactionEnabled: true,
          storePayloads: false,
        },
      });
      expect(crossTenantRes.statusCode).toBe(404);

      // Op 12: Database failure canary (injected deterministic failure routed through real authenticator)
      const canaryDbError = `CANARY_SQL_SYNTHETIC_DRIVER_ERROR_${canaryUniqueToken}`;
      const dbFailurePool = {
        query: async () => {
          throw new Error(canaryDbError);
        },
      } as unknown as pg.Pool;

      const dbFailureAuthenticator = new VirtualKeyAuthenticatorService({
        pool: dbFailurePool,
        rateLimiter: vkRateLimiter,
      });

      const initialExecCountBeforeDbCanary = inferenceExecutionCount;
      activeAuthenticator = dbFailureAuthenticator;
      let dbExceptionRes: Awaited<ReturnType<typeof app.inject>>;
      try {
        dbExceptionRes = await app.inject({
          method: 'POST',
          url: '/v1/test-inference',
          remoteAddress: MATRIX_TEST_IP,
          headers: { authorization: `Bearer ${freshKey.rawKey}` },
        });
      } finally {
        activeAuthenticator = vkAuthenticator;
      }

      expect(dbExceptionRes.statusCode).toBe(503);
      expect(dbExceptionRes.json()).toEqual({
        statusCode: 503,
        error: 'Service Unavailable',
        message: 'Authentication service unavailable',
      });
      expect(inferenceExecutionCount).toBe(initialExecCountBeforeDbCanary);

      // Op 13: Redis failure canary (injected deterministic limiter failure routed through real authenticator)
      const canaryRedisError = `CANARY_REDIS_SYNTHETIC_CONNECTION_ERROR_${canaryUniqueToken}`;
      const brokenRedisLimiter = {
        assertNotRateLimited: async () => {
          throw new Error(canaryRedisError);
        },
      } as unknown as VirtualKeyRateLimiter;

      const redisFailureAuthenticator = new VirtualKeyAuthenticatorService({
        pool: appPool,
        rateLimiter: brokenRedisLimiter,
      });

      const initialExecCountBeforeRedisCanary = inferenceExecutionCount;
      activeAuthenticator = redisFailureAuthenticator;
      let redisExceptionRes: Awaited<ReturnType<typeof app.inject>>;
      try {
        redisExceptionRes = await app.inject({
          method: 'POST',
          url: '/v1/test-inference',
          remoteAddress: MATRIX_TEST_IP,
          headers: { authorization: `Bearer ${freshKey.rawKey}` },
        });
      } finally {
        activeAuthenticator = vkAuthenticator;
      }

      expect(redisExceptionRes.statusCode).toBe(503);
      expect(redisExceptionRes.json()).toEqual({
        statusCode: 503,
        error: 'Service Unavailable',
        message: 'Authentication service unavailable',
      });
      expect(inferenceExecutionCount).toBe(initialExecCountBeforeRedisCanary);

      // Op 14: Authentication abuse-rate rejection
      // Trigger 429 on test IP
      const abuseIp = '198.51.100.188';
      let rateLimitedRes: Awaited<ReturnType<typeof app.inject>> | undefined;
      const initialExecCountBeforeAbuse = inferenceExecutionCount;
      for (let i = 0; i < 31; i++) {
        const res = await app.inject({
          method: 'POST',
          url: '/v1/test-inference',
          remoteAddress: abuseIp,
          headers: {
            authorization: `Bearer ${unknownKey}`,
          },
        });
        if (i < 30) {
          expect(res.statusCode).toBe(401);
        } else {
          rateLimitedRes = res;
        }
      }

      expect(rateLimitedRes).toBeDefined();
      expect(rateLimitedRes!.statusCode).toBe(429);
      expect(rateLimitedRes!.json()).toEqual({
        statusCode: 429,
        error: 'Too Many Requests',
        message: 'Too many authentication attempts from this IP address. Please try again later.',
      });
      expect(inferenceExecutionCount).toBe(initialExecCountBeforeAbuse);

      // --- Assertions on Captured Surfaces ---

      // 1. Response Bodies (excluding creation plaintext disclosure):
      const postCreationResponses = [
        listRes.body,
        updateRes.body,
        revokeRes.body,
        repeatRevokeRes.body,
        authSuccessRes.body,
        authUnknownRes.body,
        authMalformedRes.body,
        authRevokedRes.body,
        memberRes.body,
        crossTenantRes.body,
        dbExceptionRes.body,
        redisExceptionRes.body,
        rateLimitedRes!.body,
      ];

      for (const body of postCreationResponses) {
        expect(body).not.toContain(canaryRawKey);
        expect(body).not.toContain(canarySecret);
        expect(body).not.toContain(canaryAdminSession.secret);
        expect(body).not.toContain(canaryAdminSession.csrfToken);
        expect(body).not.toContain('keyHash');
        expect(body).not.toContain('key_hash');
        expect(body).not.toContain(canaryDbError);
        expect(body).not.toContain(canaryRedisError);
        expect(body).not.toContain('CANARY_SQL_SYNTHETIC_DRIVER_ERROR');
        expect(body).not.toContain('CANARY_REDIS_SYNTHETIC_CONNECTION_ERROR');
      }

      // 2. Structured Application Logs:
      const allLogs = capturedLogLines.join('\n');
      expect(allLogs).not.toContain(canaryRawKey);
      expect(allLogs).not.toContain(canarySecret);
      expect(allLogs).not.toContain(canaryAdminSession.secret);
      expect(allLogs).not.toContain(canaryAdminSession.csrfToken);
      expect(allLogs).not.toContain(passwords.gateway_app);
      expect(allLogs).not.toContain('postgres://');
      expect(allLogs).not.toContain(canaryDbError);
      expect(allLogs).not.toContain(canaryRedisError);
      expect(allLogs).not.toContain('CANARY_SQL_SYNTHETIC_DRIVER_ERROR');
      expect(allLogs).not.toContain('CANARY_REDIS_SYNTHETIC_CONNECTION_ERROR');

      // 3. Redis State:
      // Assert Redis contains ONLY abuse-limiter keys (auth:ratelimit:vk:ip:*)
      // NEVER raw keys, secrets, or authorization caches
      const redisKeys = await adminRedis.keys('*');
      for (const k of redisKeys) {
        expect(k).toMatch(/^auth:ratelimit:(vk:ip|ip):[0-9a-fA-F.:]+$/);
        expect(k).not.toContain('gw_live_');
        expect(k).not.toContain(canarySecret);
        const val = await adminRedis.get(k);
        expect(val).not.toContain('gw_live_');
        expect(val).not.toContain(canarySecret);
      }

      // 4. PostgreSQL Database Rows:
      // Rows store only 32-byte key_hash, never raw keys
      const dbRows = await adminClient.query<{ id: string; key_hash: Buffer }>(
        'SELECT id, key_hash FROM public.virtual_keys WHERE id = $1',
        [canaryKeyId],
      );
      expect(dbRows.rows.length).toBe(1);
      expect(dbRows.rows[0]!.key_hash.length).toBe(32);
      expect(dbRows.rows[0]!.key_hash.toString('utf8')).not.toContain(canarySecret);
    });
  });
});
