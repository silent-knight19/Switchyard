import crypto from 'node:crypto';
import fastify, { type FastifyInstance } from 'fastify';
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
import { installAuthorizationBoundary, type VirtualKeyPrincipal } from './authorization.js';
import { SessionService } from './session.js';
import { startDisposableRedis, type DisposableRedisCluster } from './test/disposable-redis.js';
import { VirtualKeyService } from './virtual-key.js';
import { VirtualKeyAuthenticatorService } from './virtual-key-authenticator.js';
import { VirtualKeyRateLimiter } from './virtual-key-rate-limiter.js';

describe('SW-1.6.2: Real HTTP Virtual Key Authentication Suite (Section 10 D & E)', () => {
  let pgCluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();
  let adminClient: pg.Client;
  let appPool: pg.Pool;

  let redisCluster: DisposableRedisCluster;
  let appRedis: Redis;

  let sessionService: SessionService;
  let issuanceService: VirtualKeyService;
  let vkRateLimiter: VirtualKeyRateLimiter;
  let vkAuthenticator: VirtualKeyAuthenticatorService;

  const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
  const ORG_B_ID = '22222222-2222-4222-8222-222222222222';
  const USER_A_ID = '33333333-3333-4333-8333-333333333333';
  const ALLOWED_ORIGIN = 'http://localhost:3000';
  let cookieName: string;

  const EXPECTED_GENERIC_401 = {
    statusCode: 401,
    error: 'Unauthorized',
    message: 'Authentication required',
  };

  beforeAll(async () => {
    // 1. PostgreSQL 16 Disposable Setup
    pgCluster = await startDisposableCluster();
    db = await createDisposableDatabase(pgCluster, 'vk_auth_http_test');
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
    `);

    await adminClient.query(`
      INSERT INTO public.users (id, org_id, email_normalized, password_hash, role)
      VALUES
        ('${USER_A_ID}', '${ORG_A_ID}', 'admin@alpha.example.com', 'dummy_hash', 'admin');
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

    // 3. Services Setup
    sessionService = new SessionService({
      pool: appPool,
      environment: 'development',
      cookieOptions: { secure: false, isProduction: false },
    });
    cookieName = sessionService.getCookieName();

    issuanceService = new VirtualKeyService(appPool);

    vkRateLimiter = new VirtualKeyRateLimiter(appRedis, {
      ipLimit: 30,
      ipWindowSeconds: 900,
    });

    vkAuthenticator = new VirtualKeyAuthenticatorService({
      pool: appPool,
      rateLimiter: vkRateLimiter,
    });
  }, 60000);

  afterAll(async () => {
    if (appRedis) await appRedis.quit().catch(() => undefined);
    if (redisCluster) await redisCluster.stop().catch(() => undefined);
    if (appPool) await appPool.end().catch(() => undefined);
    if (adminClient) await adminClient.end().catch(() => undefined);
    if (db) await db.drop().catch(() => undefined);
    if (pgCluster) await pgCluster.stop().catch(() => undefined);
  });

  interface AppFixture {
    app: FastifyInstance;
    getInferenceCount: () => number;
    getLastPrincipal: () => VirtualKeyPrincipal | undefined;
  }

  function createTestApp(authenticatorOverride?: VirtualKeyAuthenticatorService): AppFixture {
    const app = fastify();

    let inferenceCount = 0;
    let lastPrincipal: VirtualKeyPrincipal | undefined;

    installAuthorizationBoundary(app, {
      sessionService,
      trustedOrigin: ALLOWED_ORIGIN,
      virtualKeyAuthenticator: authenticatorOverride ?? vkAuthenticator,
    });

    // Virtual-key test route
    app.post(
      '/v1/test-inference',
      { config: { authz: { principal: 'virtual_key' } } },
      async (req) => {
        inferenceCount++;
        lastPrincipal = req.principal as VirtualKeyPrincipal;
        return { ok: true, principal: req.principal };
      },
    );

    // Browser admin route
    app.get(
      '/api/admin/dashboard',
      { config: { authz: { principal: 'browser', minRole: 'admin' } } },
      async () => ({ ok: true }),
    );

    return {
      app,
      getInferenceCount: () => inferenceCount,
      getLastPrincipal: () => lastPrincipal,
    };
  }

  describe('1. Real HTTP Authentication Matrix (Section 10 D)', () => {
    it('Valid active key -> Success (200), handler executes, principal attached', async () => {
      const { app, getInferenceCount, getLastPrincipal } = createTestApp();
      const key = await issuanceService.createKey({ orgId: ORG_A_ID, name: 'Active HTTP Key' });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        headers: {
          authorization: `Bearer ${key.rawKey}`,
        },
      });

      expect(res.statusCode).toBe(200);
      expect(getInferenceCount()).toBe(1);

      const principal = getLastPrincipal();
      expect(principal).toBeDefined();
      expect(principal?.type).toBe('virtual_key');
      expect(principal?.keyId).toBe(key.id);
      expect(principal?.orgId).toBe(ORG_A_ID);
      expect(principal?.keyPolicy?.allowedModels).toEqual([]);
      expect(principal?.keyPolicy?.rpmLimit).toBe(1);
    });

    it.each([
      ['Missing Authorization header', {}],
      ['Empty Authorization header', { authorization: '' }],
      ['Wrong scheme (Basic)', { authorization: 'Basic dXNlcjpwYXNz' }],
      ['Wrong scheme (Token)', { authorization: 'Token 123456789' }],
      [
        'Malformed token envelope (wrong prefix)',
        { authorization: 'Bearer sk_live_12345678901_1234567890123456789012345678901234567890123' },
      ],
      ['Incorrect length (too short)', { authorization: 'Bearer gw_live_abc_short' }],
      [
        'Incorrect length (62 chars)',
        { authorization: `Bearer gw_live_${'A'.repeat(11)}_${'B'.repeat(42)}` },
      ],
      [
        'Noncanonical base64url padding bits',
        { authorization: `Bearer gw_live_${'A'.repeat(11)}_${'A'.repeat(42)}B` },
      ],
      [
        'Well-formed unknown key',
        {
          authorization: `Bearer gw_live_${crypto.randomBytes(8).toString('base64url')}_${crypto.randomBytes(32).toString('base64url')}`,
        },
      ],
    ])(
      '%s produces exact HTTP 401 response body and zero handler executions',
      async (_desc, headers) => {
        const { app, getInferenceCount } = createTestApp();

        const res = await app.inject({
          method: 'POST',
          url: '/v1/test-inference',
          headers,
        });

        expect(res.statusCode).toBe(401);
        expect(res.json()).toEqual(EXPECTED_GENERIC_401);
        expect(getInferenceCount()).toBe(0);
      },
    );

    it('Revoked key produces exact HTTP 401 response body and zero handler executions', async () => {
      const { app, getInferenceCount } = createTestApp();
      const key = await issuanceService.createKey({ orgId: ORG_A_ID, name: 'Key to Revoke HTTP' });

      // Revoke in DB
      await adminClient.query('UPDATE public.virtual_keys SET revoked_at = NOW() WHERE id = $1', [
        key.id,
      ]);

      const res = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        headers: {
          authorization: `Bearer ${key.rawKey}`,
        },
      });

      expect(res.statusCode).toBe(401);
      expect(res.json()).toEqual(EXPECTED_GENERIC_401);
      expect(getInferenceCount()).toBe(0);
    });

    it('Browser cookie on virtual-key route produces exact HTTP 401 and zero handler executions', async () => {
      const { app, getInferenceCount } = createTestApp();
      const session = await sessionService.createSession(ORG_A_ID, USER_A_ID);

      const res = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        headers: {
          cookie: `${cookieName}=${session.secret}`,
        },
      });

      expect(res.statusCode).toBe(401);
      expect(res.json()).toEqual(EXPECTED_GENERIC_401);
      expect(getInferenceCount()).toBe(0);
    });

    it('Conflicting cookie and bearer on virtual-key route produces exact HTTP 401', async () => {
      const { app, getInferenceCount } = createTestApp();
      const key = await issuanceService.createKey({ orgId: ORG_A_ID, name: 'Conflict Key' });
      const session = await sessionService.createSession(ORG_A_ID, USER_A_ID);

      const res = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        headers: {
          authorization: `Bearer ${key.rawKey}`,
          cookie: `${cookieName}=${session.secret}`,
        },
      });

      expect(res.statusCode).toBe(401);
      expect(res.json()).toEqual(EXPECTED_GENERIC_401);
      expect(getInferenceCount()).toBe(0);
    });

    it('Valid virtual key cannot authenticate as browser administrator (401)', async () => {
      const { app } = createTestApp();
      const key = await issuanceService.createKey({ orgId: ORG_A_ID, name: 'Cross Key' });

      const res = await app.inject({
        method: 'GET',
        url: '/api/admin/dashboard',
        headers: {
          authorization: `Bearer ${key.rawKey}`,
        },
      });

      expect(res.statusCode).toBe(401);
      expect(res.json()).toEqual(EXPECTED_GENERIC_401);
    });

    it('IP abuse threshold exceeded produces generic HTTP 429', async () => {
      const customRateLimiter = new VirtualKeyRateLimiter(appRedis, {
        ipLimit: 3,
        ipWindowSeconds: 60,
      });
      const customAuth = new VirtualKeyAuthenticatorService({
        pool: appPool,
        rateLimiter: customRateLimiter,
      });

      const { app } = createTestApp(customAuth);
      const testIp = '198.51.100.123';
      await customRateLimiter.reset(testIp);

      const key = await issuanceService.createKey({ orgId: ORG_A_ID, name: 'Rate Test Key' });

      // First 3 requests succeed
      for (let i = 0; i < 3; i++) {
        const res = await app.inject({
          method: 'POST',
          url: '/v1/test-inference',
          headers: {
            authorization: `Bearer ${key.rawKey}`,
            'x-forwarded-for': testIp,
          },
          remoteAddress: testIp,
        });
        expect(res.statusCode).toBe(200);
      }

      // 4th request must be rejected with 429
      const rateRes = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        headers: {
          authorization: `Bearer ${key.rawKey}`,
          'x-forwarded-for': testIp,
        },
        remoteAddress: testIp,
      });

      expect(rateRes.statusCode).toBe(429);
      expect(rateRes.json()).toEqual({
        statusCode: 429,
        error: 'Too Many Requests',
        message: 'Too many authentication attempts from this IP address. Please try again later.',
      });
    });

    it('Redis backend failure produces generic HTTP 503', async () => {
      const deadRedis = new Redis({
        host: '127.0.0.1',
        port: 65534,
        connectTimeout: 200,
        maxRetriesPerRequest: 0,
        lazyConnect: true,
      });
      const deadRateLimiter = new VirtualKeyRateLimiter(deadRedis);
      const deadAuth = new VirtualKeyAuthenticatorService({
        pool: appPool,
        rateLimiter: deadRateLimiter,
      });

      const { app, getInferenceCount } = createTestApp(deadAuth);
      const key = await issuanceService.createKey({ orgId: ORG_A_ID, name: 'Redis Fail Key' });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        headers: {
          authorization: `Bearer ${key.rawKey}`,
        },
      });

      expect(res.statusCode).toBe(503);
      expect(res.json()).toEqual({
        statusCode: 503,
        error: 'Service Unavailable',
        message: 'Authentication service unavailable',
      });
      expect(getInferenceCount()).toBe(0);
      await deadRedis.quit().catch(() => undefined);
    });

    it('PostgreSQL backend failure produces generic HTTP 503', async () => {
      const deadPool = new pg.Pool({
        connectionString: 'postgresql://gateway_app:pw@127.0.0.1:65534/dead_db',
        connectionTimeoutMillis: 200,
      });
      deadPool.on('error', () => undefined);

      const deadAuth = new VirtualKeyAuthenticatorService({
        pool: deadPool,
        rateLimiter: vkRateLimiter,
      });

      const { app, getInferenceCount } = createTestApp(deadAuth);
      const key = await issuanceService.createKey({ orgId: ORG_A_ID, name: 'PG Fail Key' });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        headers: {
          authorization: `Bearer ${key.rawKey}`,
        },
      });

      expect(res.statusCode).toBe(503);
      expect(res.json()).toEqual({
        statusCode: 503,
        error: 'Service Unavailable',
        message: 'Authentication service unavailable',
      });
      expect(getInferenceCount()).toBe(0);
      await deadPool.end().catch(() => undefined);
    });
  });

  describe('2. Secret Leakage Verification (Section 10 E)', () => {
    it('proves zero credential material leaks in logs, errors, or responses across failure modes', async () => {
      const logLines: string[] = [];
      const testLogger = pino(
        { level: 'trace' },
        {
          write: (chunk: string) => {
            logLines.push(chunk);
          },
        },
      );

      const app = fastify({ loggerInstance: testLogger });
      installAuthorizationBoundary(app, {
        sessionService,
        trustedOrigin: ALLOWED_ORIGIN,
        virtualKeyAuthenticator: vkAuthenticator,
      });

      app.post(
        '/v1/test-inference',
        { config: { authz: { principal: 'virtual_key' } } },
        async (req) => ({ ok: true, principal: req.principal }),
      );

      // Create canary key
      const canaryKey = await issuanceService.createKey({
        orgId: ORG_A_ID,
        name: 'Canary Leakage Key',
      });

      // Extract canary secret segment (43 chars)
      const parsed = canaryKey.rawKey.slice(20); // 43 chars secret
      expect(parsed.length).toBe(43);

      const capturedResponses: string[] = [];

      // 1. Successful authentication
      const resSuccess = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        headers: { authorization: `Bearer ${canaryKey.rawKey}` },
      });
      capturedResponses.push(resSuccess.body);

      // 2. Malformed authentication
      const resMalformed = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        headers: { authorization: `Bearer ${canaryKey.rawKey}==` },
      });
      capturedResponses.push(resMalformed.body);

      // 3. Unknown key failure
      const fakeCanary = `gw_live_${canaryKey.keyPrefix.slice(8)}_${crypto.randomBytes(32).toString('base64url')}`;
      const resUnknown = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        headers: { authorization: `Bearer ${fakeCanary}` },
      });
      capturedResponses.push(resUnknown.body);

      // 4. Revoked key failure
      await adminClient.query('UPDATE public.virtual_keys SET revoked_at = NOW() WHERE id = $1', [
        canaryKey.id,
      ]);
      const resRevoked = await app.inject({
        method: 'POST',
        url: '/v1/test-inference',
        headers: { authorization: `Bearer ${canaryKey.rawKey}` },
      });
      capturedResponses.push(resRevoked.body);

      // Inspect combined logs and responses
      const allText = logLines.join('\n') + '\n' + capturedResponses.join('\n');

      // Prohibited items:
      expect(allText).not.toContain(canaryKey.rawKey);
      expect(allText).not.toContain(parsed); // 43-character secret
      expect(allText).not.toContain(`Bearer ${canaryKey.rawKey}`);
      expect(allText).not.toContain(passwords.gateway_app);
      expect(allText).not.toContain(passwords.gateway_migrator);
    });
  });
});
