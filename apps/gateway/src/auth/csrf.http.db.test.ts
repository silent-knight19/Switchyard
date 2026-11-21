import crypto from 'node:crypto';
import net from 'node:net';
import fastify, { type FastifyReply, type FastifyRequest } from 'fastify';
import pg from 'pg';
import pino from 'pino';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
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
import { registerHealthRoutes } from '../routes/health.js';
import { REDACTION_PATHS } from '../logging/redaction.js';
import { SessionService } from './session.js';
import { createCsrfProtectionPreHandler, validateOrigin } from './csrf.js';
import { CsrfError, SessionError } from './types.js';
import { buildApp } from '../app.js';
import * as authBarrel from './index.js';

/**
 * Test fixture for registering CSRF-protected mutation and reissuance routes
 * within isolated test suites (CSRF-03).
 */
function registerTestCsrfRoutes(
  app: ReturnType<typeof fastify>,
  options: { sessionService: SessionService; allowedOrigin: string; onMutation?: () => void },
) {
  const { sessionService, allowedOrigin, onMutation } = options;
  const csrfPreHandler = createCsrfProtectionPreHandler({ sessionService, allowedOrigin });

  // Test-only token reissuance endpoint
  app.post('/test/auth/csrf/reissue', async (req: FastifyRequest, reply: FastifyReply) => {
    // Requires exact allowed Origin
    const originResult = validateOrigin(req.headers['origin'], allowedOrigin);
    if (!originResult.valid) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Invalid or missing Origin',
      });
    }

    // Requires authenticated browser session
    const sessionSecret = sessionService.extractSessionSecretFromCookieHeader(
      req.headers['cookie'],
    );
    if (!sessionSecret) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Authentication required',
      });
    }

    try {
      const { csrfToken } = await sessionService.reissueCsrfToken(sessionSecret);
      return reply
        .header('Cache-Control', 'no-store, no-cache, must-revalidate, private')
        .header('Pragma', 'no-cache')
        .send({ csrfToken });
    } catch (err) {
      if (err instanceof SessionError) {
        return reply.status(401).send({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Authentication required',
        });
      }
      return reply.status(500).send({
        statusCode: 500,
        error: 'Internal Server Error',
        message: 'Internal server error',
      });
    }
  });

  // Test-only protected mutation endpoint
  app.post(
    '/test/protected/mutation',
    { preHandler: csrfPreHandler },
    async (_req: FastifyRequest, reply: FastifyReply) => {
      if (onMutation) onMutation();
      return reply.status(200).send({ success: true, mutated: true });
    },
  );

  // Test-only protected PUT mutation
  app.put(
    '/test/protected/mutation',
    { preHandler: csrfPreHandler },
    async (_req: FastifyRequest, reply: FastifyReply) => {
      if (onMutation) onMutation();
      return reply.status(200).send({ success: true, mutated: true });
    },
  );

  // Test-only protected DELETE mutation
  app.delete(
    '/test/protected/mutation',
    { preHandler: csrfPreHandler },
    async (_req: FastifyRequest, reply: FastifyReply) => {
      if (onMutation) onMutation();
      return reply.status(200).send({ success: true, mutated: true });
    },
  );
}

describe('SW-1.5.3: Fastify HTTP Injection & Security Test Suite', () => {
  let cluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();
  let adminClient: pg.Client;
  let appPool: pg.Pool;
  let sessionService: SessionService;
  let app: ReturnType<typeof fastify>;
  let serverPort: number;

  const ALLOWED_ORIGIN = 'https://app.switchyard.internal';
  const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
  const USER_A_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

  let mutationInvocationCount = 0;
  const logEntries: string[] = [];

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    db = await createDisposableDatabase(cluster, 'csrf_http_test');
    await bootstrapDatabase(db, passwords);

    // Apply migrations
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
      VALUES ('${ORG_A_ID}', 'Org Alpha', 1000000, 1, '\\x01', '\\x02', '\\x03');

      INSERT INTO public.users (id, org_id, email_normalized, password_hash, role)
      VALUES ('${USER_A_ID}', '${ORG_A_ID}', 'user.a@alpha.com', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$dGVzdA', 'admin');
    `);

    appPool = new pg.Pool({
      connectionString: roleConnectionString(db.url, 'gateway_app', passwords.gateway_app),
    });

    sessionService = new SessionService({
      pool: appPool,
      environment: 'production',
      cookieOptions: { isProduction: true },
    });

    // Custom logger stream to capture logs for redaction and leakage assertions
    const destinationStream = {
      write(msg: string) {
        logEntries.push(msg);
      },
    };

    const logger = pino(
      {
        level: 'info',
        redact: {
          paths: REDACTION_PATHS,
          censor: '[REDACTED]',
        },
      },
      destinationStream,
    );

    app = fastify({ loggerInstance: logger, disableRequestLogging: true });

    // Register health routes (unaffected by CSRF)
    const mockLifecycle = {
      getState: () => 'READY',
      isReady: () => true,
      isShuttingDown: () => false,
      assertHealthy: () => {},
    } as unknown as Parameters<typeof registerHealthRoutes>[1]['lifecycle'];

    const mockRedis = {
      checkReadiness: async () => ({ ok: true }),
    } as unknown as Parameters<typeof registerHealthRoutes>[1]['redis'];

    const mockPostgres = {
      checkReadiness: async () => ({ ok: true }),
    } as unknown as Parameters<typeof registerHealthRoutes>[1]['postgres'];

    await registerHealthRoutes(app, {
      postgres: mockPostgres,
      redis: mockRedis,
      lifecycle: mockLifecycle,
    });

    // Register isolated test CSRF routes
    registerTestCsrfRoutes(app, {
      sessionService,
      allowedOrigin: ALLOWED_ORIGIN,
      onMutation: () => {
        mutationInvocationCount++;
      },
    });

    await app.listen({ host: '127.0.0.1', port: 0 });
    serverPort = (app.server.address() as net.AddressInfo).port;
  }, 60000);

  beforeEach(() => {
    mutationInvocationCount = 0;
    logEntries.length = 0;
  });

  afterAll(async () => {
    if (app) await app.close();
    if (appPool) await appPool.end();
    if (adminClient) await adminClient.end();
    if (db) await db.drop();
    if (cluster) await cluster.stop();
  }, 30000);

  // Helper to create session cookie string
  async function createValidSessionFixture() {
    const { secret, csrfToken, session } = await sessionService.createSession(ORG_A_ID, USER_A_ID);
    const cookieHeader = `__Host-session=${secret}`;
    return { secret, csrfToken, session, cookieHeader };
  }

  // Helper to send raw HTTP request bytes over a local TCP connection (CSRF-04)
  function sendRawHttpRequest(
    port: number,
    rawRequest: string,
  ): Promise<{ statusCode: number; headers: Record<string, string>; body: string }> {
    return new Promise((resolve, reject) => {
      const client = net.connect(port, '127.0.0.1', () => {
        client.write(rawRequest);
      });
      const timer = setTimeout(() => {
        client.destroy(new Error('Socket timeout waiting for HTTP response'));
      }, 5000);
      const chunks: Buffer[] = [];
      client.on('data', (chunk: Buffer | string) => {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      });
      client.on('end', () => {
        clearTimeout(timer);
        const response = Buffer.concat(chunks).toString('utf8');
        const [headerPart, ...bodyParts] = response.split('\r\n\r\n');
        const body = bodyParts.join('\r\n\r\n');
        const lines = headerPart?.split('\r\n') ?? [];
        const statusLine = lines[0] ?? '';
        const statusMatch = /HTTP\/1\.[01]\s+(\d{3})/.exec(statusLine);
        const statusCode = statusMatch ? parseInt(statusMatch[1] ?? '0', 10) : 0;
        const headers: Record<string, string> = {};
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i];
          if (!line) continue;
          const colonIdx = line.indexOf(':');
          if (colonIdx !== -1) {
            const key = line.slice(0, colonIdx).trim().toLowerCase();
            const val = line.slice(colonIdx + 1).trim();
            headers[key] = val;
          }
        }
        resolve({ statusCode, headers, body });
      });
      client.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  describe('Positive Test', () => {
    it('succeeds when request has valid session cookie, exact allowed Origin, and valid CSRF token', async () => {
      const { csrfToken, cookieHeader } = await createValidSessionFixture();

      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: cookieHeader,
          'x-csrf-token': csrfToken,
        },
        payload: { field: 'value' },
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ success: true, mutated: true });
      expect(mutationInvocationCount).toBe(1);
    });

    it('succeeds for PUT and DELETE methods with valid credentials and Origin', async () => {
      const { csrfToken, cookieHeader } = await createValidSessionFixture();

      const putRes = await app.inject({
        method: 'PUT',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: cookieHeader,
          'x-csrf-token': csrfToken,
        },
        payload: { updated: true },
      });
      expect(putRes.statusCode).toBe(200);
      expect(mutationInvocationCount).toBe(1);

      const delRes = await app.inject({
        method: 'DELETE',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: cookieHeader,
          'x-csrf-token': csrfToken,
        },
      });
      expect(delRes.statusCode).toBe(200);
      expect(mutationInvocationCount).toBe(2);
    });
  });

  describe('Negative Tests — Protected Handler Invocation MUST Remain Zero', () => {
    it('fails with 401 when session cookie is missing', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          'x-csrf-token': crypto.randomBytes(32).toString('base64url'),
        },
      });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Authentication required',
      });
      expect(mutationInvocationCount).toBe(0);
    });

    it('fails with 401 when session is revoked', async () => {
      const { secret, csrfToken, cookieHeader } = await createValidSessionFixture();
      await sessionService.revokeSession(secret);

      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: cookieHeader,
          'x-csrf-token': csrfToken,
        },
      });

      expect(response.statusCode).toBe(401);
      expect(mutationInvocationCount).toBe(0);
    });

    it('fails with 401 when session is idle expired', async () => {
      const { session, csrfToken, cookieHeader } = await createValidSessionFixture();

      await adminClient.query(
        `UPDATE public.web_sessions
        SET idle_expires_at = clock_timestamp() - interval '1 minute'
        WHERE session_id_hash = $1`,
        [session.sessionIdHash],
      );

      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: cookieHeader,
          'x-csrf-token': csrfToken,
        },
      });

      expect(response.statusCode).toBe(401);
      expect(mutationInvocationCount).toBe(0);
    });

    it('fails with 403 when X-CSRF-Token header is missing', async () => {
      const { cookieHeader } = await createValidSessionFixture();

      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: cookieHeader,
        },
      });

      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Invalid or missing CSRF token',
      });
      expect(mutationInvocationCount).toBe(0);
    });

    it('fails with 403 when X-CSRF-Token is forged or random', async () => {
      const { cookieHeader } = await createValidSessionFixture();
      const forgedToken = crypto.randomBytes(32).toString('base64url');

      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: cookieHeader,
          'x-csrf-token': forgedToken,
        },
      });

      expect(response.statusCode).toBe(403);
      expect(mutationInvocationCount).toBe(0);
    });

    it('fails with 403 when X-CSRF-Token belongs to a different session', async () => {
      const session1 = await createValidSessionFixture();
      const session2 = await createValidSessionFixture();

      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: session1.cookieHeader,
          'x-csrf-token': session2.csrfToken, // Token from session 2
        },
      });

      expect(response.statusCode).toBe(403);
      expect(mutationInvocationCount).toBe(0);
    });

    it('fails with 403 when Origin header is missing', async () => {
      const { csrfToken, cookieHeader } = await createValidSessionFixture();

      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          cookie: cookieHeader,
          'x-csrf-token': csrfToken,
        },
      });

      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Invalid or missing Origin',
      });
      expect(mutationInvocationCount).toBe(0);
    });

    it('fails with 403 when Origin is cross-site or wrong host', async () => {
      const { csrfToken, cookieHeader } = await createValidSessionFixture();

      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: 'https://evil-attacker.com',
          cookie: cookieHeader,
          'x-csrf-token': csrfToken,
        },
      });

      expect(response.statusCode).toBe(403);
      expect(mutationInvocationCount).toBe(0);
    });

    it('fails with 403 when Origin contains subdomain suffix attack', async () => {
      const { csrfToken, cookieHeader } = await createValidSessionFixture();

      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: 'https://app.switchyard.internal.attacker.com',
          cookie: cookieHeader,
          'x-csrf-token': csrfToken,
        },
      });

      expect(response.statusCode).toBe(403);
      expect(mutationInvocationCount).toBe(0);
    });

    it('fails with 403 when Origin is "null"', async () => {
      const { csrfToken, cookieHeader } = await createValidSessionFixture();

      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: 'null',
          cookie: cookieHeader,
          'x-csrf-token': csrfToken,
        },
      });

      expect(response.statusCode).toBe(403);
      expect(mutationInvocationCount).toBe(0);
    });

    it('fails with 403 when multiple Origin headers are provided', async () => {
      const { csrfToken, cookieHeader } = await createValidSessionFixture();

      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: `${ALLOWED_ORIGIN}, ${ALLOWED_ORIGIN}`,
          cookie: cookieHeader,
          'x-csrf-token': csrfToken,
        },
      });

      expect(response.statusCode).toBe(403);
      expect(mutationInvocationCount).toBe(0);
    });

    it('fails with 403 when CSRF token has invalid encoding or length', async () => {
      const { cookieHeader } = await createValidSessionFixture();

      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: cookieHeader,
          'x-csrf-token': 'too-short',
        },
      });

      expect(response.statusCode).toBe(403);
      expect(mutationInvocationCount).toBe(0);
    });
  });

  describe('Route Scope & Principal Separation', () => {
    it('leaves health routes unaffected by CSRF and Origin checks', async () => {
      const liveRes = await app.inject({ method: 'GET', url: '/health/live' });
      expect(liveRes.statusCode).toBe(200);

      const readyRes = await app.inject({ method: 'GET', url: '/health/ready' });
      expect(readyRes.statusCode).toBe(200);
    });

    it('rejects virtual API keys on browser mutation routes (cannot substitute for session cookie)', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          authorization: 'Bearer vk_live_12345678901234567890123456789012',
          'x-csrf-token': crypto.randomBytes(32).toString('base64url'),
        },
      });

      expect(response.statusCode).toBe(401);
      expect(mutationInvocationCount).toBe(0);
    });
  });

  describe('Token Reissuance Endpoint Behavior', () => {
    it('reissues fresh token with Cache-Control no-store when session and Origin are valid', async () => {
      const { csrfToken: oldToken, cookieHeader } = await createValidSessionFixture();

      const reissueRes = await app.inject({
        method: 'POST',
        url: '/test/auth/csrf/reissue',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: cookieHeader,
        },
      });

      expect(reissueRes.statusCode).toBe(200);
      expect(reissueRes.headers['cache-control']).toBe(
        'no-store, no-cache, must-revalidate, private',
      );
      expect(reissueRes.headers['pragma']).toBe('no-cache');

      const body = reissueRes.json() as { csrfToken: string };
      expect(body.csrfToken).toBeDefined();
      expect(body.csrfToken.length).toBe(43);
      expect(body.csrfToken).not.toBe(oldToken);

      // Now verify mutation with new token succeeds and old token fails
      const oldMutationRes = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: cookieHeader,
          'x-csrf-token': oldToken,
        },
      });
      expect(oldMutationRes.statusCode).toBe(403);

      const newMutationRes = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: cookieHeader,
          'x-csrf-token': body.csrfToken,
        },
      });
      expect(newMutationRes.statusCode).toBe(200);
    });

    it('rejects token reissuance if Origin is invalid or missing', async () => {
      const { cookieHeader } = await createValidSessionFixture();

      const resNoOrigin = await app.inject({
        method: 'POST',
        url: '/test/auth/csrf/reissue',
        headers: { cookie: cookieHeader },
      });
      expect(resNoOrigin.statusCode).toBe(403);

      const resBadOrigin = await app.inject({
        method: 'POST',
        url: '/test/auth/csrf/reissue',
        headers: {
          origin: 'https://evil.com',
          cookie: cookieHeader,
        },
      });
      expect(resBadOrigin.statusCode).toBe(403);
    });

    it('rejects token reissuance if session cookie is missing', async () => {
      const resNoCookie = await app.inject({
        method: 'POST',
        url: '/test/auth/csrf/reissue',
        headers: { origin: ALLOWED_ORIGIN },
      });
      expect(resNoCookie.statusCode).toBe(401);
    });
  });

  describe('Privacy, Observability & Secret Leakage Prevention', () => {
    it('ensures synthetic canary CSRF tokens and session secrets never appear in error responses or logs', async () => {
      const canarySecret = 'canary_session_secret_xyz12345678901234567';
      const canaryToken = 'canary_csrf_token_abc12345678901234567890';

      const response = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: `__Host-session=${canarySecret}`,
          'x-csrf-token': canaryToken,
        },
      });

      // Response body must not contain canary values
      const bodyStr = response.body;
      expect(bodyStr).not.toContain(canarySecret);
      expect(bodyStr).not.toContain(canaryToken);

      // Captured log entries must not contain canary values in plaintext
      const combinedLogs = logEntries.join('\n');
      expect(combinedLogs).not.toContain(canarySecret);
      expect(combinedLogs).not.toContain(canaryToken);
    });
  });

  describe('CSRF-02: Middleware Trusted Allowed-Origin Contract', () => {
    it('factory rejects invalid allowed-Origin configurations at construction time', () => {
      expect(() => createCsrfProtectionPreHandler({ sessionService, allowedOrigin: '' })).toThrow(
        CsrfError,
      );
      expect(() =>
        createCsrfProtectionPreHandler({ sessionService, allowedOrigin: '   ' }),
      ).toThrow(CsrfError);
      expect(() => createCsrfProtectionPreHandler({ sessionService, allowedOrigin: '*' })).toThrow(
        CsrfError,
      );
      expect(() =>
        createCsrfProtectionPreHandler({
          sessionService,
          allowedOrigin: 'https://app.switchyard.internal, https://evil.com',
        }),
      ).toThrow(CsrfError);
      expect(() =>
        createCsrfProtectionPreHandler({
          sessionService,
          allowedOrigin: 'https://user:pass@app.switchyard.internal',
        }),
      ).toThrow(CsrfError);
      expect(() =>
        createCsrfProtectionPreHandler({
          sessionService,
          allowedOrigin: 'https://app.switchyard.internal/path',
        }),
      ).toThrow(CsrfError);
      expect(() =>
        createCsrfProtectionPreHandler({
          sessionService,
          allowedOrigin: 'https://app.switchyard.internal?query=1',
        }),
      ).toThrow(CsrfError);
      expect(() =>
        createCsrfProtectionPreHandler({
          sessionService,
          allowedOrigin: 'https://app.switchyard.internal#frag',
        }),
      ).toThrow(CsrfError);
      expect(() =>
        createCsrfProtectionPreHandler({
          sessionService,
          allowedOrigin: 'https://app.switchyard.internal/',
        }),
      ).toThrow(CsrfError);
      expect(() =>
        createCsrfProtectionPreHandler({ sessionService, allowedOrigin: 'not-a-valid-url' }),
      ).toThrow(CsrfError);
      expect(() =>
        createCsrfProtectionPreHandler({
          sessionService,
          allowedOrigin: 'ftp://app.switchyard.internal',
        }),
      ).toThrow(CsrfError);
    });

    it('factory accepts valid canonical production and development origins', () => {
      expect(() =>
        createCsrfProtectionPreHandler({
          sessionService,
          allowedOrigin: 'https://app.switchyard.internal',
        }),
      ).not.toThrow();
      expect(() =>
        createCsrfProtectionPreHandler({
          sessionService,
          allowedOrigin: 'http://127.0.0.1:3000',
        }),
      ).not.toThrow();
    });

    it('does not trust request Host or forwarding headers to determine the allowed origin', async () => {
      const { csrfToken, cookieHeader } = await createValidSessionFixture();

      // Attacker sends evil Host and X-Forwarded-Host matching attacker Origin
      const res = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          host: 'evil.com',
          'x-forwarded-host': 'evil.com',
          'x-forwarded-proto': 'https',
          origin: 'https://evil.com',
          cookie: cookieHeader,
          'x-csrf-token': csrfToken,
        },
      });

      expect(res.statusCode).toBe(403);
      expect(mutationInvocationCount).toBe(0);
    });
  });

  describe('CSRF-03: Production Route & Module Boundary Verification', () => {
    it('proves buildApp() does not register any test routes', async () => {
      const mockPg = { checkReadiness: async () => ({ ok: true }) } as unknown as Parameters<
        typeof buildApp
      >[0]['postgres'];
      const mockRed = { checkReadiness: async () => ({ ok: true }) } as unknown as Parameters<
        typeof buildApp
      >[0]['redis'];
      const mockLife = {
        getState: () => 'READY',
        isReady: () => true,
        isShuttingDown: () => false,
        assertHealthy: () => {},
      } as unknown as Parameters<typeof buildApp>[0]['lifecycle'];

      const nullLogger = pino({ enabled: false });
      const prodApp = await buildApp({
        postgres: mockPg,
        redis: mockRed,
        lifecycle: mockLife,
        logger: nullLogger,
      });

      try {
        // Assert test mutation route is 404 Not Found on real buildApp() instance
        const mutationRes = await prodApp.inject({
          method: 'POST',
          url: '/test/protected/mutation',
        });
        expect(mutationRes.statusCode).toBe(404);

        // Assert test reissue route is 404 Not Found
        const reissueRes = await prodApp.inject({
          method: 'POST',
          url: '/test/auth/csrf/reissue',
        });
        expect(reissueRes.statusCode).toBe(404);
      } finally {
        await prodApp.close();
      }
    });

    it('proves registerTestCsrfRoutes is not exported through the auth barrel or csrf module', () => {
      expect('registerTestCsrfRoutes' in authBarrel).toBe(false);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect((authBarrel as any).registerTestCsrfRoutes).toBeUndefined();
    });
  });

  describe('CSRF-04: Genuine Duplicate Raw HTTP Header Verification', () => {
    it('rejects duplicate raw Origin headers (identical valid origins)', async () => {
      const { csrfToken, cookieHeader } = await createValidSessionFixture();
      const raw =
        'POST /test/protected/mutation HTTP/1.1\r\n' +
        `Host: 127.0.0.1:${serverPort}\r\n` +
        'Connection: close\r\n' +
        `Cookie: ${cookieHeader}\r\n` +
        `Origin: ${ALLOWED_ORIGIN}\r\n` +
        `Origin: ${ALLOWED_ORIGIN}\r\n` +
        `X-CSRF-Token: ${csrfToken}\r\n` +
        'Content-Length: 0\r\n' +
        '\r\n';

      const res = await sendRawHttpRequest(serverPort, raw);
      expect(res.statusCode).toBe(403);
      expect(res.body).toContain('Invalid or missing Origin');
      expect(mutationInvocationCount).toBe(0);
    });

    it('rejects duplicate raw Origin headers (valid origin + evil origin)', async () => {
      const { csrfToken, cookieHeader } = await createValidSessionFixture();
      const raw =
        'POST /test/protected/mutation HTTP/1.1\r\n' +
        `Host: 127.0.0.1:${serverPort}\r\n` +
        'Connection: close\r\n' +
        `Cookie: ${cookieHeader}\r\n` +
        `Origin: ${ALLOWED_ORIGIN}\r\n` +
        'Origin: https://evil.com\r\n' +
        `X-CSRF-Token: ${csrfToken}\r\n` +
        'Content-Length: 0\r\n' +
        '\r\n';

      const res = await sendRawHttpRequest(serverPort, raw);
      expect(res.statusCode).toBe(403);
      expect(res.body).toContain('Invalid or missing Origin');
      expect(mutationInvocationCount).toBe(0);
    });

    it('rejects duplicate raw X-CSRF-Token headers (identical valid tokens)', async () => {
      const { csrfToken, cookieHeader } = await createValidSessionFixture();
      const raw =
        'POST /test/protected/mutation HTTP/1.1\r\n' +
        `Host: 127.0.0.1:${serverPort}\r\n` +
        'Connection: close\r\n' +
        `Cookie: ${cookieHeader}\r\n` +
        `Origin: ${ALLOWED_ORIGIN}\r\n` +
        `X-CSRF-Token: ${csrfToken}\r\n` +
        `X-CSRF-Token: ${csrfToken}\r\n` +
        'Content-Length: 0\r\n' +
        '\r\n';

      const res = await sendRawHttpRequest(serverPort, raw);
      expect(res.statusCode).toBe(403);
      expect(res.body).toContain('Invalid or missing CSRF token');
      expect(mutationInvocationCount).toBe(0);
    });

    it('rejects duplicate raw X-CSRF-Token headers (valid token + evil token)', async () => {
      const { csrfToken, cookieHeader } = await createValidSessionFixture();
      const raw =
        'POST /test/protected/mutation HTTP/1.1\r\n' +
        `Host: 127.0.0.1:${serverPort}\r\n` +
        'Connection: close\r\n' +
        `Cookie: ${cookieHeader}\r\n` +
        `Origin: ${ALLOWED_ORIGIN}\r\n` +
        `X-CSRF-Token: ${csrfToken}\r\n` +
        'X-CSRF-Token: evil_forged_csrf_token_value_abc\r\n' +
        'Content-Length: 0\r\n' +
        '\r\n';

      const res = await sendRawHttpRequest(serverPort, raw);
      expect(res.statusCode).toBe(403);
      expect(res.body).toContain('Invalid or missing CSRF token');
      expect(mutationInvocationCount).toBe(0);
    });

    it('allows valid single raw Origin and single raw X-CSRF-Token over HTTP stream', async () => {
      const { csrfToken, cookieHeader } = await createValidSessionFixture();
      const raw =
        'POST /test/protected/mutation HTTP/1.1\r\n' +
        `Host: 127.0.0.1:${serverPort}\r\n` +
        'Connection: close\r\n' +
        `Cookie: ${cookieHeader}\r\n` +
        `Origin: ${ALLOWED_ORIGIN}\r\n` +
        `X-CSRF-Token: ${csrfToken}\r\n` +
        'Content-Length: 0\r\n' +
        '\r\n';

      const res = await sendRawHttpRequest(serverPort, raw);
      expect(res.statusCode).toBe(200);
      expect(res.body).toContain('"mutated":true');
      expect(mutationInvocationCount).toBe(1);
    });

    it('confirms combining or normalizing duplicate headers cannot bypass authorization', async () => {
      const { csrfToken, cookieHeader } = await createValidSessionFixture();

      // Comma-joined origin injected
      const commaOriginRes = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: `${ALLOWED_ORIGIN}, https://evil.com`,
          cookie: cookieHeader,
          'x-csrf-token': csrfToken,
        },
      });
      expect(commaOriginRes.statusCode).toBe(403);

      // Comma-joined CSRF token injected
      const commaCsrfRes = await app.inject({
        method: 'POST',
        url: '/test/protected/mutation',
        headers: {
          origin: ALLOWED_ORIGIN,
          cookie: cookieHeader,
          'x-csrf-token': `${csrfToken}, ${csrfToken}`,
        },
      });
      expect(commaCsrfRes.statusCode).toBe(403);
      expect(mutationInvocationCount).toBe(0);
    });
  });
});
