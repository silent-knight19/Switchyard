import fastify from 'fastify';
import type pg from 'pg';
import pino from 'pino';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { registerProviderKeyRoutes } from './provider-keys.js';
import {
  ProviderKeyManagementError,
  ProviderKeyManagementService,
  type ListProviderKeysResult,
  type ProviderKeyMetadataDto,
} from '../auth/provider-key-management.js';
import { installAuthorizationBoundary } from '../auth/authorization.js';
import type { SessionService } from '../auth/session.js';
import type { SessionValidationResult } from '../auth/types.js';

const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
const KEY_A_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USER_A_ADMIN_ID = 'user-admin-1';
const USER_A_MEMBER_ID = 'user-member-1';
const TRUSTED_ORIGIN = 'https://app.switchyard.internal';

describe('ProviderKeyRoutes — HTTP Contract, Validation, RBAC & Headers', () => {
  let mockService: ProviderKeyManagementService;
  let mockSessionService: Partial<SessionService>;
  let sessionValidation: SessionValidationResult;
  let app: ReturnType<typeof fastify>;

  beforeEach(async () => {
    mockService = {
      createKey: vi.fn(),
      replaceKey: vi.fn(),
      listKeys: vi.fn(),
      disableKey: vi.fn(),
    } as unknown as ProviderKeyManagementService;

    sessionValidation = {
      valid: true,
      user: {
        id: USER_A_ADMIN_ID,
        orgId: ORG_A_ID,
        emailNormalized: 'admin@alpha.com',
        role: 'admin',
      },
      session: {
        sessionIdHash: Buffer.alloc(32, 1),
        userId: USER_A_ADMIN_ID,
        orgId: ORG_A_ID,
        csrfTokenHash: Buffer.alloc(32, 2),
        createdAt: new Date(),
        lastSeenAt: new Date(),
        idleExpiresAt: new Date(Date.now() + 100000),
        absoluteExpiresAt: new Date(Date.now() + 100000),
        revokedAt: null,
      },
    };

    mockSessionService = {
      getCookieName: () => '__Host-sw_session',
      extractSessionSecretFromCookieHeader: vi.fn((cookieHeader?: string): string | null => {
        if (!cookieHeader || !cookieHeader.includes('__Host-sw_session=')) return null;
        const match = /__Host-sw_session=([^;]+)/.exec(cookieHeader);
        return match ? match[1]! : null;
      }),
      resolveAndValidateSession: vi.fn(async () => sessionValidation),
      resolveAndValidateSessionWithCsrf: vi.fn(async () => sessionValidation),
    };

    app = fastify();

    installAuthorizationBoundary(app, {
      sessionService: mockSessionService as SessionService,
      trustedOrigin: TRUSTED_ORIGIN,
    });

    await registerProviderKeyRoutes(app, {
      pool: {} as pg.Pool,
      service: mockService,
    });
  });

  const authHeaders = {
    cookie: '__Host-sw_session=mock-valid-session-secret',
    origin: TRUSTED_ORIGIN,
    'x-csrf-token': 'mock-valid-csrf-token',
  };

  describe('Authorization and RBAC gates', () => {
    it('rejects unauthenticated requests with 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/provider-keys',
      });
      expect(res.statusCode).toBe(401);
      expect(JSON.parse(res.body).error).toBe('Unauthorized');
    });

    it('rejects member role requests with 403 Forbidden', async () => {
      sessionValidation = {
        valid: true,
        user: {
          id: USER_A_MEMBER_ID,
          orgId: ORG_A_ID,
          emailNormalized: 'member@alpha.com',
          role: 'member',
        },
        session: {
          sessionIdHash: Buffer.alloc(32, 1),
          userId: USER_A_MEMBER_ID,
          orgId: ORG_A_ID,
          csrfTokenHash: Buffer.alloc(32, 2),
          createdAt: new Date(),
          lastSeenAt: new Date(),
          idleExpiresAt: new Date(Date.now() + 100000),
          absoluteExpiresAt: new Date(Date.now() + 100000),
          revokedAt: null,
        },
      };

      const res = await app.inject({
        method: 'GET',
        url: '/api/provider-keys',
        headers: authHeaders,
      });
      expect(res.statusCode).toBe(403);
      expect(JSON.parse(res.body).error).toBe('Forbidden');
    });

    it('rejects state-changing requests without CSRF token with 403 Forbidden', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/provider-keys',
        headers: {
          cookie: authHeaders.cookie,
          origin: TRUSTED_ORIGIN,
          // x-csrf-token omitted
        },
        payload: {
          provider: 'openai',
          label: 'Test',
          credential: 'synthetic-credential',
        },
      });
      expect(res.statusCode).toBe(403);
    });

    it('rejects state-changing requests from untrusted origin with 403 Forbidden', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/provider-keys',
        headers: {
          cookie: authHeaders.cookie,
          origin: 'https://evil.attacker.com',
          'x-csrf-token': 'mock-valid-csrf-token',
        },
        payload: {
          provider: 'openai',
          label: 'Test',
          credential: 'synthetic-credential',
        },
      });
      expect(res.statusCode).toBe(403);
    });

    it('rejects forged or mismatched CSRF tokens with 403 Forbidden', async () => {
      (
        mockSessionService.resolveAndValidateSessionWithCsrf as ReturnType<typeof vi.fn>
      ).mockResolvedValueOnce({
        valid: false,
        reason: 'CSRF_TOKEN_MISMATCH',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/api/provider-keys',
        headers: {
          cookie: authHeaders.cookie,
          origin: TRUSTED_ORIGIN,
          'x-csrf-token': 'forged-csrf-token',
        },
        payload: {
          provider: 'openai',
          label: 'Test',
          credential: 'synthetic-credential',
        },
      });
      expect(res.statusCode).toBe(403);
      expect(JSON.parse(res.body).message).toBe('Invalid or missing CSRF token');
    });

    it('rejects virtual key Bearer authentication on browser management routes', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/provider-keys',
        headers: {
          authorization: 'Bearer sw_vk_testkey1234567890abcdef',
        },
      });
      // Virtual key token on browser-only route without session cookie fails session extraction -> 401
      expect(res.statusCode).toBe(401);
    });
  });

  describe('POST /api/provider-keys', () => {
    it('creates a provider key and returns 201 with safe metadata', async () => {
      const createdDto: ProviderKeyMetadataDto = {
        id: KEY_A_ID,
        provider: 'openai',
        label: 'Production OpenAI',
        keyHint: '****5678',
        isActive: true,
        createdAt: '2026-11-22T00:00:00.000Z',
      };
      (mockService.createKey as ReturnType<typeof vi.fn>).mockResolvedValue(createdDto);

      const res = await app.inject({
        method: 'POST',
        url: '/api/provider-keys',
        headers: authHeaders,
        payload: {
          provider: 'openai',
          label: 'Production OpenAI',
          credential: 'synthetic-test-credential-12345678',
        },
      });

      expect(res.statusCode).toBe(201);
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.headers['pragma']).toBe('no-cache');
      const body = JSON.parse(res.body);
      expect(body).toEqual(createdDto);
      expect(body.credential).toBeUndefined();
      expect(body.ciphertext).toBeUndefined();
      expect(body.iv).toBeUndefined();
      expect(body.authTag).toBeUndefined();

      expect(mockService.createKey).toHaveBeenCalledWith(ORG_A_ID, {
        provider: 'openai',
        label: 'Production OpenAI',
        credential: 'synthetic-test-credential-12345678',
      });
    });

    it('rejects query parameters with 400 Bad Request', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/provider-keys?unexpected=true',
        headers: authHeaders,
        payload: {
          provider: 'openai',
          label: 'Test',
          credential: 'synthetic-test-credential',
        },
      });
      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).message).toContain('Query parameters are not permitted');
    });

    it('rejects additional unexpected fields in body with 400 Bad Request', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/provider-keys',
        headers: authHeaders,
        payload: {
          provider: 'openai',
          label: 'Test',
          credential: 'synthetic-test-credential',
          extraProperty: 'disallowed',
        },
      });
      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).message).toContain('only "provider", "label", and "credential"');
    });

    it('rejects unsupported provider with 400 Bad Request when service rejects it', async () => {
      (mockService.createKey as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError(
          'INVALID_INPUT',
          'Unsupported provider: only "openai" is currently supported',
        ),
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/provider-keys',
        headers: authHeaders,
        payload: {
          provider: 'anthropic',
          label: 'Test Anthropic',
          credential: 'synthetic-credential',
        },
      });
      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).message).toBe(
        'Unsupported provider: only "openai" is currently supported',
      );
    });

    it('rejects unsupported provider without echoing untrusted provider value (PVAULT-05)', async () => {
      (mockService.createKey as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError(
          'INVALID_INPUT',
          'Unsupported provider: only "openai" is currently supported',
        ),
      );

      const canaryProvider = 'sk-synthetic-secret-provider-attempt-12345';
      const res = await app.inject({
        method: 'POST',
        url: '/api/provider-keys',
        headers: authHeaders,
        payload: {
          provider: canaryProvider,
          label: 'Test Secret Provider',
          credential: 'synthetic-credential',
        },
      });
      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).message).toBe(
        'Unsupported provider: only "openai" is currently supported',
      );
      expect(res.body).not.toContain(canaryProvider);
    });

    it('never echoes raw credential in validation error responses', async () => {
      (mockService.createKey as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError(
          'INVALID_INPUT',
          'Invalid credential: credential cannot be empty',
        ),
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/provider-keys',
        headers: authHeaders,
        payload: {
          provider: 'openai',
          label: 'Test',
          credential: '',
        },
      });
      expect(res.statusCode).toBe(400);
      expect(res.body).not.toContain('canary');
    });

    it('returns 503 when provider credential vault is unavailable', async () => {
      (mockService.createKey as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError(
          'VAULT_UNAVAILABLE',
          'Provider credential vault is unavailable',
        ),
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/provider-keys',
        headers: authHeaders,
        payload: {
          provider: 'openai',
          label: 'Test',
          credential: 'synthetic-test-credential',
        },
      });

      expect(res.statusCode).toBe(503);
      expect(JSON.parse(res.body).message).toBe('Provider credential vault is unavailable');
    });
  });

  describe('GET /api/provider-keys', () => {
    it('returns 200 with safe provider keys list and pagination cursor', async () => {
      const listResult: ListProviderKeysResult = {
        items: [
          {
            id: KEY_A_ID,
            provider: 'openai',
            label: 'Test Key',
            keyHint: '****1234',
            isActive: true,
            createdAt: '2026-11-22T00:00:00.000Z',
          },
        ],
        nextCursor: null,
      };
      (mockService.listKeys as ReturnType<typeof vi.fn>).mockResolvedValue(listResult);

      const res = await app.inject({
        method: 'GET',
        url: '/api/provider-keys',
        headers: authHeaders,
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['cache-control']).toBe('no-store');
      expect(JSON.parse(res.body)).toEqual(listResult);
      expect(mockService.listKeys).toHaveBeenCalledWith(ORG_A_ID, {});
    });

    it('passes validated limit and cursor to service', async () => {
      (mockService.listKeys as ReturnType<typeof vi.fn>).mockResolvedValue({
        items: [],
        nextCursor: null,
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/provider-keys?limit=50&cursor=eyJjcmVhdGVkQXQiOiIyMDI2LTExLTIyVDAwOjAwOjAwLjAwMDAwMFoiLCJpZCI6ImFhYWFhYWFhLWFhYWEtNGFhYS04YWFhLWFhYWFhYWFhYWFhYSJ9',
        headers: authHeaders,
      });

      expect(res.statusCode).toBe(200);
      expect(mockService.listKeys).toHaveBeenCalledWith(ORG_A_ID, {
        limit: 50,
        cursor:
          'eyJjcmVhdGVkQXQiOiIyMDI2LTExLTIyVDAwOjAwOjAwLjAwMDAwMFoiLCJpZCI6ImFhYWFhYWFhLWFhYWEtNGFhYS04YWFhLWFhYWFhYWFhYWFhYSJ9',
      });
    });

    it('rejects unexpected query parameters with 400 Bad Request', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/provider-keys?forbidden=true',
        headers: authHeaders,
      });
      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).message).toContain('Unexpected query parameter');
    });

    it('rejects invalid limit values with 400 Bad Request', async () => {
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/provider-keys?limit=0',
        headers: authHeaders,
      });
      expect(res1.statusCode).toBe(400);

      const res2 = await app.inject({
        method: 'GET',
        url: '/api/provider-keys?limit=101',
        headers: authHeaders,
      });
      expect(res2.statusCode).toBe(400);

      const res3 = await app.inject({
        method: 'GET',
        url: '/api/provider-keys?limit=not-a-number',
        headers: authHeaders,
      });
      expect(res3.statusCode).toBe(400);
    });
  });

  describe('PUT /api/provider-keys/:id', () => {
    it('atomically replaces credential and returns 200 with updated metadata', async () => {
      const updatedDto: ProviderKeyMetadataDto = {
        id: KEY_A_ID,
        provider: 'openai',
        label: 'Updated Label',
        keyHint: '****9999',
        isActive: true,
        createdAt: '2026-11-22T00:00:00.000Z',
      };
      (mockService.replaceKey as ReturnType<typeof vi.fn>).mockResolvedValue(updatedDto);

      const res = await app.inject({
        method: 'PUT',
        url: `/api/provider-keys/${KEY_A_ID}`,
        headers: authHeaders,
        payload: {
          label: 'Updated Label',
          credential: 'replacement-credential-9999',
        },
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['cache-control']).toBe('no-store');
      expect(JSON.parse(res.body)).toEqual(updatedDto);
      expect(mockService.replaceKey).toHaveBeenCalledWith(ORG_A_ID, KEY_A_ID, {
        label: 'Updated Label',
        credential: 'replacement-credential-9999',
      });
    });

    it('rejects invalid UUID in route params with 400 Bad Request', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: '/api/provider-keys/not-a-valid-uuid',
        headers: authHeaders,
        payload: {
          label: 'Updated',
          credential: 'new-credential',
        },
      });
      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).message).toContain('Invalid key ID');
    });

    it('returns 404 when key is not found', async () => {
      (mockService.replaceKey as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError('KEY_NOT_FOUND', 'Provider key not found'),
      );

      const res = await app.inject({
        method: 'PUT',
        url: `/api/provider-keys/${KEY_A_ID}`,
        headers: authHeaders,
        payload: {
          label: 'Updated',
          credential: 'new-credential',
        },
      });
      expect(res.statusCode).toBe(404);
      expect(JSON.parse(res.body).message).toBe('Provider key not found');
    });

    it('returns 409 Conflict when key is disabled', async () => {
      (mockService.replaceKey as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError(
          'KEY_DISABLED',
          'Cannot replace credential of a disabled provider key',
        ),
      );

      const res = await app.inject({
        method: 'PUT',
        url: `/api/provider-keys/${KEY_A_ID}`,
        headers: authHeaders,
        payload: {
          label: 'Updated',
          credential: 'new-credential',
        },
      });
      expect(res.statusCode).toBe(409);
      expect(JSON.parse(res.body).message).toContain('disabled provider key');
    });
  });

  describe('DELETE /api/provider-keys/:id', () => {
    it('disables key and returns 204 No Content', async () => {
      (mockService.disableKey as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/provider-keys/${KEY_A_ID}`,
        headers: authHeaders,
      });

      expect(res.statusCode).toBe(204);
      expect(res.body).toBe('');
      expect(res.headers['cache-control']).toBe('no-store');
      expect(mockService.disableKey).toHaveBeenCalledWith(ORG_A_ID, KEY_A_ID);
    });

    it('rejects invalid UUID parameter with 400 Bad Request', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/api/provider-keys/not-a-valid-uuid',
        headers: authHeaders,
      });
      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).message).toContain('Invalid key ID');
    });

    it('returns 404 when key is not found', async () => {
      (mockService.disableKey as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError('KEY_NOT_FOUND', 'Provider key not found'),
      );

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/provider-keys/${KEY_A_ID}`,
        headers: authHeaders,
      });
      expect(res.statusCode).toBe(404);
    });
  });

  describe('Consistent KEK Gating Across All Operations (PVAULT-01)', () => {
    it('returns 503 on POST when vault is unavailable', async () => {
      (mockService.createKey as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError(
          'VAULT_UNAVAILABLE',
          'Provider credential vault is unavailable',
        ),
      );
      const res = await app.inject({
        method: 'POST',
        url: '/api/provider-keys',
        headers: authHeaders,
        payload: {
          provider: 'openai',
          label: 'Test Key',
          credential: 'sk-test-valid-credential-123',
        },
      });
      expect(res.statusCode).toBe(503);
      expect(JSON.parse(res.body).message).toBe('Provider credential vault is unavailable');
    });

    it('returns 503 on PUT when vault is unavailable', async () => {
      (mockService.replaceKey as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError(
          'VAULT_UNAVAILABLE',
          'Provider credential vault is unavailable',
        ),
      );
      const res = await app.inject({
        method: 'PUT',
        url: `/api/provider-keys/${KEY_A_ID}`,
        headers: authHeaders,
        payload: {
          label: 'Test Replacement',
          credential: 'sk-test-valid-credential-123',
        },
      });
      expect(res.statusCode).toBe(503);
      expect(JSON.parse(res.body).message).toBe('Provider credential vault is unavailable');
    });

    it('returns 503 on GET when vault is unavailable', async () => {
      (mockService.listKeys as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError(
          'VAULT_UNAVAILABLE',
          'Provider credential vault is unavailable',
        ),
      );
      const res = await app.inject({
        method: 'GET',
        url: '/api/provider-keys',
        headers: authHeaders,
      });
      expect(res.statusCode).toBe(503);
      expect(JSON.parse(res.body).message).toBe('Provider credential vault is unavailable');
    });

    it('returns 503 on DELETE when vault is unavailable', async () => {
      (mockService.disableKey as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError(
          'VAULT_UNAVAILABLE',
          'Provider credential vault is unavailable',
        ),
      );
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/provider-keys/${KEY_A_ID}`,
        headers: authHeaders,
      });
      expect(res.statusCode).toBe(503);
      expect(JSON.parse(res.body).message).toBe('Provider credential vault is unavailable');
    });

    it('denies anonymous callers with 401 rather than disclosing vault configuration status', async () => {
      (mockService.listKeys as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError(
          'VAULT_UNAVAILABLE',
          'Provider credential vault is unavailable',
        ),
      );
      const res = await app.inject({
        method: 'GET',
        url: '/api/provider-keys',
      });
      expect(res.statusCode).toBe(401);
      expect(JSON.parse(res.body).error).toBe('Unauthorized');
      expect(res.body).not.toContain('vault');
    });

    it('denies member role callers with 403 rather than disclosing vault configuration status', async () => {
      sessionValidation = {
        valid: true,
        user: {
          id: USER_A_MEMBER_ID,
          orgId: ORG_A_ID,
          emailNormalized: 'member@alpha.com',
          role: 'member',
        },
        session: {
          ...sessionValidation.session!,
          userId: USER_A_MEMBER_ID,
        },
      };

      (mockService.listKeys as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError(
          'VAULT_UNAVAILABLE',
          'Provider credential vault is unavailable',
        ),
      );
      const res = await app.inject({
        method: 'GET',
        url: '/api/provider-keys',
        headers: authHeaders,
      });
      expect(res.statusCode).toBe(403);
      expect(JSON.parse(res.body).error).toBe('Forbidden');
      expect(res.body).not.toContain('vault');
    });
  });

  describe('Untrusted Value Reflection Prevention (PVAULT-05)', () => {
    it('does not echo untrusted path parameter in error response', async () => {
      const canaryId = 'canary-secret-token-malformed-id-12345';
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/provider-keys/${canaryId}`,
        headers: authHeaders,
      });
      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).message).toBe('Invalid key ID: malformed UUID');
      expect(res.body).not.toContain(canaryId);
    });
  });

  describe('Real Request / Log Canary Privacy Probe (PVAULT-04 Part C)', () => {
    it('proves synthetic canary credentials never appear in application logs or HTTP responses across success and failure', async () => {
      const capturedLogLines: string[] = [];
      const testLogger = pino(
        {
          level: 'trace',
          redact: {
            paths: ['credential', 'credentials', 'password', 'token', 'secret', '*.credential'],
            censor: '[REDACTED]',
          },
        },
        {
          write: (chunk: string) => {
            capturedLogLines.push(chunk);
          },
        },
      );

      const probeApp = fastify({ loggerInstance: testLogger });
      installAuthorizationBoundary(probeApp, {
        sessionService: mockSessionService as SessionService,
        trustedOrigin: TRUSTED_ORIGIN,
      });

      const probeMockService = {
        createKey: vi.fn(),
        replaceKey: vi.fn(),
        listKeys: vi.fn(),
        disableKey: vi.fn(),
      } as unknown as ProviderKeyManagementService;

      await registerProviderKeyRoutes(probeApp, {
        pool: {} as pg.Pool,
        service: probeMockService,
      });

      const canarySuccess = 'sk-synthetic-live-http-canary-success-998877';
      const canaryFailure = 'sk-synthetic-live-http-canary-failure-112233';

      (probeMockService.createKey as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: KEY_A_ID,
        provider: 'openai',
        label: 'Canary Probe Key',
        keyHint: '****8877',
        isActive: true,
        createdAt: '2026-11-22T10:00:00.000000Z',
      });

      // 1. Controlled successful operation
      const successRes = await probeApp.inject({
        method: 'POST',
        url: '/api/provider-keys',
        headers: authHeaders,
        payload: {
          provider: 'openai',
          label: 'Canary Probe Key',
          credential: canarySuccess,
        },
      });

      expect(successRes.statusCode).toBe(201);
      expect(successRes.body).not.toContain(canarySuccess);

      // 2. Controlled failure operation (service failure)
      (probeMockService.createKey as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError('DATABASE_ERROR', 'Simulated database failure'),
      );

      const failureRes = await probeApp.inject({
        method: 'POST',
        url: '/api/provider-keys',
        headers: authHeaders,
        payload: {
          provider: 'openai',
          label: 'Failing Canary Key',
          credential: canaryFailure,
        },
      });

      expect(failureRes.statusCode).toBe(503);
      expect(failureRes.body).not.toContain(canaryFailure);

      // 3. Verify neither canary appears anywhere in captured application logs
      for (const logLine of capturedLogLines) {
        expect(logLine).not.toContain(canarySuccess);
        expect(logLine).not.toContain(canaryFailure);
      }
    });
  });

  describe('Safe Error Response Coverage (PVAULT-04 Part D)', () => {
    it('covers safe 400 Invalid Input responses with Cache-Control: no-store', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/provider-keys',
        headers: authHeaders,
        payload: { invalid: 'payload' },
      });
      expect(res.statusCode).toBe(400);
      expect(res.headers['cache-control']).toBe('no-store');
      const body = JSON.parse(res.body);
      expect(body.statusCode).toBe(400);
      expect(body.error).toBe('Bad Request');
    });

    it('covers safe 403 Forbidden responses with Cache-Control: no-store', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/provider-keys',
        headers: {
          ...authHeaders,
          origin: 'https://malicious.origin.test',
        },
        payload: {
          provider: 'openai',
          label: 'Test',
          credential: 'sk-test-valid',
        },
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.statusCode).toBe(403);
      expect(body.error).toBe('Forbidden');
    });

    it('covers safe 404 Not Found responses with Cache-Control: no-store', async () => {
      (mockService.replaceKey as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError('KEY_NOT_FOUND', 'Provider key not found'),
      );
      const res = await app.inject({
        method: 'PUT',
        url: `/api/provider-keys/${KEY_A_ID}`,
        headers: authHeaders,
        payload: {
          label: 'Updated',
          credential: 'sk-test-valid',
        },
      });
      expect(res.statusCode).toBe(404);
      expect(res.headers['cache-control']).toBe('no-store');
      const body = JSON.parse(res.body);
      expect(body.statusCode).toBe(404);
      expect(body.error).toBe('Not Found');
      expect(body.message).toBe('Provider key not found');
    });

    it('covers safe 409 Conflict responses with Cache-Control: no-store', async () => {
      (mockService.replaceKey as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError(
          'KEY_DISABLED',
          'Cannot replace credential of a disabled provider key',
        ),
      );
      const res = await app.inject({
        method: 'PUT',
        url: `/api/provider-keys/${KEY_A_ID}`,
        headers: authHeaders,
        payload: {
          label: 'Updated',
          credential: 'sk-test-valid',
        },
      });
      expect(res.statusCode).toBe(409);
      expect(res.headers['cache-control']).toBe('no-store');
      const body = JSON.parse(res.body);
      expect(body.statusCode).toBe(409);
      expect(body.error).toBe('Conflict');
    });

    it('covers safe 503 Service Unavailable responses with Cache-Control: no-store', async () => {
      (mockService.listKeys as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ProviderKeyManagementError(
          'VAULT_UNAVAILABLE',
          'Provider credential vault is unavailable',
        ),
      );
      const res = await app.inject({
        method: 'GET',
        url: '/api/provider-keys',
        headers: authHeaders,
      });
      expect(res.statusCode).toBe(503);
      expect(res.headers['cache-control']).toBe('no-store');
      const body = JSON.parse(res.body);
      expect(body.statusCode).toBe(503);
      expect(body.error).toBe('Service Unavailable');
      expect(body.message).toBe('Provider credential vault is unavailable');
    });
  });
});
