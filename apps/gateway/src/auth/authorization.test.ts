import fastify, { type FastifyInstance } from 'fastify';
import { describe, expect, it } from 'vitest';
import {
  type AuthorizedRouteOptions,
  type RouteAuthorizationPolicy,
  type VirtualKeyAuthenticator,
  type VirtualKeyVerificationResult,
  AuthorizationError,
  installAuthorizationBoundary,
  registerAuthorizedRoute,
  validateRouteAuthorizationPolicy,
} from './authorization.js';
import type { SessionService } from './session.js';

describe('SW-1.5.4: Route Authorization Policy & Registration Enforcement', () => {
  const TRUSTED_ORIGIN = 'https://app.switchyard.internal';

  // Mock SessionService with required interface methods for boundary installation
  function createMockSessionService(): SessionService {
    return {
      extractSessionSecretFromCookieHeader: () => null,
      resolveAndValidateSession: async () => ({ valid: false, reason: 'SESSION_NOT_FOUND' }),
      resolveAndValidateSessionWithCsrf: async () => ({
        valid: false,
        reason: 'SESSION_NOT_FOUND',
      }),
    } as unknown as SessionService;
  }

  describe('1. validateRouteAuthorizationPolicy unit tests (Section 12)', () => {
    it('1. accepts valid anonymous declaration', () => {
      const policy: RouteAuthorizationPolicy = { principal: 'anonymous' };
      const res = validateRouteAuthorizationPolicy(policy);
      expect(res).toEqual({ principal: 'anonymous' });
    });

    it('2. accepts valid browser/member declaration', () => {
      const policy: RouteAuthorizationPolicy = { principal: 'browser', minRole: 'member' };
      const res = validateRouteAuthorizationPolicy(policy);
      expect(res).toEqual({ principal: 'browser', minRole: 'member' });
    });

    it('3. accepts valid browser/admin declaration', () => {
      const policy: RouteAuthorizationPolicy = { principal: 'browser', minRole: 'admin' };
      const res = validateRouteAuthorizationPolicy(policy);
      expect(res).toEqual({ principal: 'browser', minRole: 'admin' });
    });

    it('4. accepts valid virtual-key declaration', () => {
      const policy: RouteAuthorizationPolicy = { principal: 'virtual_key' };
      const res = validateRouteAuthorizationPolicy(policy);
      expect(res).toEqual({ principal: 'virtual_key' });
    });

    it('5. rejects missing (undefined) declaration with AUTHZ_ROUTE_POLICY_INVALID', () => {
      expect(() => validateRouteAuthorizationPolicy(undefined)).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('6. rejects null declaration with AUTHZ_ROUTE_POLICY_INVALID', () => {
      expect(() => validateRouteAuthorizationPolicy(null)).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('7. rejects empty object declaration with AUTHZ_ROUTE_POLICY_INVALID', () => {
      expect(() => validateRouteAuthorizationPolicy({})).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('8. rejects unknown principal types (superadmin, root, worker, service)', () => {
      const invalidPrincipals = ['superadmin', 'root', 'worker', 'service', 'internal', 'operator'];
      for (const p of invalidPrincipals) {
        expect(() => validateRouteAuthorizationPolicy({ principal: p })).toThrowError(
          expect.objectContaining({
            name: 'AuthorizationError',
            code: 'AUTHZ_ROUTE_POLICY_INVALID',
          }),
        );
      }
    });

    it('9. rejects browser policy without minRole', () => {
      expect(() => validateRouteAuthorizationPolicy({ principal: 'browser' })).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('10. rejects browser policy with invalid role', () => {
      const invalidRoles = ['superadmin', 'operator', 'owner', 'guest', 'root', 123, null];
      for (const r of invalidRoles) {
        expect(() =>
          validateRouteAuthorizationPolicy({ principal: 'browser', minRole: r }),
        ).toThrowError(
          expect.objectContaining({
            name: 'AuthorizationError',
            code: 'AUTHZ_ROUTE_POLICY_INVALID',
          }),
        );
      }
    });

    it('11. rejects anonymous route with minRole declared', () => {
      expect(() =>
        validateRouteAuthorizationPolicy({ principal: 'anonymous', minRole: 'member' }),
      ).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('12. rejects virtual-key route with minRole declared', () => {
      expect(() =>
        validateRouteAuthorizationPolicy({ principal: 'virtual_key', minRole: 'admin' }),
      ).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('13. rejects unexpected extra authorization fields on policies', () => {
      expect(() =>
        validateRouteAuthorizationPolicy({ principal: 'anonymous', extraField: true }),
      ).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );

      expect(() =>
        validateRouteAuthorizationPolicy({
          principal: 'browser',
          minRole: 'admin',
          allowAll: true,
        }),
      ).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );

      expect(() =>
        validateRouteAuthorizationPolicy({ principal: 'virtual_key', bypass: true }),
      ).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('14. rejects invalid declaration types (arrays, strings, numbers, booleans)', () => {
      const invalidTypes = [[], ['browser'], 'browser', 123, true, false];
      for (const val of invalidTypes) {
        expect(() => validateRouteAuthorizationPolicy(val)).toThrowError(
          expect.objectContaining({
            name: 'AuthorizationError',
            code: 'AUTHZ_ROUTE_POLICY_INVALID',
          }),
        );
      }
    });

    it('15. formats sanitized error messages with method and url without raw credentials', () => {
      try {
        validateRouteAuthorizationPolicy(undefined, { method: 'POST', url: '/auth/test' });
        expect.fail('Expected validateRouteAuthorizationPolicy to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(AuthorizationError);
        const authzErr = err as AuthorizationError;
        expect(authzErr.message).toContain('Route "POST /auth/test":');
        expect(authzErr.code).toBe('AUTHZ_ROUTE_POLICY_INVALID');
      }
    });
  });

  describe('2. Role matrix & principal separation tests on production boundary (AUTHZ-04)', () => {
    function createRbacSessionService(role?: unknown): SessionService {
      return {
        extractSessionSecretFromCookieHeader: (cookie?: string) => {
          if (cookie?.includes('valid_secret'))
            return 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
          return null;
        },
        resolveAndValidateSession: async () => {
          return {
            valid: true,
            user: {
              id: 'u1',
              orgId: 'o1',
              ...(role !== undefined ? { role } : {}),
              emailNormalized: 'u1@o1.com',
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
            } as any,
            session: {
              sessionIdHash: Buffer.alloc(32, 1),
              userId: 'u1',
              orgId: 'o1',
              csrfTokenHash: Buffer.alloc(32, 2),
              createdAt: new Date(),
              lastSeenAt: new Date(),
              idleExpiresAt: new Date(Date.now() + 3600000),
              absoluteExpiresAt: new Date(Date.now() + 86400000),
              revokedAt: null,
            },
          };
        },
        resolveAndValidateSessionWithCsrf: async () => ({
          valid: false,
          reason: 'SESSION_NOT_FOUND',
        }),
      } as unknown as SessionService;
    }

    async function buildBoundaryApp(
      role?: unknown,
      vkAuthenticator?: VirtualKeyAuthenticator,
    ): Promise<FastifyInstance> {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createRbacSessionService(role),
        trustedOrigin: TRUSTED_ORIGIN,
        virtualKeyAuthenticator: vkAuthenticator ?? {
          authenticateKey: async () => ({
            valid: true,
            principal: { type: 'virtual_key', keyId: 'k1', orgId: 'o1' },
          }),
        },
      });

      app.get(
        '/member-route',
        { config: { authz: { principal: 'browser', minRole: 'member' } } },
        async (req) => ({ ok: true, principal: req.principal }),
      );

      app.get(
        '/admin-route',
        { config: { authz: { principal: 'browser', minRole: 'admin' } } },
        async (req) => ({ ok: true, principal: req.principal }),
      );

      app.get(
        '/virtual-key-route',
        { config: { authz: { principal: 'virtual_key' } } },
        async (req) => ({ ok: true, principal: req.principal }),
      );

      app.get('/anon-route', { config: { authz: { principal: 'anonymous' } } }, async (req) => ({
        ok: true,
        principal: req.principal,
      }));

      await app.ready();
      return app;
    }

    it('enforces role access: member -> member is allow (200)', async () => {
      const app = await buildBoundaryApp('member');
      const res = await app.inject({
        method: 'GET',
        url: '/member-route',
        headers: { cookie: 'switchyard_session=valid_secret' },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().principal.role).toBe('member');
      await app.close();
    });

    it('enforces role access: admin -> member is allow (200)', async () => {
      const app = await buildBoundaryApp('admin');
      const res = await app.inject({
        method: 'GET',
        url: '/member-route',
        headers: { cookie: 'switchyard_session=valid_secret' },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().principal.role).toBe('admin');
      await app.close();
    });

    it('enforces role access: member -> admin is deny (403)', async () => {
      const app = await buildBoundaryApp('member');
      const res = await app.inject({
        method: 'GET',
        url: '/admin-route',
        headers: { cookie: 'switchyard_session=valid_secret' },
      });
      expect(res.statusCode).toBe(403);
      expect(res.json().error).toBe('Forbidden');
      await app.close();
    });

    it('enforces role access: admin -> admin is allow (200)', async () => {
      const app = await buildBoundaryApp('admin');
      const res = await app.inject({
        method: 'GET',
        url: '/admin-route',
        headers: { cookie: 'switchyard_session=valid_secret' },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().principal.role).toBe('admin');
      await app.close();
    });

    it('enforces role access: missing role is deny (403)', async () => {
      const app = await buildBoundaryApp(undefined);
      const res = await app.inject({
        method: 'GET',
        url: '/member-route',
        headers: { cookie: 'switchyard_session=valid_secret' },
      });
      expect(res.statusCode).toBe(403);
      expect(res.json().error).toBe('Forbidden');
      await app.close();
    });

    it('enforces role access: unknown or spoofed role is deny (403)', async () => {
      const invalidRoles = ['superadmin', 'operator', 'root', 'guest', 'owner'];
      for (const r of invalidRoles) {
        const app = await buildBoundaryApp(r);
        const res = await app.inject({
          method: 'GET',
          url: '/member-route',
          headers: { cookie: 'switchyard_session=valid_secret' },
        });
        expect(res.statusCode).toBe(403);
        expect(res.json().error).toBe('Forbidden');
        await app.close();
      }
    });

    it('enforces principal separation: browser cookie cannot satisfy virtual-key route (401)', async () => {
      const app = await buildBoundaryApp('admin');
      const res = await app.inject({
        method: 'GET',
        url: '/virtual-key-route',
        headers: { cookie: 'switchyard_session=valid_secret' },
      });
      expect(res.statusCode).toBe(401);
      expect(res.json().message).toBe('Authentication required');
      await app.close();
    });

    it('enforces principal separation: virtual-key bearer token cannot satisfy browser route (401)', async () => {
      const app = await buildBoundaryApp('admin');
      const res = await app.inject({
        method: 'GET',
        url: '/member-route',
        headers: { authorization: 'Bearer test_key_123' },
      });
      expect(res.statusCode).toBe(401);
      expect(res.json().message).toBe('Authentication required');
      await app.close();
    });

    it('enforces principal separation: anonymous request cannot satisfy browser or virtual-key route (401)', async () => {
      const app = await buildBoundaryApp('admin');
      const resBrowser = await app.inject({ method: 'GET', url: '/member-route' });
      expect(resBrowser.statusCode).toBe(401);

      const resVk = await app.inject({ method: 'GET', url: '/virtual-key-route' });
      expect(resVk.statusCode).toBe(401);

      const resAnon = await app.inject({ method: 'GET', url: '/anon-route' });
      expect(resAnon.statusCode).toBe(200);
      expect(resAnon.json().principal.type).toBe('anonymous');
      await app.close();
    });
  });

  describe('3. Fastify Registration & Route Helper Tests (AUTHZ-03)', () => {
    it('1. undeclared GET route fails registration', () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      expect(() => {
        app.get('/unprotected-get', async () => ({ ok: true }));
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('2. undeclared POST route fails registration', () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      expect(() => {
        app.post('/unprotected-post', async () => ({ ok: true }));
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('3. undeclared PATCH route fails registration', () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      expect(() => {
        app.patch('/unprotected-patch', async () => ({ ok: true }));
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('4. undeclared DELETE route fails registration', () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      expect(() => {
        app.delete('/unprotected-delete', async () => ({ ok: true }));
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('5. valid anonymous GET route registers and is callable', async () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      app.get('/health/live', { config: { authz: { principal: 'anonymous' } } }, async () => ({
        status: 'ok',
      }));

      await app.ready();
      const res = await app.inject({ method: 'GET', url: '/health/live' });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ status: 'ok' });
      await app.close();
    });

    it('6. valid member browser GET route registers', async () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      app.get(
        '/dashboard/overview',
        { config: { authz: { principal: 'browser', minRole: 'member' } } },
        async () => ({ ok: true }),
      );

      await app.ready();
      await app.close();
    });

    it('7. valid admin browser POST route registers', async () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      app.post(
        '/admin/settings',
        { config: { authz: { principal: 'browser', minRole: 'admin' } } },
        async () => ({ updated: true }),
      );

      await app.ready();
      await app.close();
    });

    it('8. declared virtual-key route without an authenticator dependency fails registration', () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      expect(() => {
        app.post(
          '/v1/chat/completions',
          { config: { authz: { principal: 'virtual_key' } } },
          async () => ({ model: 'test' }),
        );
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('8b. declared virtual-key route with explicit test authenticator registers successfully', async () => {
      const app = fastify();
      const mockVkAuthenticator: VirtualKeyAuthenticator = {
        authenticateKey: async () => ({
          valid: true,
          principal: { type: 'virtual_key', keyId: 'k1', orgId: 'o1' },
        }),
      };

      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
        virtualKeyAuthenticator: mockVkAuthenticator,
      });

      app.post(
        '/v1/chat/completions',
        { config: { authz: { principal: 'virtual_key' } } },
        async () => ({ model: 'test' }),
      );

      await app.ready();
      await app.close();
    });

    it('9. invalid route in nested plugin fails startup fail-closed', async () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      app.register(async (nested) => {
        nested.get('/nested/unprotected', async () => ({ ok: true }));
      });

      await expect(app.ready()).rejects.toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
      await app.close();
    });

    it('10. invalid route in prefixed plugin fails startup fail-closed', async () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      app.register(
        async (prefixed) => {
          prefixed.post('/unprotected-prefixed', async () => ({ ok: true }));
        },
        { prefix: '/api/v1' },
      );

      await expect(app.ready()).rejects.toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
      await app.close();
    });

    it('11. direct app.route without policy fails registration', () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      expect(() => {
        app.route({
          method: 'GET',
          url: '/direct-route-unprotected',
          handler: async () => ({ ok: true }),
        });
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('12. direct app.get without policy fails registration', () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      expect(() => {
        app.get('/direct-get-unprotected', async () => ({ ok: true }));
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('13. route-registration helper registers valid anonymous route', async () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      registerAuthorizedRoute(app, {
        method: 'GET',
        url: '/helper-anon',
        config: { authz: { principal: 'anonymous' } },
        handler: async () => ({ helper: true }),
      });

      await app.ready();
      const res = await app.inject({ method: 'GET', url: '/helper-anon' });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ helper: true });
      await app.close();
    });

    it('14. route-registration helper registers valid browser member and admin routes', async () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      registerAuthorizedRoute(app, {
        method: 'GET',
        url: '/helper-member',
        config: { authz: { principal: 'browser', minRole: 'member' } },
        handler: async () => ({ member: true }),
      });

      registerAuthorizedRoute(app, {
        method: 'POST',
        url: '/helper-admin',
        config: { authz: { principal: 'browser', minRole: 'admin' } },
        handler: async () => ({ admin: true }),
      });

      await app.ready();
      await app.close();
    });

    it('15. route-registration helper registers valid virtual-key route with test authenticator', async () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
        virtualKeyAuthenticator: {
          authenticateKey: async () => ({
            valid: true,
            principal: { type: 'virtual_key', keyId: 'k1', orgId: 'o1' },
          }),
        },
      });

      registerAuthorizedRoute(app, {
        method: 'POST',
        url: '/helper-vk',
        config: { authz: { principal: 'virtual_key' } },
        handler: async () => ({ vk: true }),
      });

      await app.ready();
      await app.close();
    });

    it('16. route-registration helper rejects missing config.authz at runtime', () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      expect(() => {
        registerAuthorizedRoute(app, {
          method: 'GET',
          url: '/helper-unprotected',
          handler: async () => ({ ok: true }),
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } as any);
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('17. route-registration helper rejects null policy at runtime', () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      expect(() => {
        registerAuthorizedRoute(app, {
          method: 'GET',
          url: '/helper-null-policy',
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          config: { authz: null as any },
          handler: async () => ({ ok: true }),
        });
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('18. route-registration helper rejects invalid policy at runtime', () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      expect(() => {
        registerAuthorizedRoute(app, {
          method: 'GET',
          url: '/helper-invalid-policy',
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          config: { authz: { principal: 'invalid' } as any },
          handler: async () => ({ ok: true }),
        });
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('19. route-registration helper rejects conflicting top-level authz declaration at runtime', () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      expect(() => {
        registerAuthorizedRoute(app, {
          method: 'GET',
          url: '/helper-conflicting-authz',
          config: { authz: { principal: 'anonymous' } },
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          authz: { principal: 'anonymous' } as any,
          handler: async () => ({ ok: true }),
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } as any);
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('20. route-registration helper preserves additional custom config without mutating options', async () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      const inputOptions: AuthorizedRouteOptions<
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        any,
        { customRateLimit: number; authz: RouteAuthorizationPolicy }
      > = {
        method: 'GET',
        url: '/helper-custom-config',
        config: {
          customRateLimit: 42,
          authz: { principal: 'anonymous' },
        },
        handler: async (req) => ({
          rateLimit: (req.routeOptions.config as { customRateLimit: number }).customRateLimit,
        }),
      };

      const originalConfigCopy = { ...inputOptions.config };
      registerAuthorizedRoute(app, inputOptions);

      // Verify input object was not mutated
      expect(inputOptions.config).toEqual(originalConfigCopy);

      await app.ready();
      const res = await app.inject({ method: 'GET', url: '/helper-custom-config' });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ rateLimit: 42 });
      await app.close();
    });

    it('21. compile-time test: TypeScript rejects registerAuthorizedRoute without config.authz', () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      expect(() => {
        // @ts-expect-error - Compile-time assertion: options missing config.authz must fail typecheck
        registerAuthorizedRoute(app, {
          method: 'GET',
          url: '/compile-fail-missing-config',
          handler: async () => ({ ok: true }),
        });
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );

      expect(() => {
        registerAuthorizedRoute(app, {
          method: 'GET',
          url: '/compile-fail-toplevel-authz',
          // @ts-expect-error - Compile-time assertion: options with top-level authz must fail typecheck
          authz: { principal: 'anonymous' },
          handler: async () => ({ ok: true }),
        });
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('22. automatically generated HEAD routes inherit policy and cannot bypass authorization', async () => {
      const app = fastify();
      let sessionValidated = false;

      const mockSessionService = {
        extractSessionSecretFromCookieHeader: (cookie?: string) => {
          if (cookie?.includes('valid_secret'))
            return 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
          return null;
        },
        resolveAndValidateSession: async () => {
          sessionValidated = true;
          return {
            valid: true,
            user: {
              id: 'u1',
              orgId: 'o1',
              role: 'member' as const,
              emailNormalized: 'u1@o1.com',
            },
            session: {
              sessionIdHash: Buffer.alloc(32, 1),
              userId: 'u1',
              orgId: 'o1',
              csrfTokenHash: Buffer.alloc(32, 2),
              createdAt: new Date(),
              lastSeenAt: new Date(),
              idleExpiresAt: new Date(Date.now() + 3600000),
              absoluteExpiresAt: new Date(Date.now() + 86400000),
              revokedAt: null,
            },
          };
        },
      } as unknown as SessionService;

      installAuthorizationBoundary(app, {
        sessionService: mockSessionService,
        trustedOrigin: TRUSTED_ORIGIN,
      });

      app.get(
        '/protected/resource',
        { config: { authz: { principal: 'browser', minRole: 'member' } } },
        async () => ({ data: 'secret' }),
      );

      await app.ready();

      // HEAD without cookie must fail 401
      const unauthHeadRes = await app.inject({
        method: 'HEAD',
        url: '/protected/resource',
      });
      expect(unauthHeadRes.statusCode).toBe(401);

      // HEAD with valid cookie must authenticate and succeed 200
      const authHeadRes = await app.inject({
        method: 'HEAD',
        url: '/protected/resource',
        headers: {
          cookie: 'switchyard_session=valid_secret',
        },
      });
      expect(authHeadRes.statusCode).toBe(200);
      expect(sessionValidated).toBe(true);

      await app.close();
    });

    it('23. unknown or malformed authorization metadata cannot be interpreted as anonymous', async () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      expect(() => {
        app.get(
          '/malformed-policy',
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          { config: { authz: { principal: 'public' } as any } },
          async () => ({ ok: true }),
        );
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('24. production startup fails completely on route registration error (cannot listen or ready)', async () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      app.register(async (plugin) => {
        plugin.get('/invalid-startup', async () => ({ ok: true }));
      });

      let startupFailed = false;
      try {
        await app.ready();
      } catch (err) {
        startupFailed = true;
        expect((err as AuthorizationError).code).toBe('AUTHZ_ROUTE_POLICY_INVALID');
      }
      expect(startupFailed).toBe(true);
      await app.close();
    });
  });

  describe('4. Virtual-Key Principal Shape & Authentication Tests (AUTHZ-01)', () => {
    async function buildVkApp(
      authenticator: VirtualKeyAuthenticator,
      onHandlerInvoked: () => void,
    ): Promise<FastifyInstance> {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
        virtualKeyAuthenticator: authenticator,
      });

      app.post(
        '/v1/inference',
        { config: { authz: { principal: 'virtual_key' } } },
        async (req) => {
          onHandlerInvoked();
          return { ok: true, principal: req.principal };
        },
      );

      await app.ready();
      return app;
    }

    it('1. correct virtual-key principal authorizes successfully and preserves keyPolicy', async () => {
      let handlerCalled = false;
      const authenticator: VirtualKeyAuthenticator = {
        authenticateKey: async (rawKey: string): Promise<VirtualKeyVerificationResult> => {
          if (rawKey === 'valid_key_secret') {
            return {
              valid: true,
              principal: {
                type: 'virtual_key',
                keyId: 'vk_123',
                orgId: 'org_abc',
                keyPolicy: { allowedModels: ['model-1'] },
              },
            };
          }
          return { valid: false };
        },
      };

      const app = await buildVkApp(authenticator, () => {
        handlerCalled = true;
      });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/inference',
        headers: { authorization: 'Bearer valid_key_secret' },
      });

      expect(res.statusCode).toBe(200);
      expect(handlerCalled).toBe(true);
      expect(res.json().principal).toEqual({
        type: 'virtual_key',
        keyId: 'vk_123',
        orgId: 'org_abc',
        keyPolicy: { allowedModels: ['model-1'] },
      });
      await app.close();
    });

    it('2. authenticator returns valid: false -> 401 Unauthorized, handler not invoked', async () => {
      let handlerCalled = false;
      const authenticator: VirtualKeyAuthenticator = {
        authenticateKey: async () => ({
          valid: false,
          reason: 'KEY_NOT_FOUND',
        }),
      };

      const app = await buildVkApp(authenticator, () => {
        handlerCalled = true;
      });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/inference',
        headers: { authorization: 'Bearer invalid_key' },
      });

      expect(res.statusCode).toBe(401);
      expect(res.json().message).toBe('Authentication required');
      expect(handlerCalled).toBe(false);
      await app.close();
    });

    it('3. authenticator returns valid: true with no principal -> 503, handler not invoked', async () => {
      let handlerCalled = false;
      const authenticator: VirtualKeyAuthenticator = {
        authenticateKey: async () =>
          ({
            valid: true,
            principal: undefined,
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
          }) as any,
      };

      const app = await buildVkApp(authenticator, () => {
        handlerCalled = true;
      });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/inference',
        headers: { authorization: 'Bearer any_key' },
      });

      expect(res.statusCode).toBe(503);
      expect(res.json().message).toBe('Authentication service unavailable');
      expect(handlerCalled).toBe(false);
      await app.close();
    });

    it('4. authenticator returns valid: true with a browser principal -> 503, handler not invoked', async () => {
      let handlerCalled = false;
      const authenticator: VirtualKeyAuthenticator = {
        authenticateKey: async () => ({
          valid: true,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          principal: { type: 'browser', userId: 'u1', orgId: 'o1', role: 'admin' } as any,
        }),
      };

      const app = await buildVkApp(authenticator, () => {
        handlerCalled = true;
      });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/inference',
        headers: { authorization: 'Bearer any_key' },
      });

      expect(res.statusCode).toBe(503);
      expect(res.json().message).toBe('Authentication service unavailable');
      expect(handlerCalled).toBe(false);
      await app.close();
    });

    it('5. authenticator returns valid: true with an anonymous principal -> 503, handler not invoked', async () => {
      let handlerCalled = false;
      const authenticator: VirtualKeyAuthenticator = {
        authenticateKey: async () => ({
          valid: true,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          principal: { type: 'anonymous' } as any,
        }),
      };

      const app = await buildVkApp(authenticator, () => {
        handlerCalled = true;
      });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/inference',
        headers: { authorization: 'Bearer any_key' },
      });

      expect(res.statusCode).toBe(503);
      expect(res.json().message).toBe('Authentication service unavailable');
      expect(handlerCalled).toBe(false);
      await app.close();
    });

    it('6. authenticator returns missing keyId -> 503, handler not invoked', async () => {
      let handlerCalled = false;
      const authenticator: VirtualKeyAuthenticator = {
        authenticateKey: async () => ({
          valid: true,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          principal: { type: 'virtual_key', orgId: 'o1' } as any,
        }),
      };

      const app = await buildVkApp(authenticator, () => {
        handlerCalled = true;
      });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/inference',
        headers: { authorization: 'Bearer any_key' },
      });

      expect(res.statusCode).toBe(503);
      expect(res.json().message).toBe('Authentication service unavailable');
      expect(handlerCalled).toBe(false);
      await app.close();
    });

    it('7. authenticator returns empty keyId -> 503, handler not invoked', async () => {
      let handlerCalled = false;
      const authenticator: VirtualKeyAuthenticator = {
        authenticateKey: async () => ({
          valid: true,
          principal: { type: 'virtual_key', keyId: '   ', orgId: 'o1' },
        }),
      };

      const app = await buildVkApp(authenticator, () => {
        handlerCalled = true;
      });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/inference',
        headers: { authorization: 'Bearer any_key' },
      });

      expect(res.statusCode).toBe(503);
      expect(res.json().message).toBe('Authentication service unavailable');
      expect(handlerCalled).toBe(false);
      await app.close();
    });

    it('8. authenticator returns missing orgId -> 503, handler not invoked', async () => {
      let handlerCalled = false;
      const authenticator: VirtualKeyAuthenticator = {
        authenticateKey: async () => ({
          valid: true,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          principal: { type: 'virtual_key', keyId: 'k1' } as any,
        }),
      };

      const app = await buildVkApp(authenticator, () => {
        handlerCalled = true;
      });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/inference',
        headers: { authorization: 'Bearer any_key' },
      });

      expect(res.statusCode).toBe(503);
      expect(res.json().message).toBe('Authentication service unavailable');
      expect(handlerCalled).toBe(false);
      await app.close();
    });

    it('9. authenticator returns empty orgId -> 503, handler not invoked', async () => {
      let handlerCalled = false;
      const authenticator: VirtualKeyAuthenticator = {
        authenticateKey: async () => ({
          valid: true,
          principal: { type: 'virtual_key', keyId: 'k1', orgId: '' },
        }),
      };

      const app = await buildVkApp(authenticator, () => {
        handlerCalled = true;
      });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/inference',
        headers: { authorization: 'Bearer any_key' },
      });

      expect(res.statusCode).toBe(503);
      expect(res.json().message).toBe('Authentication service unavailable');
      expect(handlerCalled).toBe(false);
      await app.close();
    });

    it('10. authenticator returns unexpected role/userId fields -> 503, handler not invoked', async () => {
      let handlerCalled = false;
      const authenticator: VirtualKeyAuthenticator = {
        authenticateKey: async () => ({
          valid: true,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          principal: { type: 'virtual_key', keyId: 'k1', orgId: 'o1', role: 'admin' } as any,
        }),
      };

      const app = await buildVkApp(authenticator, () => {
        handlerCalled = true;
      });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/inference',
        headers: { authorization: 'Bearer any_key' },
      });

      expect(res.statusCode).toBe(503);
      expect(res.json().message).toBe('Authentication service unavailable');
      expect(handlerCalled).toBe(false);
      await app.close();

      // Also check userId unexpected field
      let handlerCalled2 = false;
      const authenticator2: VirtualKeyAuthenticator = {
        authenticateKey: async () => ({
          valid: true,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          principal: { type: 'virtual_key', keyId: 'k1', orgId: 'o1', userId: 'u1' } as any,
        }),
      };

      const app2 = await buildVkApp(authenticator2, () => {
        handlerCalled2 = true;
      });

      const res2 = await app2.inject({
        method: 'POST',
        url: '/v1/inference',
        headers: { authorization: 'Bearer any_key' },
      });

      expect(res2.statusCode).toBe(503);
      expect(res2.json().message).toBe('Authentication service unavailable');
      expect(handlerCalled2).toBe(false);
      await app2.close();
    });

    it('11. authenticator throws an exception -> 503, handler not invoked', async () => {
      let handlerCalled = false;
      const authenticator: VirtualKeyAuthenticator = {
        authenticateKey: async () => {
          throw new Error('Database connection failed');
        },
      };

      const app = await buildVkApp(authenticator, () => {
        handlerCalled = true;
      });

      const res = await app.inject({
        method: 'POST',
        url: '/v1/inference',
        headers: { authorization: 'Bearer any_key' },
      });

      expect(res.statusCode).toBe(503);
      expect(res.json().message).toBe('Authentication service unavailable');
      expect(handlerCalled).toBe(false);
      await app.close();
    });
  });
});
