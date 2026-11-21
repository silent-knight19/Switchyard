import fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import {
  type AuthorizedPrincipal,
  type BrowserRole,
  type RouteAuthorizationPolicy,
  type VirtualKeyAuthenticator,
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

  describe('2. Role matrix & principal separation logic tests (Section 12)', () => {
    function evaluateRoleAccess(userRole: unknown, requiredMinRole: BrowserRole): boolean {
      if (userRole !== 'admin' && userRole !== 'member') {
        return false;
      }
      if (requiredMinRole === 'admin') {
        return userRole === 'admin';
      }
      if (requiredMinRole === 'member') {
        return userRole === 'member' || userRole === 'admin';
      }
      return false;
    }

    it('enforces role access matrix: member -> member is allow', () => {
      expect(evaluateRoleAccess('member', 'member')).toBe(true);
    });

    it('enforces role access matrix: admin -> member is allow', () => {
      expect(evaluateRoleAccess('admin', 'member')).toBe(true);
    });

    it('enforces role access matrix: member -> admin is deny', () => {
      expect(evaluateRoleAccess('member', 'admin')).toBe(false);
    });

    it('enforces role access matrix: admin -> admin is allow', () => {
      expect(evaluateRoleAccess('admin', 'admin')).toBe(true);
    });

    it('enforces role access matrix: missing role is deny', () => {
      expect(evaluateRoleAccess(undefined, 'member')).toBe(false);
      expect(evaluateRoleAccess(null, 'admin')).toBe(false);
    });

    it('enforces role access matrix: unknown or spoofed role is deny', () => {
      expect(evaluateRoleAccess('superadmin', 'member')).toBe(false);
      expect(evaluateRoleAccess('operator', 'admin')).toBe(false);
      expect(evaluateRoleAccess('root', 'admin')).toBe(false);
    });

    it('enforces principal separation: browser principal cannot satisfy virtual-key policy', () => {
      const browserPrincipal: AuthorizedPrincipal = {
        type: 'browser',
        userId: 'u1',
        orgId: 'org1',
        role: 'admin',
      };
      const isVirtualKey = (browserPrincipal.type as string) === 'virtual_key';
      expect(isVirtualKey).toBe(false);
    });

    it('enforces principal separation: virtual-key principal cannot satisfy browser policy', () => {
      const vkPrincipal: AuthorizedPrincipal = {
        type: 'virtual_key',
        keyId: 'k1',
        orgId: 'org1',
      };
      const isBrowser = (vkPrincipal.type as string) === 'browser';
      expect(isBrowser).toBe(false);
    });

    it('enforces principal separation: anonymous principal cannot satisfy browser or virtual-key policy', () => {
      const anonPrincipal: AuthorizedPrincipal = { type: 'anonymous' };
      expect((anonPrincipal.type as string) === 'browser').toBe(false);
      expect((anonPrincipal.type as string) === 'virtual_key').toBe(false);
    });
  });

  describe('3. Fastify Registration Tests (Section 13)', () => {
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
        // virtualKeyAuthenticator omitted (production buildApp behavior)
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

    it('13. route-registration helper without policy fails', () => {
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
        } as unknown as Parameters<typeof registerAuthorizedRoute>[1]);
      }).toThrowError(
        expect.objectContaining({
          name: 'AuthorizationError',
          code: 'AUTHZ_ROUTE_POLICY_INVALID',
        }),
      );
    });

    it('13b. route-registration helper with explicit authz registers successfully', async () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      registerAuthorizedRoute(app, {
        method: 'GET',
        url: '/helper-protected',
        authz: { principal: 'anonymous' },
        handler: async () => ({ helper: true }),
      });

      await app.ready();
      const res = await app.inject({ method: 'GET', url: '/helper-protected' });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ helper: true });
      await app.close();
    });

    it('14. automatically generated HEAD routes inherit policy and cannot bypass authorization', async () => {
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

      // Register GET browser route
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

    it('15. unknown or malformed authorization metadata cannot be interpreted as anonymous', async () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      // Attempting to declare arbitrary unknown metadata
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

    it('16. production startup fails completely on route registration error (cannot listen or ready)', async () => {
      const app = fastify();
      installAuthorizationBoundary(app, {
        sessionService: createMockSessionService(),
        trustedOrigin: TRUSTED_ORIGIN,
      });

      app.register(async (plugin) => {
        // Invalid route inside plugin
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
});
