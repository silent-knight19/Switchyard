import crypto from 'node:crypto';
import type pg from 'pg';
import { describe, expect, it } from 'vitest';
import { decodeSessionSecret, hashSecret, SessionService } from './session.js';
import { SessionError } from './types.js';

describe('SW-1.5.2: Session Cookie & Secret Encoding', () => {
  describe('decodeSessionSecret (AUTH-04)', () => {
    it('accepts and decodes a canonical 43-character base64url encoded 32-byte secret', () => {
      // 32 zero bytes in base64url is 43 'A's per standard
      const secret = 'A'.repeat(43);
      const buf = decodeSessionSecret(secret);
      expect(buf).toBeInstanceOf(Buffer);
      expect(buf.length).toBe(32);
      expect(buf.toString('base64url')).toBe(secret);
    });

    it('round-trips cryptographically random 32-byte tokens without loss', () => {
      for (let i = 0; i < 10; i++) {
        const raw = crypto.randomBytes(32);
        const encoded = raw.toString('base64url');
        const decoded = decodeSessionSecret(encoded);
        expect(decoded).toEqual(raw);
        expect(decoded.toString('base64url')).toBe(encoded);
      }
    });

    it('rejects secrets with invalid length without trimming', () => {
      expect(() => decodeSessionSecret('A'.repeat(42))).toThrow(SessionError);
      expect(() => decodeSessionSecret('A'.repeat(44))).toThrow(SessionError);
      expect(() => decodeSessionSecret('')).toThrow(SessionError);
    });

    it('rejects leading or trailing whitespace (no silent trimming)', () => {
      const canonical = 'A'.repeat(43);
      expect(() => decodeSessionSecret(` ${canonical}`)).toThrow(SessionError);
      expect(() => decodeSessionSecret(`${canonical} `)).toThrow(SessionError);
      expect(() => decodeSessionSecret(`\t${canonical}\n`)).toThrow(SessionError);
    });

    it('rejects standard base64 characters (+, /) and padding (=)', () => {
      // 43 chars with '+' or '/'
      const withPlus = 'A'.repeat(42) + '+';
      const withSlash = 'A'.repeat(42) + '/';
      const withPad = 'A'.repeat(42) + '=';

      expect(() => decodeSessionSecret(withPlus)).toThrow(SessionError);
      expect(() => decodeSessionSecret(withSlash)).toThrow(SessionError);
      expect(() => decodeSessionSecret(withPad)).toThrow(SessionError);
    });

    it('rejects non-base64url characters', () => {
      expect(() => decodeSessionSecret('A'.repeat(42) + '!')).toThrow(SessionError);
      expect(() => decodeSessionSecret('A'.repeat(42) + '@')).toThrow(SessionError);
      expect(() => decodeSessionSecret('A'.repeat(42) + '#')).toThrow(SessionError);
    });

    it('rejects noncanonical trailing pad bits (42 A chars + B vs 42 A chars + A)', () => {
      const canonical = 'A'.repeat(42) + 'A';
      const nonCanonical = 'A'.repeat(42) + 'B';

      // Both decode to 32 bytes in permissive Node Buffer.from, but 'B' has noncanonical pad bits
      expect(decodeSessionSecret(canonical)).toBeDefined();
      expect(() => decodeSessionSecret(nonCanonical)).toThrow(SessionError);
      try {
        decodeSessionSecret(nonCanonical);
      } catch (err) {
        expect(err).toBeInstanceOf(SessionError);
        expect((err as SessionError).reason).toBe('MALFORMED_SECRET');
        expect((err as SessionError).message).toContain(
          'noncanonical base64url encoding or invalid pad bits',
        );
      }
    });

    it('rejects non-string secrets', () => {
      expect(() => decodeSessionSecret(null)).toThrow(SessionError);
      expect(() => decodeSessionSecret(undefined)).toThrow(SessionError);
      expect(() => decodeSessionSecret(12345)).toThrow(SessionError);
    });

    it('hashSecret produces a 32-byte SHA-256 digest', () => {
      const buf = Buffer.alloc(32, 0x5a);
      const digest = hashSecret(buf);
      expect(digest).toBeInstanceOf(Buffer);
      expect(digest.length).toBe(32);
    });
  });

  describe('SessionService Cookie Security & Regression Matrix (AUTH-02, AUTH-07, AUTH-10)', () => {
    const dummyPool = {} as unknown as pg.Pool;

    function assertSecureHostCookie(service: SessionService) {
      expect(service.getCookieName()).toBe('__Host-session');

      // Verify cookie creation
      const sessionCookie = service.createSessionCookie('valid-opaque-secret-43-chars-example-123');
      expect(
        sessionCookie.startsWith('__Host-session=valid-opaque-secret-43-chars-example-123'),
      ).toBe(true);
      expect(sessionCookie).toContain('Path=/');
      expect(sessionCookie).toContain('HttpOnly');
      expect(sessionCookie).toContain('SameSite=Lax');
      expect(sessionCookie).toContain('Secure');
      expect(sessionCookie).not.toContain('Domain=');

      // Verify cookie clearing
      const clearCookie = service.createClearSessionCookie();
      expect(clearCookie.startsWith('__Host-session=')).toBe(true);
      expect(clearCookie).toContain('Path=/');
      expect(clearCookie).toContain('HttpOnly');
      expect(clearCookie).toContain('SameSite=Lax');
      expect(clearCookie).toContain('Secure');
      expect(clearCookie).toContain('Max-Age=0');
      expect(clearCookie).toContain('Expires=Thu, 01 Jan 1970 00:00:00 GMT');
      expect(clearCookie).not.toContain('Domain=');
    }

    function assertApprovedDevCookie(service: SessionService) {
      expect(service.getCookieName()).toBe('switchyard_session');

      // Verify cookie creation
      const sessionCookie = service.createSessionCookie('dev-secret-43-chars-example-1234567890');
      expect(
        sessionCookie.startsWith('switchyard_session=dev-secret-43-chars-example-1234567890'),
      ).toBe(true);
      expect(sessionCookie).toContain('Path=/');
      expect(sessionCookie).toContain('HttpOnly');
      expect(sessionCookie).toContain('SameSite=Lax');
      expect(sessionCookie).not.toContain('Secure');
      expect(sessionCookie).not.toContain('Domain=');

      // Verify cookie clearing
      const clearCookie = service.createClearSessionCookie();
      expect(clearCookie.startsWith('switchyard_session=')).toBe(true);
      expect(clearCookie).toContain('Path=/');
      expect(clearCookie).toContain('HttpOnly');
      expect(clearCookie).toContain('SameSite=Lax');
      expect(clearCookie).not.toContain('Secure');
      expect(clearCookie).toContain('Max-Age=0');
      expect(clearCookie).toContain('Expires=Thu, 01 Jan 1970 00:00:00 GMT');
      expect(clearCookie).not.toContain('Domain=');
    }

    // 1. Ambient production with no overrides
    it('1. Ambient production with no overrides produces secure __Host-session cookie', () => {
      const origEnv = process.env['NODE_ENV'];
      try {
        process.env['NODE_ENV'] = 'production';
        const service = new SessionService({ pool: dummyPool });
        assertSecureHostCookie(service);
      } finally {
        process.env['NODE_ENV'] = origEnv;
      }
    });

    // 2. Ambient production + environment: 'development' (AUTH-10 downgrade prevention)
    it('2. Ambient production + environment: "development" is rejected with CONFIGURATION_ERROR', () => {
      const origEnv = process.env['NODE_ENV'];
      try {
        process.env['NODE_ENV'] = 'production';
        expect(
          () =>
            new SessionService({
              pool: dummyPool,
              environment: 'development',
              cookieOptions: { secure: false },
            }),
        ).toThrow(SessionError);

        try {
          new SessionService({
            pool: dummyPool,
            environment: 'development',
            cookieOptions: { secure: false },
          });
        } catch (err) {
          expect(err).toBeInstanceOf(SessionError);
          expect((err as SessionError).reason).toBe('CONFIGURATION_ERROR');
          expect((err as SessionError).message).toContain(
            'Cannot downgrade production runtime to "development"',
          );
        }
      } finally {
        process.env['NODE_ENV'] = origEnv;
      }
    });

    // 3. Ambient production + environment: 'test'
    it('3. Ambient production + environment: "test" is rejected with CONFIGURATION_ERROR', () => {
      const origEnv = process.env['NODE_ENV'];
      try {
        process.env['NODE_ENV'] = 'production';
        expect(
          () =>
            new SessionService({
              pool: dummyPool,
              environment: 'test',
            }),
        ).toThrow(SessionError);
      } finally {
        process.env['NODE_ENV'] = origEnv;
      }
    });

    // 4. Ambient production + cookieOptions.isProduction = false
    it('4. Ambient production + cookieOptions.isProduction = false is rejected with CONFIGURATION_ERROR', () => {
      const origEnv = process.env['NODE_ENV'];
      try {
        process.env['NODE_ENV'] = 'production';
        expect(
          () =>
            new SessionService({
              pool: dummyPool,
              cookieOptions: { isProduction: false },
            }),
        ).toThrow(SessionError);

        try {
          new SessionService({
            pool: dummyPool,
            cookieOptions: { isProduction: false },
          });
        } catch (err) {
          expect(err).toBeInstanceOf(SessionError);
          expect((err as SessionError).reason).toBe('CONFIGURATION_ERROR');
          expect((err as SessionError).message).toContain(
            'Production environment cannot be overridden with isProduction: false',
          );
        }
      } finally {
        process.env['NODE_ENV'] = origEnv;
      }
    });

    // 5. Ambient production + cookieOptions.secure = false
    it('5. Ambient production + cookieOptions.secure = false is rejected with CONFIGURATION_ERROR', () => {
      const origEnv = process.env['NODE_ENV'];
      try {
        process.env['NODE_ENV'] = 'production';
        expect(
          () =>
            new SessionService({
              pool: dummyPool,
              cookieOptions: { secure: false },
            }),
        ).toThrow(SessionError);

        try {
          new SessionService({
            pool: dummyPool,
            cookieOptions: { secure: false },
          });
        } catch (err) {
          expect(err).toBeInstanceOf(SessionError);
          expect((err as SessionError).reason).toBe('CONFIGURATION_ERROR');
          expect((err as SessionError).message).toContain('Insecure session cookies');
        }
      } finally {
        process.env['NODE_ENV'] = origEnv;
      }
    });

    // 6. Ambient production + insecure custom cookie name
    it('6. Ambient production + insecure custom cookie name is rejected with CONFIGURATION_ERROR', () => {
      const origEnv = process.env['NODE_ENV'];
      try {
        process.env['NODE_ENV'] = 'production';
        expect(
          () =>
            new SessionService({
              pool: dummyPool,
              cookieOptions: { cookieName: 'insecure_cookie' },
            }),
        ).toThrow(SessionError);

        try {
          new SessionService({
            pool: dummyPool,
            cookieOptions: { cookieName: 'insecure_cookie' },
          });
        } catch (err) {
          expect(err).toBeInstanceOf(SessionError);
          expect((err as SessionError).reason).toBe('CONFIGURATION_ERROR');
          expect((err as SessionError).message).toContain('must use the "__Host-session" name');
        }
      } finally {
        process.env['NODE_ENV'] = origEnv;
      }
    });

    // 7. Validated production config + explicit development environment
    it('7. Validated production config + explicit development environment is rejected with CONFIGURATION_ERROR', () => {
      const prodConfig = {
        NODE_ENV: 'production',
        PORT: 3000,
        HOST: '127.0.0.1',
        POSTGRES_HOST: '127.0.0.1',
        POSTGRES_PORT: 5432,
        POSTGRES_DB: 'switchyard',
        POSTGRES_USER: 'gateway_app',
        POSTGRES_PASSWORD: 'prod_password',
        REDIS_HOST: '127.0.0.1',
        REDIS_PORT: 6379,
        REDIS_USER: 'switchyard_app',
        REDIS_PASSWORD: 'prod_password',
        REDIS_MAXMEMORY_POLICY: 'noeviction',
        REDIS_TLS: false,
        COOKIE_SECURE: true,
        TLS_VERIFY: true,
        MOCK_PROVIDER_ENABLED: false,
        DEMO_SEEDING_ENABLED: false,
      } as const;

      expect(
        () =>
          new SessionService({
            pool: dummyPool,
            config: prodConfig,
            environment: 'development',
          }),
      ).toThrow(SessionError);

      try {
        new SessionService({
          pool: dummyPool,
          config: prodConfig,
          environment: 'development',
        });
      } catch (err) {
        expect(err).toBeInstanceOf(SessionError);
        expect((err as SessionError).reason).toBe('CONFIGURATION_ERROR');
        expect((err as SessionError).message).toContain('Conflicting environment configuration');
      }
    });

    // 8. Validated production config + insecure cookie options
    it('8. Validated production config + insecure cookie options is rejected with CONFIGURATION_ERROR', () => {
      const prodConfig = {
        NODE_ENV: 'production',
        PORT: 3000,
        HOST: '127.0.0.1',
        POSTGRES_HOST: '127.0.0.1',
        POSTGRES_PORT: 5432,
        POSTGRES_DB: 'switchyard',
        POSTGRES_USER: 'gateway_app',
        POSTGRES_PASSWORD: 'prod_password',
        REDIS_HOST: '127.0.0.1',
        REDIS_PORT: 6379,
        REDIS_USER: 'switchyard_app',
        REDIS_PASSWORD: 'prod_password',
        REDIS_MAXMEMORY_POLICY: 'noeviction',
        REDIS_TLS: false,
        COOKIE_SECURE: true,
        TLS_VERIFY: true,
        MOCK_PROVIDER_ENABLED: false,
        DEMO_SEEDING_ENABLED: false,
      } as const;

      expect(
        () =>
          new SessionService({
            pool: dummyPool,
            config: prodConfig,
            cookieOptions: { secure: false },
          }),
      ).toThrow(SessionError);

      expect(
        () =>
          new SessionService({
            pool: dummyPool,
            config: prodConfig,
            cookieOptions: { isProduction: false },
          }),
      ).toThrow(SessionError);
    });

    // 9. Conflicting validated config and environment overrides
    it('9. Conflicting validated config and environment overrides fails closed', () => {
      const devConfig = {
        NODE_ENV: 'development',
        PORT: 3000,
        HOST: '127.0.0.1',
        POSTGRES_HOST: '127.0.0.1',
        POSTGRES_PORT: 5432,
        POSTGRES_DB: 'switchyard',
        POSTGRES_USER: 'gateway_app',
        POSTGRES_PASSWORD: 'dev_password',
        REDIS_HOST: '127.0.0.1',
        REDIS_PORT: 6379,
        REDIS_USER: 'switchyard_app',
        REDIS_PASSWORD: 'dev_password',
        REDIS_MAXMEMORY_POLICY: 'noeviction',
        REDIS_TLS: false,
        COOKIE_SECURE: false,
        TLS_VERIFY: true,
        MOCK_PROVIDER_ENABLED: false,
        DEMO_SEEDING_ENABLED: false,
      } as const;

      expect(
        () =>
          new SessionService({
            pool: dummyPool,
            config: devConfig,
            environment: 'test',
          }),
      ).toThrow(SessionError);
    });

    // 10. Production config with ambient test environment, confirming production protections remain enforced
    it('10. Production config with ambient test environment enforces production protections', () => {
      const origEnv = process.env['NODE_ENV'];
      try {
        process.env['NODE_ENV'] = 'test';
        const prodConfig = {
          NODE_ENV: 'production',
          PORT: 3000,
          HOST: '127.0.0.1',
          POSTGRES_HOST: '127.0.0.1',
          POSTGRES_PORT: 5432,
          POSTGRES_DB: 'switchyard',
          POSTGRES_USER: 'gateway_app',
          POSTGRES_PASSWORD: 'prod_password',
          REDIS_HOST: '127.0.0.1',
          REDIS_PORT: 6379,
          REDIS_USER: 'switchyard_app',
          REDIS_PASSWORD: 'prod_password',
          REDIS_MAXMEMORY_POLICY: 'noeviction',
          REDIS_TLS: false,
          COOKIE_SECURE: true,
          TLS_VERIFY: true,
          MOCK_PROVIDER_ENABLED: false,
          DEMO_SEEDING_ENABLED: false,
        } as const;

        // Default construction with prodConfig produces secure __Host-session
        const service = new SessionService({
          pool: dummyPool,
          config: prodConfig,
        });
        assertSecureHostCookie(service);

        // Attempting insecure options fails closed
        expect(
          () =>
            new SessionService({
              pool: dummyPool,
              config: prodConfig,
              cookieOptions: { secure: false },
            }),
        ).toThrow(SessionError);
      } finally {
        process.env['NODE_ENV'] = origEnv;
      }
    });

    // 11. Development HTTP-loopback behavior
    it('11. Development HTTP-loopback behavior produces approved unencrypted cookie', () => {
      const service = new SessionService({
        pool: dummyPool,
        environment: 'development',
        cookieOptions: { secure: false },
      });
      assertApprovedDevCookie(service);
    });

    // 12. Development with explicitly secure cookies
    it('12. Development with explicitly secure cookies produces secure __Host-session cookie', () => {
      const service = new SessionService({
        pool: dummyPool,
        environment: 'development',
        cookieOptions: { secure: true },
      });
      assertSecureHostCookie(service);
    });

    // 13. Test environment with isolated configuration
    it('13. Test environment with isolated configuration allows isolated test behavior', () => {
      const service = new SessionService({
        pool: dummyPool,
        environment: 'test',
        cookieOptions: { cookieName: 'custom_test_cookie', secure: false },
      });

      expect(service.getCookieName()).toBe('custom_test_cookie');
      const sessionCookie = service.createSessionCookie('test-token');
      expect(sessionCookie.startsWith('custom_test_cookie=test-token')).toBe(true);
      expect(sessionCookie).toContain('Path=/');
      expect(sessionCookie).toContain('HttpOnly');
      expect(sessionCookie).toContain('SameSite=Lax');
      expect(sessionCookie).not.toContain('Secure');

      const clearCookie = service.createClearSessionCookie();
      expect(clearCookie.startsWith('custom_test_cookie=')).toBe(true);
      expect(clearCookie).toContain('Max-Age=0');
      expect(clearCookie).not.toContain('Secure');
    });

    // 14. Unknown/invalid environment configuration
    it('14. Unknown/invalid environment configuration fails closed with CONFIGURATION_ERROR', () => {
      expect(
        () =>
          new SessionService({
            pool: dummyPool,
            environment: 'staging' as unknown as 'development',
          }),
      ).toThrow(SessionError);

      expect(
        () =>
          new SessionService({
            pool: dummyPool,
            environment: 'unknown' as unknown as 'development',
          }),
      ).toThrow(SessionError);

      expect(
        () =>
          new SessionService({
            pool: dummyPool,
            environment: '' as unknown as 'development',
          }),
      ).toThrow(SessionError);

      const origEnv = process.env['NODE_ENV'];
      try {
        process.env['NODE_ENV'] = 'invalid_env';
        expect(
          () =>
            new SessionService({
              pool: dummyPool,
            }),
        ).toThrow(SessionError);
      } finally {
        process.env['NODE_ENV'] = origEnv;
      }
    });

    // 15. Cookie issuance and clearing consistency
    it('15. Cookie issuance and clearing consistency: same name and required security attributes', () => {
      const service = new SessionService({
        pool: dummyPool,
        environment: 'production',
      });

      const sessionCookie = service.createSessionCookie('secret_token');
      const clearCookie = service.createClearSessionCookie();

      // Both use exact same cookie name
      expect(sessionCookie.startsWith('__Host-session=secret_token')).toBe(true);
      expect(clearCookie.startsWith('__Host-session=;')).toBe(true);

      // Both enforce Path=/, HttpOnly, SameSite=Lax, Secure
      for (const attr of ['Path=/', 'HttpOnly', 'SameSite=Lax', 'Secure']) {
        expect(sessionCookie).toContain(attr);
        expect(clearCookie).toContain(attr);
      }

      expect(clearCookie).toContain('Max-Age=0');
      expect(clearCookie).toContain('Expires=Thu, 01 Jan 1970 00:00:00 GMT');
      expect(sessionCookie).not.toContain('Domain=');
      expect(clearCookie).not.toContain('Domain=');
    });

    it('development fails closed if __Host- prefix is used with secure: false', () => {
      expect(
        () =>
          new SessionService({
            pool: dummyPool,
            environment: 'development',
            cookieOptions: { cookieName: '__Host-dev', secure: false },
          }),
      ).toThrow(SessionError);
    });

    it('extracts session secret from Cookie header string', () => {
      const service = new SessionService({
        pool: dummyPool,
        environment: 'production',
      });

      const cookieHeader =
        'theme=dark; __Host-session=valid-secret-43-chars-long-example-1234; other=1';
      const extracted = service.extractSessionSecretFromCookieHeader(cookieHeader);
      expect(extracted).toBe('valid-secret-43-chars-long-example-1234');
    });

    it('returns null if session cookie is absent from Cookie header', () => {
      const service = new SessionService({
        pool: dummyPool,
        environment: 'production',
      });

      expect(service.extractSessionSecretFromCookieHeader('theme=dark; other=1')).toBeNull();
      expect(service.extractSessionSecretFromCookieHeader('')).toBeNull();
      expect(service.extractSessionSecretFromCookieHeader(undefined)).toBeNull();
    });
  });
});
