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

  describe('SessionService Cookie Formatting & Parsing (AUTH-02)', () => {
    const dummyPool = {} as unknown as pg.Pool;

    it('production defaults produce secure cookie with __Host- prefix and required security flags', () => {
      const service = new SessionService({
        pool: dummyPool,
        cookieOptions: { isProduction: true },
      });

      expect(service.getCookieName()).toBe('__Host-session');

      const cookieStr = service.createSessionCookie('my-opaque-session-secret-12345');
      expect(cookieStr).toContain('__Host-session=my-opaque-session-secret-12345');
      expect(cookieStr).toContain('Path=/');
      expect(cookieStr).toContain('HttpOnly');
      expect(cookieStr).toContain('SameSite=Lax');
      expect(cookieStr).toContain('Secure');
      expect(cookieStr).not.toContain('Domain=');
    });

    it('fails closed when production configuration attempts secure=false (AUTH-02 downgrade prevention)', () => {
      expect(
        () =>
          new SessionService({
            pool: dummyPool,
            cookieOptions: { isProduction: true, secure: false },
          }),
      ).toThrow(SessionError);

      try {
        new SessionService({
          pool: dummyPool,
          cookieOptions: { isProduction: true, secure: false },
        });
      } catch (err) {
        expect(err).toBeInstanceOf(SessionError);
        expect((err as SessionError).reason).toBe('CONFIGURATION_ERROR');
        expect((err as SessionError).message).toContain('Insecure session cookies');
      }
    });

    it('fails closed when production configuration attempts an arbitrary cookie name', () => {
      expect(
        () =>
          new SessionService({
            pool: dummyPool,
            cookieOptions: { isProduction: true, cookieName: 'arbitrary_insecure_name' },
          }),
      ).toThrow(SessionError);

      try {
        new SessionService({
          pool: dummyPool,
          cookieOptions: { isProduction: true, cookieName: 'arbitrary_insecure_name' },
        });
      } catch (err) {
        expect(err).toBeInstanceOf(SessionError);
        expect((err as SessionError).reason).toBe('CONFIGURATION_ERROR');
        expect((err as SessionError).message).toContain('must use the "__Host-session" name');
      }
    });

    it('development produces the explicitly documented development cookie', () => {
      const service = new SessionService({
        pool: dummyPool,
        cookieOptions: { isProduction: false, secure: false },
      });

      expect(service.getCookieName()).toBe('switchyard_session');

      const cookieStr = service.createSessionCookie('my-dev-secret');
      expect(cookieStr).toContain('switchyard_session=my-dev-secret');
      expect(cookieStr).toContain('Path=/');
      expect(cookieStr).toContain('HttpOnly');
      expect(cookieStr).toContain('SameSite=Lax');
      expect(cookieStr).not.toContain('Secure');
    });

    it('development settings cannot affect a production instance', () => {
      const prodService = new SessionService({
        pool: dummyPool,
        cookieOptions: { isProduction: true },
      });
      const devService = new SessionService({
        pool: dummyPool,
        cookieOptions: { isProduction: false },
      });

      expect(prodService.getCookieName()).toBe('__Host-session');
      expect(devService.getCookieName()).toBe('switchyard_session');
    });

    it('development fails closed if __Host- prefix is used with secure: false', () => {
      expect(
        () =>
          new SessionService({
            pool: dummyPool,
            cookieOptions: { isProduction: false, cookieName: '__Host-dev', secure: false },
          }),
      ).toThrow(SessionError);
    });

    it('session cookie and clear-cookie use consistent names and required attributes', () => {
      const service = new SessionService({
        pool: dummyPool,
        cookieOptions: { isProduction: true },
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
    });

    it('extracts session secret from Cookie header string', () => {
      const service = new SessionService({
        pool: dummyPool,
        cookieOptions: { isProduction: true },
      });

      const cookieHeader =
        'theme=dark; __Host-session=valid-secret-43-chars-long-example-1234; other=1';
      const extracted = service.extractSessionSecretFromCookieHeader(cookieHeader);
      expect(extracted).toBe('valid-secret-43-chars-long-example-1234');
    });

    it('returns null if session cookie is absent from Cookie header', () => {
      const service = new SessionService({
        pool: dummyPool,
        cookieOptions: { isProduction: true },
      });

      expect(service.extractSessionSecretFromCookieHeader('theme=dark; other=1')).toBeNull();
      expect(service.extractSessionSecretFromCookieHeader('')).toBeNull();
      expect(service.extractSessionSecretFromCookieHeader(undefined)).toBeNull();
    });
  });
});
