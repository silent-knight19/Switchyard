import type pg from 'pg';
import { describe, expect, it } from 'vitest';
import { decodeSessionSecret, hashSecret, SessionService } from './session.js';
import { SessionError } from './types.js';

describe('SW-1.5.2: Session Cookie & Secret Encoding', () => {
  describe('decodeSessionSecret', () => {
    it('accepts and decodes a 43-character base64url encoded 32-byte secret', () => {
      // 32 zero bytes in base64url is 43 chars (with padding omitted per standard)
      const secret = 'A'.repeat(43);
      const buf = decodeSessionSecret(secret);
      expect(buf).toBeInstanceOf(Buffer);
      expect(buf.length).toBe(32);
    });

    it('rejects secrets with invalid length', () => {
      expect(() => decodeSessionSecret('A'.repeat(42))).toThrow(SessionError);
      expect(() => decodeSessionSecret('A'.repeat(44))).toThrow(SessionError);
      expect(() => decodeSessionSecret('')).toThrow(SessionError);
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

  describe('SessionService Cookie Formatting & Parsing', () => {
    it('generates production cookie with __Host- prefix and required security flags', () => {
      const dummyPool = {} as unknown as pg.Pool;
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

    it('generates development cookie with isolated name when non-secure', () => {
      const dummyPool = {} as unknown as pg.Pool;
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

    it('generates expired clear-cookie header with Max-Age=0', () => {
      const dummyPool = {} as unknown as pg.Pool;
      const service = new SessionService({
        pool: dummyPool,
        cookieOptions: { isProduction: true },
      });

      const clearStr = service.createClearSessionCookie();
      expect(clearStr).toContain('__Host-session=;');
      expect(clearStr).toContain('Max-Age=0');
      expect(clearStr).toContain('Expires=Thu, 01 Jan 1970 00:00:00 GMT');
      expect(clearStr).toContain('Secure');
    });

    it('extracts session secret from Cookie header string', () => {
      const dummyPool = {} as unknown as pg.Pool;
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
      const dummyPool = {} as unknown as pg.Pool;
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
