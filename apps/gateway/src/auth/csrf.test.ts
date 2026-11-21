import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decodeCsrfToken, hashCsrfToken, verifyCsrfTokenHash, validateOrigin } from './csrf.js';
import { CsrfError } from './types.js';

describe('SW-1.5.3: CSRF Token & Origin Verification Unit Test Suite', () => {
  describe('CSRF Token Encoding & Decoding (decodeCsrfToken)', () => {
    it('accepts and decodes a canonical 43-character base64url 32-byte token', () => {
      const rawBytes = crypto.randomBytes(32);
      const canonicalToken = rawBytes.toString('base64url');

      expect(canonicalToken.length).toBe(43);
      const decoded = decodeCsrfToken(canonicalToken);
      expect(decoded).toBeInstanceOf(Buffer);
      expect(decoded.length).toBe(32);
      expect(decoded.equals(rawBytes)).toBe(true);
    });

    it('round-trips 100 randomly generated 32-byte tokens without loss', () => {
      for (let i = 0; i < 100; i++) {
        const bytes = crypto.randomBytes(32);
        const token = bytes.toString('base64url');
        const decoded = decodeCsrfToken(token);
        expect(decoded.equals(bytes)).toBe(true);
        expect(decoded.toString('base64url')).toBe(token);
      }
    });

    it('rejects missing or undefined tokens', () => {
      expect(() => decodeCsrfToken(undefined)).toThrow(CsrfError);
      expect(() => decodeCsrfToken(null)).toThrow(CsrfError);
      try {
        decodeCsrfToken(undefined);
      } catch (err) {
        expect(err).toBeInstanceOf(CsrfError);
        expect((err as CsrfError).reason).toBe('MISSING_TOKEN');
      }
    });

    it('rejects empty string token', () => {
      expect(() => decodeCsrfToken('')).toThrow(CsrfError);
      try {
        decodeCsrfToken('');
      } catch (err) {
        expect(err).toBeInstanceOf(CsrfError);
        expect((err as CsrfError).reason).toBe('MISSING_TOKEN');
      }
    });

    it('rejects tokens with invalid length (too short or too long)', () => {
      const shortToken = 'A'.repeat(42);
      const longToken = 'A'.repeat(44);

      expect(() => decodeCsrfToken(shortToken)).toThrow(CsrfError);
      expect(() => decodeCsrfToken(longToken)).toThrow(CsrfError);

      try {
        decodeCsrfToken(shortToken);
      } catch (err) {
        expect(err).toBeInstanceOf(CsrfError);
        expect((err as CsrfError).reason).toBe('MALFORMED_TOKEN');
        expect((err as CsrfError).message).toContain('expected exactly 43');
      }
    });

    it('rejects leading, trailing, or embedded whitespace without trimming', () => {
      const valid = crypto.randomBytes(32).toString('base64url');
      expect(() => decodeCsrfToken(` ${valid}`)).toThrow(CsrfError);
      expect(() => decodeCsrfToken(`${valid} `)).toThrow(CsrfError);
      expect(() => decodeCsrfToken(`${valid.slice(0, 20)} ${valid.slice(21)}`)).toThrow(CsrfError);
    });

    it('rejects standard base64 characters (+, /) and padding (=)', () => {
      const tokenWithPlus = 'A'.repeat(42) + '+';
      const tokenWithSlash = 'A'.repeat(42) + '/';
      const tokenWithPadding = 'A'.repeat(42) + '=';

      expect(() => decodeCsrfToken(tokenWithPlus)).toThrow(CsrfError);
      expect(() => decodeCsrfToken(tokenWithSlash)).toThrow(CsrfError);
      expect(() => decodeCsrfToken(tokenWithPadding)).toThrow(CsrfError);
    });

    it('rejects noncanonical trailing pad bits', () => {
      // In 43-character base64url encoding of 32 bytes (256 bits):
      // 42 chars * 6 bits = 252 bits.
      // 43rd char contributes 4 data bits and 2 pad bits.
      // The 2 pad bits MUST be zero.
      // 'A' represents 0b000000 (valid zero pad bits).
      // 'B' represents 0b000001 (non-zero pad bit).
      const valid = 'A'.repeat(42) + 'A';
      const noncanonical = 'A'.repeat(42) + 'B';

      expect(decodeCsrfToken(valid).length).toBe(32);
      expect(() => decodeCsrfToken(noncanonical)).toThrow(CsrfError);
      try {
        decodeCsrfToken(noncanonical);
      } catch (err) {
        expect(err).toBeInstanceOf(CsrfError);
        expect((err as CsrfError).reason).toBe('MALFORMED_TOKEN');
        expect((err as CsrfError).message).toContain('noncanonical base64url');
      }
    });

    it('rejects duplicate X-CSRF-Token headers represented as arrays', () => {
      const validToken = crypto.randomBytes(32).toString('base64url');
      expect(() => decodeCsrfToken([validToken, validToken])).toThrow(CsrfError);
      try {
        decodeCsrfToken([validToken, validToken]);
      } catch (err) {
        expect(err).toBeInstanceOf(CsrfError);
        expect((err as CsrfError).reason).toBe('MALFORMED_TOKEN');
        expect((err as CsrfError).message).toContain(
          'Multiple X-CSRF-Token headers are not allowed',
        );
      }
    });

    it('rejects comma-combined token values', () => {
      const token1 = crypto.randomBytes(32).toString('base64url');
      const token2 = crypto.randomBytes(32).toString('base64url');
      expect(() => decodeCsrfToken(`${token1}, ${token2}`)).toThrow(CsrfError);
    });

    it('rejects non-string primitives', () => {
      expect(() => decodeCsrfToken(12345)).toThrow(CsrfError);
      expect(() => decodeCsrfToken({})).toThrow(CsrfError);
      expect(() => decodeCsrfToken(true)).toThrow(CsrfError);
    });
  });

  describe('Constant-Time Hash Verification (verifyCsrfTokenHash)', () => {
    it('returns true when candidate token matches stored SHA-256 verifier', () => {
      const tokenBytes = crypto.randomBytes(32);
      const storedHash = hashCsrfToken(tokenBytes);

      expect(verifyCsrfTokenHash(tokenBytes, storedHash)).toBe(true);
    });

    it('returns false for mismatched or forged token', () => {
      const genuineToken = crypto.randomBytes(32);
      const forgedToken = crypto.randomBytes(32);
      const storedHash = hashCsrfToken(genuineToken);

      expect(verifyCsrfTokenHash(forgedToken, storedHash)).toBe(false);
    });

    it('returns false when token bytes or verifier hash length is invalid (not 32 bytes)', () => {
      const validToken = crypto.randomBytes(32);
      const validHash = hashCsrfToken(validToken);

      const shortToken = crypto.randomBytes(31);
      const longToken = crypto.randomBytes(33);
      const shortHash = crypto.randomBytes(31);
      const longHash = crypto.randomBytes(33);

      expect(verifyCsrfTokenHash(shortToken, validHash)).toBe(false);
      expect(verifyCsrfTokenHash(longToken, validHash)).toBe(false);
      expect(verifyCsrfTokenHash(validToken, shortHash)).toBe(false);
      expect(verifyCsrfTokenHash(validToken, longHash)).toBe(false);
    });

    it('returns false if arguments are not Buffer instances', () => {
      const validToken = crypto.randomBytes(32);
      const validHash = hashCsrfToken(validToken);

      expect(verifyCsrfTokenHash('not a buffer' as unknown as Buffer, validHash)).toBe(false);
      expect(verifyCsrfTokenHash(validToken, 'not a buffer' as unknown as Buffer)).toBe(false);
    });
  });

  describe('Strict Origin Verification (validateOrigin)', () => {
    const PROD_ALLOWED = 'https://app.switchyard.internal';
    const DEV_ALLOWED = 'http://127.0.0.1:3000';

    it('accepts exact production HTTPS origin', () => {
      const res = validateOrigin('https://app.switchyard.internal', PROD_ALLOWED);
      expect(res.valid).toBe(true);
      expect(res.reason).toBeUndefined();
    });

    it('accepts exact development HTTP loopback origin', () => {
      const res = validateOrigin('http://127.0.0.1:3000', DEV_ALLOWED);
      expect(res.valid).toBe(true);
      expect(res.reason).toBeUndefined();
    });

    it('rejects missing or undefined Origin', () => {
      expect(validateOrigin(undefined, PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'MISSING_ORIGIN',
      });
      expect(validateOrigin(null, PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'MISSING_ORIGIN',
      });
    });

    it('rejects empty Origin string', () => {
      expect(validateOrigin('', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'EMPTY_ORIGIN',
      });
      expect(validateOrigin('   ', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'EMPTY_ORIGIN',
      });
    });

    it('rejects "null" Origin string', () => {
      expect(validateOrigin('null', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'DISALLOWED_PROTOCOL',
      });
    });

    it('rejects wrong protocol (http instead of https)', () => {
      expect(validateOrigin('http://app.switchyard.internal', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'ORIGIN_MISMATCH',
      });
    });

    it('rejects wrong hostname', () => {
      expect(validateOrigin('https://evil.internal', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'ORIGIN_MISMATCH',
      });
    });

    it('rejects wrong port', () => {
      expect(validateOrigin('https://app.switchyard.internal:8443', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'ORIGIN_MISMATCH',
      });
      expect(validateOrigin('http://127.0.0.1:3001', DEV_ALLOWED)).toEqual({
        valid: false,
        reason: 'ORIGIN_MISMATCH',
      });
    });

    it('rejects subdomain prefix and suffix attacks', () => {
      // Attacker owns domain ending with target
      expect(validateOrigin('https://app.switchyard.internal.attacker.com', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'ORIGIN_MISMATCH',
      });
      // Attacker prepends
      expect(validateOrigin('https://evilapp.switchyard.internal', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'ORIGIN_MISMATCH',
      });
      // Subdomain when top-level expected
      expect(validateOrigin('https://sub.app.switchyard.internal', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'ORIGIN_MISMATCH',
      });
    });

    it('rejects multiple Origin headers (array from Node HTTP parser)', () => {
      const multiple = ['https://app.switchyard.internal', 'https://app.switchyard.internal'];
      expect(validateOrigin(multiple, PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'MULTIPLE_ORIGINS',
      });
    });

    it('rejects comma-separated Origin lists', () => {
      expect(
        validateOrigin('https://app.switchyard.internal, https://evil.com', PROD_ALLOWED),
      ).toEqual({
        valid: false,
        reason: 'MULTIPLE_ORIGINS',
      });
    });

    it('rejects origin containing trailing slash', () => {
      expect(validateOrigin('https://app.switchyard.internal/', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'MALFORMED_ORIGIN',
      });
    });

    it('rejects origin containing paths, query parameters, fragments, or user credentials', () => {
      expect(validateOrigin('https://app.switchyard.internal/path', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'MALFORMED_ORIGIN',
      });

      expect(validateOrigin('https://app.switchyard.internal?param=1', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'MALFORMED_ORIGIN',
      });

      expect(validateOrigin('https://app.switchyard.internal#hash', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'MALFORMED_ORIGIN',
      });

      expect(validateOrigin('https://user:pass@app.switchyard.internal', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'MALFORMED_ORIGIN',
      });
    });

    it('rejects malformed and non-URL origin strings', () => {
      expect(validateOrigin('not-a-valid-url', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'MALFORMED_ORIGIN',
      });
      expect(validateOrigin('ftp://app.switchyard.internal', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'DISALLOWED_PROTOCOL',
      });
      expect(validateOrigin('javascript:alert(1)', PROD_ALLOWED)).toEqual({
        valid: false,
        reason: 'DISALLOWED_PROTOCOL',
      });
    });

    it('fails closed when allowed origin configuration itself is invalid', () => {
      expect(validateOrigin('https://app.switchyard.internal', 'invalid-allowed-config')).toEqual({
        valid: false,
        reason: 'MALFORMED_ORIGIN',
      });
    });
  });
});
