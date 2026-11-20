import { describe, expect, it } from 'vitest';
import { assertCanonicalEmail, isCanonicalEmail, normalizeEmail } from './email.js';
import { AuthenticationError } from './types.js';

describe('SW-1.5.1: Canonical Email Validation and Normalization', () => {
  describe('isCanonicalEmail', () => {
    it('accepts canonical lowercase trimmed emails', () => {
      expect(isCanonicalEmail('admin@example.com')).toBe(true);
      expect(isCanonicalEmail('user.name+tag@sub.domain.org')).toBe(true);
      expect(isCanonicalEmail('a@b.co')).toBe(true);
    });

    it('rejects mixed-case emails', () => {
      expect(isCanonicalEmail('Admin@example.com')).toBe(false);
      expect(isCanonicalEmail('user@EXAMPLE.COM')).toBe(false);
      expect(isCanonicalEmail('User@Example.Com')).toBe(false);
    });

    it('rejects leading and trailing whitespace', () => {
      expect(isCanonicalEmail(' admin@example.com')).toBe(false);
      expect(isCanonicalEmail('admin@example.com ')).toBe(false);
      expect(isCanonicalEmail('\tadmin@example.com\n')).toBe(false);
    });

    it('rejects internal whitespace', () => {
      expect(isCanonicalEmail('admin @example.com')).toBe(false);
      expect(isCanonicalEmail('admin@ example.com')).toBe(false);
    });

    it('rejects emails with missing or multiple "@" symbols', () => {
      expect(isCanonicalEmail('adminexample.com')).toBe(false);
      expect(isCanonicalEmail('admin@@example.com')).toBe(false);
      expect(isCanonicalEmail('admin@sub@example.com')).toBe(false);
    });

    it('rejects empty and oversized emails', () => {
      expect(isCanonicalEmail('')).toBe(false);
      const longEmail = `${'a'.repeat(244)}@example.com`; // 256 chars
      expect(longEmail.length).toBe(256);
      expect(isCanonicalEmail(longEmail)).toBe(false);
    });

    it('rejects non-string inputs', () => {
      expect(isCanonicalEmail(null)).toBe(false);
      expect(isCanonicalEmail(undefined)).toBe(false);
      expect(isCanonicalEmail(123)).toBe(false);
      expect(isCanonicalEmail({})).toBe(false);
    });
  });

  describe('normalizeEmail', () => {
    it('normalizes mixed-case and untrimmed valid emails', () => {
      expect(normalizeEmail('  Admin@Example.COM  ')).toBe('admin@example.com');
      expect(normalizeEmail('USER+TAG@Sub.Domain.ORG')).toBe('user+tag@sub.domain.org');
    });

    it('throws AuthenticationError with INVALID_INPUT for non-string input', () => {
      expect(() => normalizeEmail(null)).toThrow(AuthenticationError);
      expect(() => normalizeEmail(undefined)).toThrow(AuthenticationError);
      try {
        normalizeEmail(123);
      } catch (err) {
        expect(err).toBeInstanceOf(AuthenticationError);
        expect((err as AuthenticationError).reason).toBe('INVALID_INPUT');
      }
    });

    it('throws AuthenticationError with INVALID_INPUT for empty string', () => {
      expect(() => normalizeEmail('   ')).toThrow(AuthenticationError);
    });

    it('throws AuthenticationError with INVALID_INPUT for oversized string', () => {
      const longEmail = `${'a'.repeat(250)}@test.com`;
      expect(() => normalizeEmail(longEmail)).toThrow(AuthenticationError);
    });

    it('throws AuthenticationError with INVALID_INPUT for missing or multiple "@"', () => {
      expect(() => normalizeEmail('invalidemail.com')).toThrow(AuthenticationError);
      expect(() => normalizeEmail('user@@domain.com')).toThrow(AuthenticationError);
    });

    it('handles SQL-injection shaped strings safely by rejecting or normalizing structure', () => {
      expect(() => normalizeEmail("' OR '1'='1")).toThrow(AuthenticationError);
      expect(() => normalizeEmail("admin@example.com'; DROP TABLE users;--")).toThrow(
        AuthenticationError,
      );
    });
  });

  describe('assertCanonicalEmail', () => {
    it('returns the canonical email when already canonical', () => {
      expect(assertCanonicalEmail('admin@alpha.com')).toBe('admin@alpha.com');
    });

    it('rejects mixed-case input without silently normalizing', () => {
      expect(() => assertCanonicalEmail('Admin@alpha.com')).toThrow(AuthenticationError);
    });

    it('rejects untrimmed input without silently normalizing', () => {
      expect(() => assertCanonicalEmail(' admin@alpha.com ')).toThrow(AuthenticationError);
    });
  });
});
