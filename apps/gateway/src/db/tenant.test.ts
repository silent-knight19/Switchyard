import { describe, expect, it } from 'vitest';
import {
  InvalidTenantIdError,
  TenantTransactionError,
  assertNoTransactionControl,
  getActiveTenantContext,
  stripCommentsAndLiterals,
  stripLeadingCommentsAndWhitespace,
  validateTenantId,
} from './tenant.js';

describe('SW-1.4.1 tenant helper unit tests: input validation & context tracking', () => {
  describe('validateTenantId', () => {
    it('accepts valid canonical UUID strings', () => {
      expect(validateTenantId('a0000001-0000-4000-8000-000000000001')).toBe(
        'a0000001-0000-4000-8000-000000000001',
      );
      expect(validateTenantId('FDF80FBA-E8B5-4305-FA70-4A619C62FAF0')).toBe(
        'FDF80FBA-E8B5-4305-FA70-4A619C62FAF0',
      );
      expect(validateTenantId('  a0000001-0000-4000-8000-000000000001  ')).toBe(
        'a0000001-0000-4000-8000-000000000001',
      );
    });

    it('rejects non-string types fail-closed', () => {
      expect(() => validateTenantId(undefined)).toThrow(InvalidTenantIdError);
      expect(() => validateTenantId(undefined)).toThrow(/expected string, got undefined/);

      expect(() => validateTenantId(null)).toThrow(InvalidTenantIdError);
      expect(() => validateTenantId(null)).toThrow(/expected string, got null/);

      expect(() => validateTenantId(12345)).toThrow(InvalidTenantIdError);
      expect(() => validateTenantId(12345)).toThrow(/expected string, got number/);

      expect(() => validateTenantId({})).toThrow(InvalidTenantIdError);
      expect(() => validateTenantId({})).toThrow(/expected string, got object/);

      expect(() => validateTenantId(['a0000001-0000-4000-8000-000000000001'])).toThrow(
        InvalidTenantIdError,
      );
    });

    it('rejects empty and whitespace-only strings fail-closed', () => {
      expect(() => validateTenantId('')).toThrow(InvalidTenantIdError);
      expect(() => validateTenantId('')).toThrow(/empty or whitespace-only/);

      expect(() => validateTenantId('   ')).toThrow(InvalidTenantIdError);
      expect(() => validateTenantId('   ')).toThrow(/empty or whitespace-only/);

      expect(() => validateTenantId('\t\n')).toThrow(InvalidTenantIdError);
    });

    it('rejects malformed UUID strings fail-closed', () => {
      expect(() => validateTenantId('not-a-uuid')).toThrow(InvalidTenantIdError);
      expect(() => validateTenantId('not-a-uuid')).toThrow(/malformed UUID/);

      // Invalid character (g)
      expect(() => validateTenantId('g0000001-0000-4000-8000-000000000001')).toThrow(
        InvalidTenantIdError,
      );

      // Wrong length
      expect(() => validateTenantId('a0000001-0000-4000-8000-00000000000')).toThrow(
        InvalidTenantIdError,
      );
      expect(() => validateTenantId('a0000001-0000-4000-8000-0000000000001')).toThrow(
        InvalidTenantIdError,
      );

      // Missing dashes
      expect(() => validateTenantId('a0000001000040008000000000000001')).toThrow(
        InvalidTenantIdError,
      );

      // SQL injection attempt string
      expect(() => validateTenantId("'; DROP TABLE organizations; --")).toThrow(
        InvalidTenantIdError,
      );
    });
  });

  describe('stripCommentsAndLiterals', () => {
    it('strips line comments and block comments without altering outer structure', () => {
      expect(stripCommentsAndLiterals('SELECT 1; -- line comment\nSELECT 2;').trim()).toBe(
        'SELECT 1;  \nSELECT 2;',
      );
      expect(stripCommentsAndLiterals('SELECT /* block comment */ 1;').trim()).toBe('SELECT   1;');
      expect(stripCommentsAndLiterals('SELECT 1; /* multi\nline\ncomment */').trim()).toBe(
        'SELECT 1;',
      );
    });

    it('strips single-quoted string literals including escaped quotes', () => {
      expect(stripCommentsAndLiterals("SELECT 'hello world';").trim()).toBe('SELECT  ;');
      expect(stripCommentsAndLiterals("SELECT 'hello ''nested'' world';").trim()).toBe('SELECT  ;');
      expect(stripCommentsAndLiterals("SELECT E'hello \\'escaped\\' world';").trim()).toBe(
        'SELECT  ;',
      );
    });

    it('DB-30: respects standard_conforming_strings=on where backslash does not escape quotes in standard literals', () => {
      // In standard SQL ('...'), a backslash is a literal character, not an escape.
      // Therefore, 'a\' ends at the quote, exposing the following COMMIT statement.
      const sql = "SELECT 'a\\'; COMMIT; SELECT 'b'";
      const stripped = stripCommentsAndLiterals(sql);
      expect(stripped).toContain('COMMIT');
    });

    it('strips dollar-quoted string literals', () => {
      expect(stripCommentsAndLiterals('SELECT $$hello world$$;').trim()).toBe('SELECT  ;');
      expect(stripCommentsAndLiterals('SELECT $tag$hello world$tag$;').trim()).toBe('SELECT  ;');
    });
  });

  describe('stripLeadingCommentsAndWhitespace', () => {
    it('strips leading whitespace without altering body', () => {
      expect(stripLeadingCommentsAndWhitespace('   \n\t  SELECT 1')).toBe('SELECT 1');
    });

    it('strips leading line comments', () => {
      expect(stripLeadingCommentsAndWhitespace('-- line comment\nCOMMIT')).toBe('COMMIT');
    });

    it('strips leading block comments including nested block comments', () => {
      expect(stripLeadingCommentsAndWhitespace('/* block */ ROLLBACK')).toBe('ROLLBACK');
      expect(stripLeadingCommentsAndWhitespace('/* outer /* inner */ */ BEGIN')).toBe('BEGIN');
      expect(stripLeadingCommentsAndWhitespace('/* comment */ -- line\n   START TRANSACTION')).toBe(
        'START TRANSACTION',
      );
    });

    it('does not strip non-leading comments or strings', () => {
      expect(stripLeadingCommentsAndWhitespace("SELECT '/* not comment */'")).toBe(
        "SELECT '/* not comment */'",
      );
    });
  });

  describe('assertNoTransactionControl (DB-27)', () => {
    it('rejects standalone transaction control statements', () => {
      expect(() => assertNoTransactionControl('COMMIT')).toThrow(TenantTransactionError);
      expect(() => assertNoTransactionControl('commit;')).toThrow(TenantTransactionError);
      expect(() => assertNoTransactionControl('ROLLBACK')).toThrow(TenantTransactionError);
      expect(() => assertNoTransactionControl('rollback;')).toThrow(TenantTransactionError);
      expect(() => assertNoTransactionControl('BEGIN')).toThrow(TenantTransactionError);
      expect(() => assertNoTransactionControl('begin;')).toThrow(TenantTransactionError);
      expect(() => assertNoTransactionControl('START TRANSACTION')).toThrow(TenantTransactionError);
      expect(() => assertNoTransactionControl('END')).toThrow(TenantTransactionError);
      expect(() => assertNoTransactionControl('ABORT')).toThrow(TenantTransactionError);
      expect(() => assertNoTransactionControl('SAVEPOINT sp1')).toThrow(TenantTransactionError);
      expect(() => assertNoTransactionControl('RELEASE SAVEPOINT sp1')).toThrow(
        TenantTransactionError,
      );
      expect(() => assertNoTransactionControl('ROLLBACK TO sp1')).toThrow(TenantTransactionError);
      expect(() => assertNoTransactionControl('ROLLBACK TO SAVEPOINT sp1')).toThrow(
        TenantTransactionError,
      );
    });

    it('rejects multi-statement transaction control evasion', () => {
      expect(() => assertNoTransactionControl('SELECT 1; COMMIT;')).toThrow(TenantTransactionError);
      expect(() => assertNoTransactionControl('INSERT INTO foo VALUES (1); ROLLBACK;')).toThrow(
        TenantTransactionError,
      );
      expect(() => assertNoTransactionControl('SELECT 1; BEGIN; SELECT 2;')).toThrow(
        TenantTransactionError,
      );
      expect(() => assertNoTransactionControl('SELECT 1; START TRANSACTION;')).toThrow(
        TenantTransactionError,
      );
      expect(() => assertNoTransactionControl("SELECT 'a\\'; COMMIT; SELECT 'b'")).toThrow(
        TenantTransactionError,
      );
    });

    it('rejects comment-wrapped transaction control evasion', () => {
      expect(() => assertNoTransactionControl('/* comment */ COMMIT;')).toThrow(
        TenantTransactionError,
      );
      expect(() => assertNoTransactionControl('-- comment\nROLLBACK;')).toThrow(
        TenantTransactionError,
      );
      expect(() => assertNoTransactionControl('SELECT 1; /* sneaky */ COMMIT;')).toThrow(
        TenantTransactionError,
      );
    });

    it('permits legitimate queries containing transaction words inside literals', () => {
      expect(() =>
        assertNoTransactionControl("SELECT * FROM organizations WHERE name = 'COMMIT'"),
      ).not.toThrow();
      expect(() =>
        assertNoTransactionControl("SELECT * FROM organizations WHERE name = 'foo; COMMIT; bar'"),
      ).not.toThrow();
      expect(() =>
        assertNoTransactionControl(
          'SELECT * FROM organizations WHERE name = $$foo; ROLLBACK; bar$$',
        ),
      ).not.toThrow();
      expect(() =>
        assertNoTransactionControl(
          "UPDATE users SET role = 'member' WHERE email = 'begin@example.com'",
        ),
      ).not.toThrow();
    });

    it('permits legitimate single-statement parameterized queries', () => {
      expect(() =>
        assertNoTransactionControl('SELECT * FROM users WHERE org_id = $1 AND role = $2'),
      ).not.toThrow();
      expect(() =>
        assertNoTransactionControl(
          'INSERT INTO gateway_requests (request_id, org_id) VALUES ($1, $2)',
        ),
      ).not.toThrow();
    });
  });

  describe('getActiveTenantContext', () => {
    it('returns undefined when called outside withTenant', () => {
      expect(getActiveTenantContext()).toBeUndefined();
    });
  });

  describe('TenantTransactionError', () => {
    it('preserves cause and rollbackError', () => {
      const cause = new Error('Original cause');
      const rollbackErr = new Error('Rollback failed');
      const err = new TenantTransactionError('Transaction error', {
        cause,
        rollbackError: rollbackErr,
      });

      expect(err.name).toBe('TenantTransactionError');
      expect(err.message).toBe('Transaction error');
      expect(err.cause).toBe(cause);
      expect(err.rollbackError).toBe(rollbackErr);
    });
  });
});
