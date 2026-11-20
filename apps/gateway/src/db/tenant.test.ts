import { describe, expect, it } from 'vitest';
import {
  InvalidTenantIdError,
  TenantTransactionError,
  getActiveTenantContext,
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
