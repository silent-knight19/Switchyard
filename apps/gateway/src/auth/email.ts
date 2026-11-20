import { AuthenticationError } from './types.js';

/**
 * Regular expression strictly matching email address structure for Switchyard canonical emails:
 * Exactly one '@' symbol, non-whitespace non-@ characters before and after.
 * Conforms identically to the PostgreSQL regular expression in migrations 0010 and 0011:
 * `^[^@\s]+@[^@\s]+$`
 */
const CANONICAL_EMAIL_REGEX = /^[^@\s]+@[^@\s]+$/;

/**
 * Maximum email length supported by database schema (users.email_normalized).
 */
export const MAX_EMAIL_LENGTH = 255;

/**
 * Checks whether the given input is already a canonical normalized email:
 * 1. Primitive string.
 * 2. Non-empty and length <= 255 characters.
 * 3. Exact trimmed representation (no leading or trailing whitespace).
 * 4. Exact lowercase representation.
 * 5. Contains exactly one '@' character with non-whitespace characters before and after.
 */
export function isCanonicalEmail(email: unknown): email is string {
  if (typeof email !== 'string') {
    return false;
  }

  const len = email.length;
  if (len === 0 || len > MAX_EMAIL_LENGTH) {
    return false;
  }

  if (email !== email.trim()) {
    return false;
  }

  if (email !== email.toLowerCase()) {
    return false;
  }

  return CANONICAL_EMAIL_REGEX.test(email);
}

/**
 * Validates and normalizes an input email for login identification:
 * 1. Checks that input is a primitive string.
 * 2. Trims leading and trailing whitespace.
 * 3. Transforms to lowercase.
 * 4. Asserts length is between 1 and 255 characters.
 * 5. Asserts structure conforms to single '@' without whitespace.
 *
 * Throws AuthenticationError with 'INVALID_INPUT' on malformed or non-string input.
 */
export function normalizeEmail(rawEmail: unknown): string {
  if (typeof rawEmail !== 'string') {
    throw new AuthenticationError('INVALID_INPUT', 'Email must be a string');
  }

  const trimmed = rawEmail.trim();
  if (trimmed.length === 0) {
    throw new AuthenticationError('INVALID_INPUT', 'Email must not be empty');
  }

  if (trimmed.length > MAX_EMAIL_LENGTH) {
    throw new AuthenticationError(
      'INVALID_INPUT',
      `Email length (${trimmed.length}) exceeds maximum allowed length of ${MAX_EMAIL_LENGTH} characters`,
    );
  }

  const lowercased = trimmed.toLowerCase();
  if (!CANONICAL_EMAIL_REGEX.test(lowercased)) {
    throw new AuthenticationError(
      'INVALID_INPUT',
      'Email must have a valid format with exactly one "@" and no whitespace',
    );
  }

  return lowercased;
}

/**
 * Asserts that the provided email is already strictly canonical.
 * Used for bootstrap and schema-level validation where non-canonical inputs must be rejected outright.
 */
export function assertCanonicalEmail(email: unknown): string {
  if (!isCanonicalEmail(email)) {
    throw new AuthenticationError(
      'INVALID_INPUT',
      'Email must be strictly canonical: trimmed, lowercase, valid format, and at most 255 characters',
    );
  }
  return email;
}
