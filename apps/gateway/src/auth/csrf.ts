import crypto from 'node:crypto';
import type { FastifyReply, FastifyRequest, FastifyInstance } from 'fastify';
import type { SessionService } from './session.js';
import { CsrfError, SessionError, type OriginValidationResult } from './types.js';

export const PROTECTED_HTTP_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Validates whether an opaque CSRF token string is structurally valid:
 * Exact canonical unpadded base64url representation of a 32-byte secret (256 bits).
 * Rejects whitespace, non-base64url characters, padding, and noncanonical pad bits.
 */
export function decodeCsrfToken(rawToken: unknown): Buffer {
  if (Array.isArray(rawToken)) {
    throw new CsrfError('MALFORMED_TOKEN', 'Multiple X-CSRF-Token headers are not allowed');
  }

  if (rawToken === null || rawToken === undefined) {
    throw new CsrfError('MISSING_TOKEN', 'CSRF token is missing');
  }

  if (typeof rawToken !== 'string') {
    throw new CsrfError('MALFORMED_TOKEN', 'CSRF token must be a string');
  }

  if (rawToken.length === 0) {
    throw new CsrfError('MISSING_TOKEN', 'CSRF token must not be empty');
  }

  // Exact length constraint: 32 bytes in unpadded base64url is exactly 43 characters (no trimming)
  if (rawToken.length !== 43) {
    throw new CsrfError(
      'MALFORMED_TOKEN',
      `CSRF token length (${rawToken.length}) is invalid; expected exactly 43 base64url characters`,
    );
  }

  // Strict unpadded base64url alphabet (no whitespace, no +, no /, no =)
  if (!/^[A-Za-z0-9_-]{43}$/.test(rawToken)) {
    throw new CsrfError(
      'MALFORMED_TOKEN',
      'CSRF token contains invalid characters; expected canonical unpadded base64url',
    );
  }

  const buf = Buffer.from(rawToken, 'base64url');
  if (buf.length !== 32) {
    throw new CsrfError(
      'MALFORMED_TOKEN',
      `Decoded CSRF token length (${buf.length} bytes) is invalid; expected exactly 32 bytes`,
    );
  }

  // Canonical round-trip verification:
  // Catches noncanonical pad bits where distinct 43-character strings decode to identical 32-byte buffers
  if (buf.toString('base64url') !== rawToken) {
    throw new CsrfError(
      'MALFORMED_TOKEN',
      'CSRF token contains noncanonical base64url encoding or invalid pad bits',
    );
  }

  return buf;
}

/**
 * Computes SHA-256 verifier digest of a 32-byte CSRF token buffer.
 */
export function hashCsrfToken(tokenBytes: Buffer): Buffer {
  return crypto.createHash('sha256').update(tokenBytes).digest();
}

/**
 * Performs constant-time comparison between a candidate CSRF token and a stored verifier hash.
 * Enforces fixed 32-byte digest lengths prior to invoking timingSafeEqual.
 */
export function verifyCsrfTokenHash(candidateBytes: Buffer, storedVerifierHash: Buffer): boolean {
  if (
    !Buffer.isBuffer(candidateBytes) ||
    candidateBytes.length !== 32 ||
    !Buffer.isBuffer(storedVerifierHash) ||
    storedVerifierHash.length !== 32
  ) {
    return false;
  }

  const computedHash = hashCsrfToken(candidateBytes);
  return crypto.timingSafeEqual(computedHash, storedVerifierHash);
}

/**
 * Validates request Origin against approved browser origin configuration.
 * Rejects missing, empty, "null", multiple, malformed, cross-site, or parameter-bearing origins.
 */
export function validateOrigin(rawOrigin: unknown, allowedOrigin: string): OriginValidationResult {
  // Reject multiple headers (array from Node HTTP parser)
  if (Array.isArray(rawOrigin)) {
    return { valid: false, reason: 'MULTIPLE_ORIGINS' };
  }

  if (rawOrigin === undefined || rawOrigin === null) {
    return { valid: false, reason: 'MISSING_ORIGIN' };
  }

  if (typeof rawOrigin !== 'string') {
    return { valid: false, reason: 'MALFORMED_ORIGIN' };
  }

  const trimmed = rawOrigin.trim();
  if (trimmed === '' || rawOrigin === '') {
    return { valid: false, reason: 'EMPTY_ORIGIN' };
  }

  if (trimmed === 'null' || rawOrigin === 'null') {
    return { valid: false, reason: 'DISALLOWED_PROTOCOL' };
  }

  // Reject comma-separated origin values
  if (rawOrigin.includes(',')) {
    return { valid: false, reason: 'MULTIPLE_ORIGINS' };
  }

  // Parse allowed origin once
  let allowedUrl: URL;
  try {
    allowedUrl = new URL(allowedOrigin);
  } catch {
    return { valid: false, reason: 'MALFORMED_ORIGIN' };
  }

  let originUrl: URL;
  try {
    originUrl = new URL(rawOrigin);
  } catch {
    return { valid: false, reason: 'MALFORMED_ORIGIN' };
  }

  // Reject invalid protocols
  if (originUrl.protocol !== 'http:' && originUrl.protocol !== 'https:') {
    return { valid: false, reason: 'DISALLOWED_PROTOCOL' };
  }

  // Reject userinfo (username/password)
  if (originUrl.username || originUrl.password) {
    return { valid: false, reason: 'MALFORMED_ORIGIN' };
  }

  // Reject paths, query parameters, or fragments
  if (originUrl.pathname !== '' && originUrl.pathname !== '/') {
    return { valid: false, reason: 'MALFORMED_ORIGIN' };
  }
  if (originUrl.search || originUrl.hash) {
    return { valid: false, reason: 'MALFORMED_ORIGIN' };
  }

  // Canonical origin check: originUrl.origin must match rawOrigin exactly
  // Catches trailing slashes (e.g. "http://example.com/" vs "http://example.com")
  if (originUrl.origin !== rawOrigin) {
    return { valid: false, reason: 'MALFORMED_ORIGIN' };
  }

  // Exact match against allowedOrigin
  if (originUrl.origin !== allowedUrl.origin) {
    return { valid: false, reason: 'ORIGIN_MISMATCH' };
  }

  return { valid: true };
}

export interface CsrfProtectionOptions {
  sessionService: SessionService;
  allowedOrigin: string;
}

/**
 * Creates a Fastify preHandler hook enforcing strict Origin verification and
 * session-bound CSRF token validation on state-changing browser mutations.
 */
export function createCsrfProtectionPreHandler(options: CsrfProtectionOptions) {
  const { sessionService, allowedOrigin } = options;

  return async function csrfProtectionPreHandler(
    req: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    const method = req.method.toUpperCase();

    // Only state-changing browser mutations require Origin and CSRF
    if (!PROTECTED_HTTP_METHODS.has(method)) {
      return;
    }

    // 1. Strict Origin verification
    const rawOrigin = req.headers['origin'];
    const originResult = validateOrigin(rawOrigin, allowedOrigin);
    if (!originResult.valid) {
      reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Invalid or missing Origin',
      });
      return;
    }

    // 2. Extract Session Cookie
    const cookieHeader = req.headers['cookie'];
    const sessionSecret = sessionService.extractSessionSecretFromCookieHeader(cookieHeader);
    if (!sessionSecret) {
      reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Authentication required',
      });
      return;
    }

    // 3. Extract CSRF Token Header
    const rawCsrfHeader = req.headers['x-csrf-token'];
    if (!rawCsrfHeader || Array.isArray(rawCsrfHeader) || rawCsrfHeader.includes(',')) {
      reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Invalid or missing CSRF token',
      });
      return;
    }

    // 4. Session-bound validation with CSRF token
    try {
      const validation = await sessionService.resolveAndValidateSessionWithCsrf(
        sessionSecret,
        rawCsrfHeader,
      );

      if (!validation.valid) {
        if (
          validation.reason === 'CSRF_TOKEN_MISMATCH' ||
          validation.reason === 'MALFORMED_TOKEN' ||
          validation.reason === 'MISSING_TOKEN'
        ) {
          reply.status(403).send({
            statusCode: 403,
            error: 'Forbidden',
            message: 'Invalid or missing CSRF token',
          });
          return;
        }

        // Session failure reasons (REVOKED, EXPIRED, NOT_FOUND, MALFORMED_SECRET)
        reply.status(401).send({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Authentication required',
        });
        return;
      }

      // Attach validated session & user to request for downstream handlers
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any).session = validation.session;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any).user = validation.user;
    } catch {
      reply.status(500).send({
        statusCode: 500,
        error: 'Internal Server Error',
        message: 'Internal server error',
      });
      return;
    }
  };
}

/**
 * Registers test-only endpoints in an isolated test harness for verifying
 * CSRF token reissuance and mutation handling without exposing incomplete
 * production routes (SW-1.5.3 test boundary; production routes owned by SW-1.5.4).
 */
export function registerTestCsrfRoutes(
  app: FastifyInstance,
  options: { sessionService: SessionService; allowedOrigin: string; onMutation?: () => void },
) {
  const { sessionService, allowedOrigin, onMutation } = options;
  const csrfPreHandler = createCsrfProtectionPreHandler({ sessionService, allowedOrigin });

  // Test-only token reissuance endpoint
  app.post('/test/auth/csrf/reissue', async (req, reply) => {
    // Requires exact allowed Origin
    const originResult = validateOrigin(req.headers['origin'], allowedOrigin);
    if (!originResult.valid) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Invalid or missing Origin',
      });
    }

    // Requires authenticated browser session
    const sessionSecret = sessionService.extractSessionSecretFromCookieHeader(
      req.headers['cookie'],
    );
    if (!sessionSecret) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Authentication required',
      });
    }

    try {
      const { csrfToken } = await sessionService.reissueCsrfToken(sessionSecret);
      return reply
        .header('Cache-Control', 'no-store, no-cache, must-revalidate, private')
        .header('Pragma', 'no-cache')
        .send({ csrfToken });
    } catch (err) {
      if (err instanceof SessionError) {
        return reply.status(401).send({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Authentication required',
        });
      }
      return reply.status(500).send({
        statusCode: 500,
        error: 'Internal Server Error',
        message: 'Internal server error',
      });
    }
  });

  // Test-only protected mutation endpoint
  app.post('/test/protected/mutation', { preHandler: csrfPreHandler }, async (_req, reply) => {
    if (onMutation) onMutation();
    return reply.status(200).send({ success: true, mutated: true });
  });

  // Test-only protected PUT mutation
  app.put('/test/protected/mutation', { preHandler: csrfPreHandler }, async (_req, reply) => {
    if (onMutation) onMutation();
    return reply.status(200).send({ success: true, mutated: true });
  });

  // Test-only protected DELETE mutation
  app.delete('/test/protected/mutation', { preHandler: csrfPreHandler }, async (_req, reply) => {
    if (onMutation) onMutation();
    return reply.status(200).send({ success: true, mutated: true });
  });
}
