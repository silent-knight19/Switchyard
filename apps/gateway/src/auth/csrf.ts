import crypto from 'node:crypto';
import net from 'node:net';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { SessionService } from './session.js';
import { CsrfError, type OriginValidationResult } from './types.js';

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
 * Evaluates whether a given parsed hostname represents a loopback or unspecified address
 * across IPv4, IPv6, and IPv4-mapped IPv6 representations (CSRF-01, CSRF-06).
 * Accounts for terminal root dots in fully qualified DNS names (e.g. localhost.).
 * Used to enforce strict non-loopback browser origin policies in production.
 */
export function isLoopbackOrUnspecifiedHost(hostname: string): boolean {
  const raw = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  const host = raw.toLowerCase();

  // Strip optional trailing root dot for DNS FQDN classification (CSRF-06)
  const dnsHost = host.endsWith('.') ? host.slice(0, -1) : host;

  // Localhost hostname check (localhost and any *.localhost subdomain, with or without root dot)
  if (dnsHost === 'localhost' || dnsHost.endsWith('.localhost')) {
    return true;
  }

  // IPv4 check: entire 127.0.0.0/8 loopback block and 0.0.0.0 unspecified
  if (net.isIPv4(dnsHost)) {
    const octets = dnsHost.split('.').map(Number);
    if (octets[0] === 127) {
      return true;
    }
    if (octets[0] === 0 && octets[1] === 0 && octets[2] === 0 && octets[3] === 0) {
      return true;
    }
    return false;
  }

  // IPv6 check: ::1 loopback, :: unspecified, and IPv4-mapped representations
  if (net.isIPv6(dnsHost)) {
    if (dnsHost === '::1' || dnsHost === '0:0:0:0:0:0:0:1') {
      return true;
    }
    if (dnsHost === '::' || dnsHost === '0:0:0:0:0:0:0:0') {
      return true;
    }

    // IPv4-mapped IPv6 check (::ffff:...)
    const ipv4MappedPrefix = '::ffff:';
    if (dnsHost.startsWith(ipv4MappedPrefix)) {
      const rest = dnsHost.slice(ipv4MappedPrefix.length);

      // In dotted-decimal notation (e.g. ::ffff:127.0.0.2)
      if (net.isIPv4(rest)) {
        const octets = rest.split('.').map(Number);
        return (
          octets[0] === 127 ||
          (octets[0] === 0 && octets[1] === 0 && octets[2] === 0 && octets[3] === 0)
        );
      }

      // In normalized hex notation (e.g. ::ffff:7f00:2 or ::ffff:0:0)
      const parts = rest.split(':');
      if (parts.length === 2) {
        const highWord = parseInt(parts[0] ?? '', 16);
        const lowWord = parseInt(parts[1] ?? '', 16);
        const firstOctet = (highWord >> 8) & 0xff;
        if (firstOctet === 127) {
          return true;
        }
        if (highWord === 0 && lowWord === 0) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Validates that an allowed-Origin configuration is an exact, canonical browser origin (CSRF-02).
 * Fails closed if the configuration contains credentials, paths, queries, fragments,
 * trailing slashes, wildcards, multiple origins, or unsupported protocols.
 */
export function assertCanonicalOrigin(origin: unknown): string {
  if (typeof origin !== 'string' || origin.trim() === '') {
    throw new CsrfError(
      'CONFIGURATION_ERROR',
      'Allowed browser origin configuration must be a non-empty string',
    );
  }

  if (origin.includes(',') || origin === '*') {
    throw new CsrfError(
      'CONFIGURATION_ERROR',
      'Wildcards and multiple comma-separated origins are strictly prohibited',
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new CsrfError(
      'CONFIGURATION_ERROR',
      `Malformed browser origin configuration: "${String(origin)}"`,
    );
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new CsrfError(
      'CONFIGURATION_ERROR',
      `Browser origin must use http: or https: protocol; received "${parsed.protocol}"`,
    );
  }

  if (parsed.username || parsed.password) {
    throw new CsrfError('CONFIGURATION_ERROR', 'Browser origin must not contain credentials');
  }

  if (parsed.pathname !== '' && parsed.pathname !== '/') {
    throw new CsrfError('CONFIGURATION_ERROR', 'Browser origin must not contain a path');
  }

  if (parsed.search || parsed.hash) {
    throw new CsrfError(
      'CONFIGURATION_ERROR',
      'Browser origin must not contain query or fragment parameters',
    );
  }

  if (parsed.origin !== origin) {
    throw new CsrfError(
      'CONFIGURATION_ERROR',
      `Browser origin must be an exact canonical origin without trailing slash; received "${origin}", expected "${parsed.origin}"`,
    );
  }

  return parsed.origin;
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

  // Parse allowed origin
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
  if (originUrl.origin !== rawOrigin) {
    return { valid: false, reason: 'MALFORMED_ORIGIN' };
  }

  // Exact match against allowedOrigin
  if (originUrl.origin !== allowedUrl.origin) {
    return { valid: false, reason: 'ORIGIN_MISMATCH' };
  }

  return { valid: true };
}

/**
 * Checks whether rawHeaders array contains more than one occurrence of a header name (CSRF-04).
 */
function hasDuplicateRawHeader(rawHeaders: string[] | undefined, headerName: string): boolean {
  if (!rawHeaders) return false;
  const target = headerName.toLowerCase();
  let count = 0;
  for (let i = 0; i < rawHeaders.length; i += 2) {
    if (rawHeaders[i]?.toLowerCase() === target) {
      count++;
      if (count > 1) return true;
    }
  }
  return false;
}

export interface CsrfProtectionOptions {
  sessionService: SessionService;
  allowedOrigin: string;
}

/**
 * Creates a Fastify preHandler hook enforcing strict Origin verification and
 * session-bound CSRF token validation on state-changing browser mutations.
 * Validates the allowedOrigin configuration once at construction time (CSRF-02).
 */
export function createCsrfProtectionPreHandler(options: CsrfProtectionOptions) {
  const { sessionService, allowedOrigin } = options;

  // Validate allowedOrigin once at factory creation time (CSRF-02)
  const trustedOrigin = assertCanonicalOrigin(allowedOrigin);

  return async function csrfProtectionPreHandler(
    req: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    const method = req.method.toUpperCase();

    // Only state-changing browser mutations require Origin and CSRF
    if (!PROTECTED_HTTP_METHODS.has(method)) {
      return;
    }

    // 0. Defense-in-depth: Reject duplicate raw header lines (CSRF-04)
    if (hasDuplicateRawHeader(req.raw.rawHeaders, 'origin')) {
      reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Invalid or missing Origin',
      });
      return;
    }

    if (hasDuplicateRawHeader(req.raw.rawHeaders, 'x-csrf-token')) {
      reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Invalid or missing CSRF token',
      });
      return;
    }

    // 1. Strict Origin verification
    const rawOrigin = req.headers['origin'];
    const originResult = validateOrigin(rawOrigin, trustedOrigin);
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
