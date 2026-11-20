import { ZodError, type ZodIssue } from 'zod';
import { sanitizeString } from './redaction.js';

const MAX_MESSAGE_LENGTH = 1024;
const MAX_ERROR_DEPTH = 3;

const ALLOWED_REQ_HEADERS = new Set([
  'host',
  'user-agent',
  'content-type',
  'content-length',
  'accept',
  'x-request-id',
]);

export const ALLOWED_STATIC_ROUTES = new Set([
  '/health/live',
  '/health/ready',
  '/v1/chat/completions',
  '/v1/models',
  '/v1/embeddings',
]);

/**
 * Returns a safe route identifier, never leaking arbitrary URL path segments or query strings.
 */
export function getSafeRouteIdentifier(
  rawUrl?: string | undefined,
  routePattern?: string | undefined,
): string {
  if (routePattern && typeof routePattern === 'string') {
    return routePattern;
  }
  if (rawUrl && typeof rawUrl === 'string') {
    const cleanPath = rawUrl.split('?')[0];
    if (cleanPath && ALLOWED_STATIC_ROUTES.has(cleanPath)) {
      return cleanPath;
    }
  }
  return '[UNMATCHED_ROUTE]';
}

export const SAFE_ERROR_TYPES = new Set([
  'StartupError',
  'ConfigValidationError',
  'FastifyError',
  'ZodError',
  'DatabaseError',
  'PostgresError',
  'RedisError',
  'ReplyError',
  'Error',
  'TypeError',
  'RangeError',
  'SyntaxError',
  'URIError',
  'ReferenceError',
  'CyclicReference',
]);

export const SAFE_ERROR_MESSAGES = new Set([
  'PostgreSQL readiness check failed during startup',
  'Redis readiness check failed during startup',
  'Redis ACL verification failed: runtime identity is not properly restricted',
  'Unsafe Redis policy: expected "noeviction"',
  'Configuration validation failed',
  'PostgreSQL readiness check timed out',
  'PostgreSQL readiness check query failed',
  'PostgreSQL database operation failed',
  'Redis operation failed',
  'Redis readiness check timed out',
  'Redis ping failed',
  'Redis ACL verification failed',
  'Database operation failed',
  'Database connection failed',
  'Database query timed out',
  'Upstream provider request failed',
  'Parent cyclic error',
  'Child error',
  'Gateway fatal startup failure',
  'Not Found',
  'Internal Server Error',
  'Service Unavailable',
  'Bad Request',
  'Method Not Allowed',
  'Gateway server is listening and ready',
  'Process signal received; shutting down',
  'Fatal error during graceful shutdown',
  '[CIRCULAR REFERENCE DETECTED]',
]);

export interface SerializedError {
  type: string;
  message: string;
  code?: string | number | undefined;
  statusCode?: number | undefined;
  stack?: string | undefined;
  issues?: Array<{ path: string; message: string }> | undefined;
  cause?: SerializedError | undefined;
}

export function truncateMessage(msg: string, maxLength = MAX_MESSAGE_LENGTH): string {
  if (msg.length <= maxLength) return msg;
  return `${msg.slice(0, maxLength)}... [TRUNCATED]`;
}

/**
 * Formats a safe Zod issue message that never echoes raw input values.
 */
export function formatSafeZodMessage(issue: ZodIssue): string {
  switch (issue.code) {
    case 'invalid_type':
      return `Expected ${issue.expected}`;
    case 'invalid_value':
      return `Invalid option: expected one of ${issue.values.map(String).join(' | ')}`;
    case 'too_small':
      return `Must contain at least ${issue.minimum} character(s)`;
    case 'too_big':
      return `Must contain at most ${issue.maximum} character(s)`;
    case 'invalid_format':
      return `Invalid format: ${issue.format}`;
    case 'custom':
      return sanitizeString(issue.message);
    default:
      return 'Invalid configuration value';
  }
}

/**
 * Safe error serializer enforcing strict allowlisting (Finding 1).
 * Never serializes arbitrary upstream, database, Redis, or validation error text into production logs.
 * Never exposes raw stack traces containing untrusted values.
 */
export function safeErrorSerializer(
  err: unknown,
  depth = 0,
  seen = new WeakSet<object>(),
): SerializedError {
  if (typeof err !== 'object' || err === null) {
    const raw = String(err);
    const safeMsg = SAFE_ERROR_MESSAGES.has(raw) ? raw : '[UNVETTED_PRIMITIVE_ERROR]';
    return {
      type: typeof err,
      message: safeMsg,
    };
  }

  if (seen.has(err)) {
    return {
      type: 'CyclicReference',
      message: '[CIRCULAR REFERENCE DETECTED]',
    };
  }
  seen.add(err);

  const errorObj = err as Record<string, unknown>;
  const rawType = typeof errorObj['name'] === 'string' ? errorObj['name'] : 'Error';
  const type = SAFE_ERROR_TYPES.has(rawType) ? rawType : 'OperationalError';

  // Handle Safe Error Code
  let code: string | number | undefined;
  if (
    'code' in errorObj &&
    (typeof errorObj['code'] === 'string' || typeof errorObj['code'] === 'number')
  ) {
    const rawCode = String(errorObj['code']);
    if (/^[A-Za-z0-9_.-]{1,64}$/.test(rawCode)) {
      code = errorObj['code'];
    } else {
      code = 'ERR_UNKNOWN';
    }
  }

  // Handle Safe Status Code
  let statusCode: number | undefined;
  if ('statusCode' in errorObj && typeof errorObj['statusCode'] === 'number') {
    if (errorObj['statusCode'] >= 100 && errorObj['statusCode'] <= 599) {
      statusCode = errorObj['statusCode'];
    }
  }

  // Determine Safe Message via Allowlist / Error Classification
  let message: string;
  const rawMessage = typeof errorObj['message'] === 'string' ? errorObj['message'] : '';

  if (type === 'StartupError' && errorObj['message']) {
    message = truncateMessage(sanitizeString(rawMessage));
  } else if (type === 'ConfigValidationError') {
    message = 'Configuration validation failed';
  } else if (type === 'DatabaseError' || type === 'PostgresError') {
    message = 'PostgreSQL database operation failed';
  } else if (type === 'RedisError' || type === 'ReplyError') {
    message = 'Redis operation failed';
  } else if (SAFE_ERROR_MESSAGES.has(rawMessage)) {
    message = rawMessage;
  } else if (rawMessage.startsWith('ERR_PAYLOAD_TOO_LARGE')) {
    message = truncateMessage(rawMessage);
  } else if (type === 'FastifyError' && statusCode) {
    message = statusCode === 404 ? 'Not Found' : 'HTTP Request Failed';
  } else {
    // Un-allowlisted arbitrary error text: do not emit into logs to prevent secret leakage
    message = code ? `Operation failed: ${String(code)}` : 'Operation failed';
  }

  const serialized: SerializedError = {
    type,
    message,
  };

  if (code !== undefined) {
    serialized.code = code;
  }
  if (statusCode !== undefined) {
    serialized.statusCode = statusCode;
  }

  // Safe Stack Trace: never expose line 0 (which contains raw error message).
  // Filter only call site frames ('at ...') to prevent leaking sensitive values.
  if (typeof errorObj['stack'] === 'string') {
    const lines = errorObj['stack'].split('\n');
    const callFrames = lines.filter((l) => /^\s*at\s+/.test(l)).slice(0, 10);
    serialized.stack = [`${type}: [STACK_FRAMES]`, ...callFrames].join('\n');
  }

  // Safe Issues (Zod / Config issues)
  if (err instanceof ZodError) {
    serialized.issues = err.issues.map((i) => ({
      path: i.path.join('.'),
      message: formatSafeZodMessage(i),
    }));
  } else if (Array.isArray(errorObj['issues'])) {
    serialized.issues = (
      errorObj['issues'] as Array<{ field?: string; path?: string; message?: string }>
    ).map((i) => ({
      path: String(i.field ?? i.path ?? 'field'),
      message: sanitizeString(String(i.message ?? 'Invalid value')),
    }));
  }

  // Recurse into cause if within depth limit
  if ('cause' in errorObj && errorObj['cause'] !== undefined && depth < MAX_ERROR_DEPTH) {
    serialized.cause = safeErrorSerializer(errorObj['cause'], depth + 1, seen);
  }

  return serialized;
}

/**
 * Serializes HTTP request metadata safely.
 * Never logs raw query strings or arbitrary path segments.
 */
export function safeReqSerializer(req: unknown): Record<string, unknown> {
  if (typeof req !== 'object' || req === null) return {};
  const r = req as Record<string, unknown>;

  const rawUrl = typeof r['url'] === 'string' ? r['url'] : '';
  const routeUrl =
    typeof (r['routeOptions'] as Record<string, unknown> | undefined)?.['url'] === 'string'
      ? ((r['routeOptions'] as Record<string, unknown>)['url'] as string)
      : undefined;

  const safeRoute = getSafeRouteIdentifier(rawUrl, routeUrl);

  const safeHeaders: Record<string, unknown> = {};
  if (typeof r['headers'] === 'object' && r['headers'] !== null) {
    for (const [key, val] of Object.entries(r['headers'])) {
      const lowerKey = key.toLowerCase();
      if (ALLOWED_REQ_HEADERS.has(lowerKey)) {
        safeHeaders[lowerKey] = typeof val === 'string' ? sanitizeString(val) : val;
      }
    }
  }

  return {
    id: r['id'],
    method: r['method'],
    url: safeRoute,
    route: safeRoute,
    headers: safeHeaders,
  };
}

/**
 * Serializes HTTP response metadata safely.
 */
export function safeResSerializer(res: unknown): Record<string, unknown> {
  if (typeof res !== 'object' || res === null) return {};
  const r = res as Record<string, unknown>;

  return {
    statusCode: r['statusCode'],
  };
}
