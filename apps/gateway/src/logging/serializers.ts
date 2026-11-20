import { ZodError, type ZodIssue } from 'zod';
import { sanitizeString } from './redaction.js';

const MAX_MESSAGE_LENGTH = 256;
const MAX_ERROR_DEPTH = 2;
const MAX_ISSUES = 8;

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
  'OperationalError',
  'Error',
  'TypeError',
  'RangeError',
  'SyntaxError',
  'URIError',
  'ReferenceError',
  'CyclicReference',
]);

export const SAFE_ERROR_CODES = new Set([
  'CONFIG_VALIDATION_FAILED',
  'STARTUP_TIMEOUT',
  'DATABASE_CONNECT_FAILED',
  'REDIS_CONNECT_FAILED',
  'UNSAFE_REDIS_POLICY',
  'UNSAFE_REDIS_ACL',
  'DEFAULT_USER_FORBIDDEN',
  'OVERPRIVILEGED_CONFIG_PERMITTED',
  'OVERPRIVILEGED_KEYS_PERMITTED',
  'OVERPRIVILEGED_ACL_PERMITTED',
  'REDIS_ACL_PROBE_FAILED',
  'POSTGRES_QUERY_TIMEOUT',
  'POSTGRES_CONNECTION_FAILED',
  'DATABASE_ERROR',
  'REDIS_ERROR',
  'TIMEOUT',
  'UNEXPECTED_PING_RESPONSE',
  'UNSAFE_POLICY',
  'WHOAMI_FAILED',
  'ACL_PROBE_ERROR',
  'LISTEN_FAILED',
  'SIGTERM',
  'SIGINT',
  'MANUAL',
  'ECONNREFUSED',
  'ECONNRESET',
  'ETIMEDOUT',
  'ENOTFOUND',
  'EAI_AGAIN',
  '57014',
  '28P01',
  '08006',
  '42P01',
  'FST_ERR_NOT_FOUND',
  'FST_ERR_BAD_URL',
  'ERR_UPSTREAM_FAILURE',
  'ERR_NESTED_ROOT',
  'ERR_PAYLOAD_TOO_LARGE',
]);

export const SAFE_STARTUP_MESSAGES: Record<string, string> = {
  DATABASE_CONNECT_FAILED: 'PostgreSQL readiness check failed during startup',
  REDIS_CONNECT_FAILED: 'Redis readiness check failed during startup',
  UNSAFE_REDIS_POLICY: 'Unsafe Redis policy: expected "noeviction"',
  UNSAFE_REDIS_ACL: 'Redis ACL verification failed: runtime identity is not properly restricted',
  DEFAULT_USER_FORBIDDEN: 'Redis runtime identity cannot be default user',
  OVERPRIVILEGED_CONFIG_PERMITTED: 'Administrative CONFIG command permitted in runtime identity',
  OVERPRIVILEGED_KEYS_PERMITTED: 'Unrestricted KEYS command permitted in runtime identity',
  OVERPRIVILEGED_ACL_PERMITTED: 'Administrative ACL command permitted in runtime identity',
  STARTUP_TIMEOUT: 'Gateway startup timed out',
  LISTEN_FAILED: 'Gateway HTTP listen failed',
};

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
  'Payload too large',
  '[CIRCULAR REFERENCE DETECTED]',
]);

export const SAFE_ISSUE_FIELDS = new Set([
  'NODE_ENV',
  'PORT',
  'HOST',
  'POSTGRES_HOST',
  'POSTGRES_PORT',
  'POSTGRES_DB',
  'POSTGRES_USER',
  'POSTGRES_PASSWORD',
  'REDIS_HOST',
  'REDIS_PORT',
  'REDIS_USER',
  'REDIS_PASSWORD',
  'REDIS_TLS',
  'REDIS_MAXMEMORY_POLICY',
  'COOKIE_SECRET',
  'COOKIE_SECURE',
  'COOKIE_DOMAIN',
  'TLS_VERIFY',
  'MOCK_PROVIDER_ENABLED',
  'DEMO_SEEDING_ENABLED',
  'UPSTREAM_ENDPOINT_URL',
  'FAIL_OPEN',
  'ALLOW_FAIL_OPEN',
  'BYPASS_AUTH',
  'ALLOW_INSECURE_AUTH',
  'BYPASS_RLS',
  'DISABLE_TENANT_ISOLATION',
  'DISABLE_AUTH',
  'INSECURE_MODE',
  'NODE_TLS_REJECT_UNAUTHORIZED',
]);

export const SAFE_CUSTOM_ZOD_MESSAGES = new Set([
  'Expected "true" or "false"',
  'Expected integer between 1 and 65535',
  'Expected exactly "true" or "false" string',
  'PORT must be an integer between 1 and 65535',
  'Malformed endpoint URL: expected valid http:// or https:// URL without embedded credentials',
  'Unsafe Redis policy: must be "noeviction" to prevent silent monetary eviction',
  'UPSTREAM_ENDPOINT_URL must use http or https protocol',
  'UPSTREAM_ENDPOINT_URL must not contain embedded user credentials',
  'Production profile requires secure cookies (COOKIE_SECURE=true)',
  'COOKIE_SECURE must be true in production profile',
  'Production profile requires TLS verification (TLS_VERIFY=true)',
  'TLS_VERIFY must be true in production profile',
  'Mock provider is prohibited in production profile',
  'Demo seeding is prohibited in production profile',
  'Default development credentials are prohibited in production profile',
  'Custom upstream endpoint overrides are prohibited in production profile',
  'Custom upstream endpoint URL overrides are prohibited in production profile pending provider allowlist specification',
  'Disabling Node TLS verification is prohibited in production.',
  'Forbidden security bypass flag detected. Switchyard is strictly fail-closed.',
  'Invalid value provided for sensitive credential',
]);

export interface SerializedError {
  type: string;
  message: string;
  code?: string | number | undefined;
  statusCode?: number | undefined;
  issues?: Array<{ path: string; message: string }> | undefined;
  cause?: SerializedError | undefined;
}

export function truncateMessage(msg: string, maxLength = MAX_MESSAGE_LENGTH): string {
  if (msg.length <= maxLength) return msg;
  return `${msg.slice(0, maxLength)}... [TRUNCATED]`;
}

/**
 * Formats a safe Zod issue message strictly from allowlisted messages.
 * Never echoes raw received values or unrecognized custom messages.
 */
export function formatSafeZodMessage(issue: ZodIssue): string {
  switch (issue.code) {
    case 'invalid_type':
      return `Expected ${issue.expected}`;
    case 'invalid_value':
      return 'Invalid option provided';
    case 'too_small':
      return `Must contain at least ${issue.minimum} character(s)`;
    case 'too_big':
      return `Must contain at most ${issue.maximum} character(s)`;
    case 'invalid_format':
      return `Invalid format: ${issue.format}`;
    case 'custom':
      return SAFE_CUSTOM_ZOD_MESSAGES.has(issue.message)
        ? issue.message
        : 'Invalid configuration value';
    default:
      return 'Invalid configuration value';
  }
}

/**
 * Safe error serializer enforcing strict allowlisting (Finding B).
 * Never serializes arbitrary upstream, database, Redis, startup, or validation error text into production logs.
 * Never exposes raw stack-frame lines.
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

  // Handle Safe Error Code via strict allowlist
  let code: string | number | undefined;
  if (
    'code' in errorObj &&
    (typeof errorObj['code'] === 'string' || typeof errorObj['code'] === 'number')
  ) {
    const rawCode = String(errorObj['code']);
    if (SAFE_ERROR_CODES.has(rawCode)) {
      code = errorObj['code'];
    } else {
      code = 'UNKNOWN_ERROR';
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

  if (type === 'StartupError') {
    const mapped = code ? SAFE_STARTUP_MESSAGES[String(code)] : undefined;
    message = mapped ?? 'Gateway startup failed';
  } else if (type === 'ConfigValidationError') {
    message = 'Configuration validation failed';
  } else if (type === 'DatabaseError' || type === 'PostgresError') {
    message = 'PostgreSQL database operation failed';
  } else if (type === 'RedisError' || type === 'ReplyError') {
    message = 'Redis operation failed';
  } else if (rawMessage.startsWith('ERR_PAYLOAD_TOO_LARGE') || code === 'ERR_PAYLOAD_TOO_LARGE') {
    message = 'Payload too large';
  } else if (SAFE_ERROR_MESSAGES.has(rawMessage)) {
    message = rawMessage;
  } else if (type === 'FastifyError' && statusCode) {
    message = statusCode === 404 ? 'Not Found' : 'HTTP Request Failed';
  } else {
    message =
      code && code !== 'UNKNOWN_ERROR' ? `Operation failed: ${String(code)}` : 'Operation failed';
  }

  const serialized: SerializedError = {
    type,
    message: truncateMessage(message),
  };

  if (code !== undefined) {
    serialized.code = code;
  }
  if (statusCode !== undefined) {
    serialized.statusCode = statusCode;
  }

  // Stack traces: omit raw stack-frame lines completely to eliminate any risk of leaking sensitive values
  // (Architecture §14.3 & Finding B requirement: omission is acceptable).

  // Safe Issues (Zod / Config issues) capped at MAX_ISSUES
  if (err instanceof ZodError) {
    serialized.issues = err.issues.slice(0, MAX_ISSUES).map((i) => {
      const fieldPath = i.path.join('.');
      const safePath = SAFE_ISSUE_FIELDS.has(fieldPath) ? fieldPath : 'configuration';
      return {
        path: safePath,
        message: formatSafeZodMessage(i),
      };
    });
  } else if (Array.isArray(errorObj['issues'])) {
    const rawIssues = errorObj['issues'] as Array<{
      field?: string;
      path?: string;
      message?: string;
    }>;
    serialized.issues = rawIssues.slice(0, MAX_ISSUES).map((i) => {
      const rawPath = String(i.field ?? i.path ?? 'configuration');
      const safePath = SAFE_ISSUE_FIELDS.has(rawPath) ? rawPath : 'configuration';
      const rawMsg = String(i.message ?? '');
      const safeMsg = SAFE_CUSTOM_ZOD_MESSAGES.has(rawMsg) ? rawMsg : 'Invalid configuration value';
      return {
        path: safePath,
        message: safeMsg,
      };
    });
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
