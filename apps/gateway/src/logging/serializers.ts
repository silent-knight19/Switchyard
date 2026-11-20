import { ZodError } from 'zod';
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

export interface SerializedError {
  type: string;
  message: string;
  code?: string | number | undefined;
  statusCode?: number | undefined;
  stack?: string | undefined;
  issues?: Array<{ path: string; message: string }> | undefined;
  cause?: SerializedError | undefined;
}

/**
 * Truncates overly long messages to prevent log injection or denial-of-service via huge strings.
 */
export function truncateMessage(msg: string, maxLength = MAX_MESSAGE_LENGTH): string {
  if (msg.length <= maxLength) return msg;
  return `${msg.slice(0, maxLength)}... [TRUNCATED]`;
}

/**
 * Sanitizes and bounds error serialization.
 * Never serializes raw DB credentials, connection strings, unbounded cause chains, cyclic references, or raw validation inputs.
 */
export function safeErrorSerializer(
  err: unknown,
  depth = 0,
  seen = new WeakSet<object>(),
): SerializedError {
  if (typeof err !== 'object' || err === null) {
    return {
      type: typeof err,
      message: sanitizeString(truncateMessage(String(err))),
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
  const type = typeof errorObj['name'] === 'string' ? errorObj['name'] : 'Error';
  const rawMessage =
    typeof errorObj['message'] === 'string' ? errorObj['message'] : 'Unknown error';

  // Sanitize message: strip connection URLs, bearer tokens, passwords, query credentials
  const message = truncateMessage(sanitizeString(rawMessage));

  const serialized: SerializedError = {
    type,
    message,
  };

  if (
    'code' in errorObj &&
    (typeof errorObj['code'] === 'string' || typeof errorObj['code'] === 'number')
  ) {
    serialized.code = errorObj['code'];
  }

  if ('statusCode' in errorObj && typeof errorObj['statusCode'] === 'number') {
    serialized.statusCode = errorObj['statusCode'];
  }

  if (typeof errorObj['stack'] === 'string') {
    // Sanitize stack trace: never leak credentials or tokens embedded in stack traces
    const sanitizedStack = sanitizeString(errorObj['stack']);
    const lines = sanitizedStack.split('\n').slice(0, 10);
    if (lines[0]) {
      lines[0] = truncateMessage(lines[0], MAX_MESSAGE_LENGTH);
    }
    serialized.stack = lines.join('\n');
  }

  // Sanitize ZodError issues: never serialize raw inputs or received values
  if (err instanceof ZodError) {
    serialized.issues = err.issues.map((i) => ({
      path: i.path.join('.'),
      message: sanitizeString(i.message),
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
 * Strips query strings from URLs and filters headers against an explicit safe allowlist.
 */
export function safeReqSerializer(req: unknown): Record<string, unknown> {
  if (typeof req !== 'object' || req === null) return {};
  const r = req as Record<string, unknown>;

  const rawUrl = typeof r['url'] === 'string' ? r['url'] : '';
  const safePath = rawUrl.split('?')[0] ?? '';

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
    url: safePath,
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
