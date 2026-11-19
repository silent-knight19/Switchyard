import { ZodError } from 'zod';

const MAX_MESSAGE_LENGTH = 1024;
const MAX_ERROR_DEPTH = 3;

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
 * Never serializes raw DB credentials, unbounded cause chains, cyclic references, or raw validation inputs.
 */
export function safeErrorSerializer(
  err: unknown,
  depth = 0,
  seen = new WeakSet<object>(),
): SerializedError {
  if (typeof err !== 'object' || err === null) {
    return {
      type: typeof err,
      message: truncateMessage(String(err)),
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
  const message = truncateMessage(rawMessage);

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
    // Bound stack trace to top 10 frames and truncate oversized messages in stack
    const lines = errorObj['stack'].split('\n').slice(0, 10);
    if (lines[0]) {
      lines[0] = truncateMessage(lines[0], MAX_MESSAGE_LENGTH);
    }
    serialized.stack = lines.join('\n');
  }

  // Sanitize ZodError issues: never serialize raw inputs or received values
  if (err instanceof ZodError) {
    serialized.issues = err.issues.map((i) => ({
      path: i.path.join('.'),
      message: i.message,
    }));
  }

  // Recurse into cause if within depth limit
  if ('cause' in errorObj && errorObj['cause'] !== undefined && depth < MAX_ERROR_DEPTH) {
    serialized.cause = safeErrorSerializer(errorObj['cause'], depth + 1, seen);
  }

  return serialized;
}

export function safeReqSerializer(req: unknown): Record<string, unknown> {
  if (typeof req !== 'object' || req === null) return {};
  const r = req as Record<string, unknown>;

  const headers =
    typeof r['headers'] === 'object' && r['headers'] !== null
      ? { ...(r['headers'] as Record<string, unknown>) }
      : {};

  // Delete sensitive headers from req serializer directly
  delete headers['authorization'];
  delete headers['cookie'];
  delete headers['set-cookie'];

  return {
    id: r['id'],
    method: r['method'],
    url: r['url'],
    headers,
  };
}

export function safeResSerializer(res: unknown): Record<string, unknown> {
  if (typeof res !== 'object' || res === null) return {};
  const r = res as Record<string, unknown>;

  return {
    statusCode: r['statusCode'],
  };
}
