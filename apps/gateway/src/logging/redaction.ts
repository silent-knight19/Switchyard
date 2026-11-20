/**
 * Architecture v1.2 §14.3 Normative Redaction Paths & Data Privacy.
 * Pino uses these wildcards to recursively redact known sensitive keys in structured logs.
 */
export const REDACTION_PATHS: string[] = [
  // HTTP Headers
  'req.headers.authorization',
  'headers.authorization',
  'authorization',
  'req.headers.cookie',
  'headers.cookie',
  'cookie',
  'req.headers["set-cookie"]',
  'headers["set-cookie"]',
  'set-cookie',

  // Wildcard patterns across all logging levels
  '*.*password*',
  '*password*',
  '*.*token*',
  '*token*',
  '*.*secret*',
  '*secret*',
  '*.*key*',
  '*key*',
  '*.*prompt*',
  '*prompt*',
  '*.*response*',
  '*response*',
  '*.*completion*',
  '*completion*',
  '*.*payload*',
  '*payload*',
  '*.*body*',
  '*body*',
];

export const CENSOR_VALUE = '[REDACTED]';
export const MAX_REDACT_DEPTH = 8;

const SENSITIVE_KEY_ROOTS = [
  'authorization',
  'cookie',
  'setcookie',
  'password',
  'passwd',
  'pwd',
  'passwordhash',
  'sessiontoken',
  'sessionid',
  'session',
  'csrftoken',
  'csrf',
  'token',
  'accesstoken',
  'idtoken',
  'authtoken',
  'refreshtoken',
  'secret',
  'clientsecret',
  'sharedsecret',
  'virtualkey',
  'virtualapikey',
  'apikey',
  'providerkey',
  'providerapikey',
  'kek',
  'dek',
  'masterkey',
  'dbpassword',
  'postgrespassword',
  'redispassword',
  'redisapppassword',
  'privatekey',
  'secretkey',
  'signature',
  'sig',
  'credential',
  'credentials',
  'prompt',
  'prompts',
  'response',
  'responses',
  'completion',
  'completions',
  'payload',
  'body',
];

/**
 * Checks whether an object key is sensitive regardless of casing (camelCase, snake_case, PascalCase, UPPERCASE).
 */
export function isSensitiveKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!normalized) return false;

  for (const root of SENSITIVE_KEY_ROOTS) {
    if (normalized === root) return true;
  }

  // Suffix checks for composite credential names (e.g., myAppPassword, customApiKey, userSessionToken)
  if (
    normalized.endsWith('password') ||
    normalized.endsWith('secret') ||
    normalized.endsWith('token') ||
    normalized.endsWith('apikey') ||
    normalized.endsWith('credential') ||
    normalized.endsWith('credentials') ||
    normalized.endsWith('kek') ||
    normalized.endsWith('dek') ||
    normalized.endsWith('prompt') ||
    normalized.endsWith('completion')
  ) {
    return true;
  }

  // Key-type checks
  if (
    normalized.endsWith('key') &&
    (normalized.includes('virtual') ||
      normalized.includes('provider') ||
      normalized.includes('master') ||
      normalized.includes('private') ||
      normalized.includes('secret') ||
      normalized.includes('api'))
  ) {
    return true;
  }

  return false;
}

/**
 * Sanitizes sensitive substrings from arbitrary string values (connection URLs, bearer tokens, query params, etc.).
 */
export function sanitizeString(val: string): string {
  if (typeof val !== 'string' || val.length === 0) return val;

  let sanitized = val;

  // 1. Connection URLs with embedded credentials (e.g. postgres://user:pass@host or redis://... or rediss://...)
  sanitized = sanitized.replace(
    /(postgres(?:ql)?|redis(?:s)?):\/\/([^:]+):([^@]+)@/gi,
    '$1://[REDACTED]:[REDACTED]@',
  );

  // 2. Authorization Bearer tokens
  sanitized = sanitized.replace(/Bearer\s+[A-Za-z0-9_.~+\/=-]+/gi, 'Bearer [REDACTED]');

  // 3. Virtual and provider keys
  sanitized = sanitized.replace(/sk_live_[A-Za-z0-9_-]+/gi, 'sk_live_[REDACTED]');
  sanitized = sanitized.replace(/sk-ant-[A-Za-z0-9_-]+/gi, 'sk-ant-[REDACTED]');
  sanitized = sanitized.replace(/sk-[A-Za-z0-9_-]{20,}/gi, 'sk-[REDACTED]');

  // 4. Query string or key-value credential parameters
  sanitized = sanitized.replace(
    /([?&]|\b)(api_?key|token|secret|password|passwd|pwd|virtual_?key|provider_?key)=([^&\s]+)/gi,
    '$1$2=[REDACTED]',
  );

  return sanitized;
}

/**
 * Deep recursive object sanitizer for structured log payloads.
 * Bounded by MAX_REDACT_DEPTH and cyclic detection to prevent resource exhaustion.
 */
export function deepRedact(obj: unknown, depth = 0, seen = new WeakSet<object>()): unknown {
  if (typeof obj !== 'object' || obj === null) {
    if (typeof obj === 'string') {
      return sanitizeString(obj);
    }
    return obj;
  }

  // Preserve Error instances so safeErrorSerializer can process them with full error metadata
  if (obj instanceof Error) {
    return obj;
  }

  if (depth > MAX_REDACT_DEPTH) {
    return '[DEPTH_LIMIT_EXCEEDED]';
  }

  if (seen.has(obj)) {
    return '[CIRCULAR]';
  }
  seen.add(obj);

  if (Array.isArray(obj)) {
    return obj.map((item) => deepRedact(item, depth + 1, seen));
  }

  const result: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(obj)) {
    if (isSensitiveKey(key)) {
      result[key] = CENSOR_VALUE;
    } else if (typeof val === 'object' && val !== null) {
      result[key] = deepRedact(val, depth + 1, seen);
    } else if (typeof val === 'string') {
      result[key] = sanitizeString(val);
    } else {
      result[key] = val;
    }
  }

  return result;
}
