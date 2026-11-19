/**
 * Architecture v1.2 §14.3 Normative Redaction Paths.
 * Pino uses these wildcards to recursively redact known sensitive keys in structured logs.
 */
export const REDACTION_PATHS: string[] = [
  // HTTP Headers
  'req.headers.authorization',
  'headers.authorization',
  'authorization',
  'req.headers["authorization"]',
  'headers["authorization"]',
  'req.headers.cookie',
  'headers.cookie',
  'cookie',
  'req.headers["cookie"]',
  'headers["cookie"]',
  'req.headers["set-cookie"]',
  'headers["set-cookie"]',
  'set-cookie',

  // Authentication & Session
  '*.password',
  'password',
  '*.passwordHash',
  'passwordHash',
  '*.sessionToken',
  'sessionToken',
  '*.session_token',
  'session_token',
  '*.csrfToken',
  'csrfToken',
  '*.csrf_token',
  'csrf_token',
  '*.token',
  'token',
  '*.secret',
  'secret',

  // API Keys (Virtual and Provider)
  '*.virtualKey',
  'virtualKey',
  '*.virtual_key',
  'virtual_key',
  '*.apiKey',
  'apiKey',
  '*.api_key',
  'api_key',
  '*.providerKey',
  'providerKey',
  '*.provider_key',
  'provider_key',
  '*.providerApiKey',
  'providerApiKey',

  // Encryption Keys
  '*.kek',
  'kek',
  '*.dek',
  'dek',
  '*.masterKey',
  'masterKey',
  '*.master_key',
  'master_key',

  // Database & Cache Credentials
  '*.dbPassword',
  'dbPassword',
  '*.redisPassword',
  'redisPassword',
  '*.POSTGRES_PASSWORD',
  'POSTGRES_PASSWORD',
  '*.REDIS_PASSWORD',
  'REDIS_PASSWORD',
  '*.REDIS_APP_PASSWORD',
  'REDIS_APP_PASSWORD',

  // Prompts, Responses, and Bodies (Defensive Privacy by Default)
  '*.prompt',
  'prompt',
  '*.prompts',
  'prompts',
  '*.response',
  'response',
  '*.responses',
  'responses',
  '*.body',
  'body',
  'req.body',
  '*.payload',
  'payload',
];

export const CENSOR_VALUE = '[REDACTED]';

const SENSITIVE_KEY_REGEX =
  /^(authorization|cookie|set-cookie|password|passwordhash|sessiontoken|session_token|csrftoken|csrf_token|token|secret|virtualkey|virtual_key|apikey|api_key|providerkey|provider_key|providerapikey|kek|dek|masterkey|master_key|dbpassword|redispassword|prompt|prompts|response|responses|payload)$/i;

/**
 * Deep recursive object sanitizer for structured log payloads.
 * Acts as an additional defensive boundary ensuring nested secrets at any depth are censored.
 */
export function deepRedact(obj: unknown, depth = 0, seen = new WeakSet<object>()): unknown {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  // Preserve Error instances so safeErrorSerializer can process them with full error metadata
  if (obj instanceof Error) {
    return obj;
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
    if (SENSITIVE_KEY_REGEX.test(key)) {
      result[key] = CENSOR_VALUE;
    } else if (typeof val === 'object' && val !== null) {
      result[key] = deepRedact(val, depth + 1, seen);
    } else {
      result[key] = val;
    }
  }

  return result;
}
