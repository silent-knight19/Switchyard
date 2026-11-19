import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { Writable } from 'node:stream';
import { createLogger, CENSOR_VALUE } from './index.js';

function createLogCapture(): {
  stream: Writable;
  getLogs: () => Array<Record<string, unknown>>;
  getRawOutput: () => string;
} {
  let raw = '';
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      raw += chunk.toString();
      callback();
    },
  });

  return {
    stream,
    getRawOutput: () => raw,
    getLogs: () => {
      return raw
        .trim()
        .split('\n')
        .filter((l) => l.length > 0)
        .map((line) => JSON.parse(line));
    },
  };
}

describe('SW-1.2.3 Structured Logging and Redaction', () => {
  it('1. redacts authorization bearer tokens', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const bearerToken = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_payload.signature';
    logger.info({ headers: { authorization: bearerToken } }, 'Request received');

    expect(getRawOutput()).not.toContain(bearerToken);
    const logs = getLogs();
    const headers = logs[0]?.headers as Record<string, unknown>;
    expect(headers?.authorization).toBe(CENSOR_VALUE);
  });

  it('2. redacts session cookies', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const sessionCookie = 'session_id=s%3A_super_secret_session_token_xyz123';
    logger.info({ headers: { cookie: sessionCookie } }, 'Session access');

    expect(getRawOutput()).not.toContain(sessionCookie);
    const logs = getLogs();
    const headers = logs[0]?.headers as Record<string, unknown>;
    expect(headers?.cookie).toBe(CENSOR_VALUE);
  });

  it('3. redacts CSRF secrets', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const csrfSecret = 'csrf_token_secret_value_987654321';
    logger.info({ csrfToken: csrfSecret, csrf_token: csrfSecret }, 'Form validation');

    expect(getRawOutput()).not.toContain(csrfSecret);
    const logs = getLogs();
    expect(logs[0]?.csrfToken).toBe(CENSOR_VALUE);
    expect(logs[0]?.csrf_token).toBe(CENSOR_VALUE);
  });

  it('4. redacts Gateway virtual API keys', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const virtualKey = 'sk_live_switchyard_virtual_key_abc123xyz789';
    logger.info({ virtualKey, virtual_key: virtualKey }, 'Virtual key used');

    expect(getRawOutput()).not.toContain(virtualKey);
    const logs = getLogs();
    expect(logs[0]?.virtualKey).toBe(CENSOR_VALUE);
  });

  it('5. redacts provider API keys', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const providerKey = 'sk-ant-api03-anthropic_live_key_99999999';
    logger.info({ providerApiKey: providerKey, apiKey: providerKey }, 'Upstream dispatch');

    expect(getRawOutput()).not.toContain(providerKey);
    const logs = getLogs();
    expect(logs[0]?.providerApiKey).toBe(CENSOR_VALUE);
  });

  it('6. redacts database passwords', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const dbPass = 'db_super_secret_postgres_pass_4444';
    logger.info({ POSTGRES_PASSWORD: dbPass, dbPassword: dbPass }, 'DB connection check');

    expect(getRawOutput()).not.toContain(dbPass);
    const logs = getLogs();
    expect(logs[0]?.POSTGRES_PASSWORD).toBe(CENSOR_VALUE);
  });

  it('7. redacts Redis passwords', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const redisPass = 'redis_super_secret_app_pass_5555';
    logger.info({ REDIS_PASSWORD: redisPass, REDIS_APP_PASSWORD: redisPass }, 'Redis check');

    expect(getRawOutput()).not.toContain(redisPass);
    const logs = getLogs();
    expect(logs[0]?.REDIS_PASSWORD).toBe(CENSOR_VALUE);
  });

  it('8. redacts nested secret objects', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const nestedSecret = 'ultra_confidential_nested_kek_material';
    logger.info(
      {
        context: {
          auth: {
            token: nestedSecret,
            secret: nestedSecret,
          },
        },
      },
      'Deep nested context',
    );

    expect(getRawOutput()).not.toContain(nestedSecret);
    const logs = getLogs();
    const auth = (logs[0]?.context as Record<string, unknown>)?.auth as Record<string, unknown>;
    expect(auth?.token).toBe(CENSOR_VALUE);
    expect(auth?.secret).toBe(CENSOR_VALUE);
  });

  it('9. redacts raw prompt and response text by default', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const promptText = 'Tell me the secret launch codes for the system';
    const responseText = 'The secret launch codes are 12345';
    logger.info({ prompt: promptText, response: responseText }, 'Inference turn');

    expect(getRawOutput()).not.toContain(promptText);
    expect(getRawOutput()).not.toContain(responseText);
    const logs = getLogs();
    expect(logs[0]?.prompt).toBe(CENSOR_VALUE);
    expect(logs[0]?.response).toBe(CENSOR_VALUE);
  });

  it('10. bounds overly long error messages to prevent log bloat', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const hugeErrorString = 'ERR_PAYLOAD_TOO_LARGE: ' + 'X'.repeat(5000);
    const err = new Error(hugeErrorString);
    logger.error({ err }, 'Operation failed');

    const raw = getRawOutput();
    expect(raw).toContain('[TRUNCATED]');
    expect(raw.length).toBeLessThan(4000); // Truncated well below 5000 chars

    const logs = getLogs();
    const loggedErr = logs[0]?.err as Record<string, unknown>;
    expect(String(loggedErr?.message).endsWith('... [TRUNCATED]')).toBe(true);
  });

  it('11. handles cyclic and malformed error objects safely without stack overflow', () => {
    const { stream, getLogs } = createLogCapture();
    const logger = createLogger({ stream });

    const cyclicError = new Error('Parent cyclic error') as Error & { cause?: unknown };
    const child = new Error('Child error') as Error & { cause?: unknown };
    cyclicError.cause = child;
    child.cause = cyclicError; // Circular reference

    expect(() => {
      logger.error({ err: cyclicError }, 'Cyclic error log');
    }).not.toThrow();

    const logs = getLogs();
    const err = logs[0]?.err as Record<string, unknown>;
    expect(err?.message).toBe('Parent cyclic error');
    const cause = err?.cause as Record<string, unknown>;
    expect(cause?.message).toBe('Child error');
    const circular = cause?.cause as Record<string, unknown>;
    expect(circular?.type).toBe('CyclicReference');
  });

  it('12. serializes Zod validation errors without leaking sensitive raw input values', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const secretPasswordInput = 'RawLeakedPasswordInPlaintext123';
    const testSchema = z.object({
      password: z.string().min(50, 'Password is too short'),
    });

    const parseResult = testSchema.safeParse({ password: secretPasswordInput });
    expect(parseResult.success).toBe(false);

    if (!parseResult.success) {
      logger.error({ err: parseResult.error }, 'Validation failed');
    }

    expect(getRawOutput()).not.toContain(secretPasswordInput);
    const logs = getLogs();
    const loggedErr = logs[0]?.err as Record<string, unknown>;
    expect(loggedErr?.type).toBe('ZodError');
    expect(loggedErr?.issues).toBeDefined();
  });
});
