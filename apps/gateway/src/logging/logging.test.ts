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

  it('8. redacts nested secret objects across arbitrary depth (R2)', () => {
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

  it('13. strips sensitive query string parameters from request URL logs (R2, R7)', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const secretQueryKey = 'synthetic_secret_query_api_key_777';
    logger.info(
      {
        req: {
          id: 'req-1',
          method: 'GET',
          url: `/v1/chat/completions?api_key=${secretQueryKey}&model=mock-gpt`,
          headers: { host: 'localhost' },
        },
      },
      'Request incoming',
    );

    expect(getRawOutput()).not.toContain(secretQueryKey);
    const logs = getLogs();
    const req = logs[0]?.req as Record<string, unknown>;
    expect(req?.url).toBe('/v1/chat/completions');
  });

  it('14. filters unallowlisted request headers by default in safeReqSerializer (R2)', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const secretHeaderToken = 'secret_bearer_token_in_custom_header_999';
    logger.info(
      {
        req: {
          id: 'req-2',
          method: 'POST',
          url: '/health/ready',
          headers: {
            host: '127.0.0.1:3000',
            'x-custom-secret-key': secretHeaderToken,
            authorization: 'Bearer secret_auth_token_888',
          },
        },
      },
      'Checking headers',
    );

    expect(getRawOutput()).not.toContain(secretHeaderToken);
    expect(getRawOutput()).not.toContain('secret_auth_token_888');
    const logs = getLogs();
    const req = logs[0]?.req as Record<string, unknown>;
    const headers = req?.headers as Record<string, unknown>;
    expect(headers?.host).toBe('127.0.0.1:3000');
    expect(headers?.['x-custom-secret-key']).toBeUndefined();
    expect(headers?.authorization).toBeUndefined();
  });

  it('15. covers uppercase, snake_case, and camelCase credential names (R2)', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const secretVal = 'confidential_credential_pattern';
    logger.info(
      {
        POSTGRES_PASSWORD: secretVal,
        postgres_password: secretVal,
        postgresPassword: secretVal,
        REDIS_APP_PASSWORD: secretVal,
        redis_app_password: secretVal,
        redisAppPassword: secretVal,
        ApiKey: secretVal,
        api_key: secretVal,
        API_KEY: secretVal,
      },
      'Testing case variations',
    );

    expect(getRawOutput()).not.toContain(secretVal);
    const logs = getLogs();
    const entry = logs[0] as Record<string, unknown>;
    expect(entry.POSTGRES_PASSWORD).toBe(CENSOR_VALUE);
    expect(entry.postgres_password).toBe(CENSOR_VALUE);
    expect(entry.postgresPassword).toBe(CENSOR_VALUE);
    expect(entry.REDIS_APP_PASSWORD).toBe(CENSOR_VALUE);
    expect(entry.redis_app_password).toBe(CENSOR_VALUE);
    expect(entry.redisAppPassword).toBe(CENSOR_VALUE);
    expect(entry.ApiKey).toBe(CENSOR_VALUE);
    expect(entry.api_key).toBe(CENSOR_VALUE);
    expect(entry.API_KEY).toBe(CENSOR_VALUE);
  });

  it('16. sanitizes raw connection strings and credentials embedded in Error messages (R1, R7)', () => {
    const { stream, getLogs, getRawOutput } = createLogCapture();
    const logger = createLogger({ stream });

    const secretPassword = 'raw_untrusted_database_password_4321';
    const connectionError = new Error(
      `connect ECONNREFUSED postgresql://switchyard:${secretPassword}@127.0.0.1:5432/switchyard_db`,
    );

    logger.error({ err: connectionError }, 'Database connection failed');

    expect(getRawOutput()).not.toContain(secretPassword);
    const logs = getLogs();
    const loggedErr = logs[0]?.err as Record<string, unknown>;
    expect(loggedErr?.message).toContain('postgresql://[REDACTED]:[REDACTED]@127.0.0.1:5432');
    expect(loggedErr?.stack).not.toContain(secretPassword);
  });

  it('17. bounds deep nested object traversal to prevent resource exhaustion (R2)', () => {
    const { stream, getLogs } = createLogCapture();
    const logger = createLogger({ stream });

    let deepObj: Record<string, unknown> = { val: 'leaf' };
    for (let i = 0; i < 12; i++) {
      deepObj = { nested: deepObj };
    }

    expect(() => {
      logger.info({ deepObj }, 'Deep nested logging');
    }).not.toThrow();

    const logs = getLogs();
    expect(logs.length).toBe(1);
    const raw = JSON.stringify(logs[0]);
    expect(raw).toContain('[DEPTH_LIMIT_EXCEEDED]');
  });
});
