import { describe, expect, it } from 'vitest';
import { ConfigValidationError, loadConfig } from './index.js';

const VALID_DEV_ENV: Record<string, string> = {
  NODE_ENV: 'development',
  PORT: '3000',
  HOST: '127.0.0.1',
  POSTGRES_HOST: '127.0.0.1',
  POSTGRES_PORT: '5432',
  POSTGRES_DB: 'switchyard',
  POSTGRES_USER: 'switchyard',
  POSTGRES_PASSWORD: 'switchyard_dev_password',
  REDIS_HOST: '127.0.0.1',
  REDIS_PORT: '6379',
  REDIS_USER: 'switchyard_app',
  REDIS_PASSWORD: 'switchyard_app_password',
  REDIS_MAXMEMORY_POLICY: 'noeviction',
  REDIS_TLS: 'false',
  COOKIE_SECURE: 'false',
  TLS_VERIFY: 'true',
  MOCK_PROVIDER_ENABLED: 'false',
  DEMO_SEEDING_ENABLED: 'false',
};

const VALID_PROD_ENV: Record<string, string> = {
  NODE_ENV: 'production',
  PORT: '8080',
  HOST: '0.0.0.0',
  POSTGRES_HOST: 'postgres.internal',
  POSTGRES_PORT: '5432',
  POSTGRES_DB: 'switchyard_prod',
  POSTGRES_USER: 'switchyard_app',
  POSTGRES_PASSWORD: 'very_strong_unique_postgres_password_12345',
  REDIS_HOST: 'redis.internal',
  REDIS_PORT: '6379',
  REDIS_USER: 'switchyard_app',
  REDIS_PASSWORD: 'very_strong_unique_redis_password_67890',
  REDIS_MAXMEMORY_POLICY: 'noeviction',
  REDIS_TLS: 'true',
  COOKIE_SECURE: 'true',
  TLS_VERIFY: 'true',
  MOCK_PROVIDER_ENABLED: 'false',
  DEMO_SEEDING_ENABLED: 'false',
};

describe('SW-1.2.2 Central Zod Configuration', () => {
  it('1. accepts valid development configuration', () => {
    const config = loadConfig(VALID_DEV_ENV);
    expect(config.NODE_ENV).toBe('development');
    expect(config.PORT).toBe(3000);
    expect(config.POSTGRES_PORT).toBe(5432);
    expect(config.REDIS_MAXMEMORY_POLICY).toBe('noeviction');
  });

  it('2. accepts valid test configuration', () => {
    const testEnv = { ...VALID_DEV_ENV, NODE_ENV: 'test' };
    const config = loadConfig(testEnv);
    expect(config.NODE_ENV).toBe('test');
  });

  it('3. rejects invalid environment profile', () => {
    const invalidEnv = { ...VALID_DEV_ENV, NODE_ENV: 'staging_invalid' };
    expect(() => loadConfig(invalidEnv)).toThrowError(ConfigValidationError);
    try {
      loadConfig(invalidEnv);
    } catch (e) {
      const err = e as ConfigValidationError;
      expect(err.issues.some((i) => i.field === 'NODE_ENV')).toBe(true);
    }
  });

  it('4. rejects missing mandatory settings when NODE_ENV is missing', () => {
    const missingEnv: Record<string, string> = { ...VALID_DEV_ENV };
    delete missingEnv['NODE_ENV'];
    expect(() => loadConfig(missingEnv)).toThrowError(ConfigValidationError);
  });

  it('5. rejects invalid port (non-integer, out of range)', () => {
    const invalidPortEnv = { ...VALID_DEV_ENV, PORT: '70000' };
    expect(() => loadConfig(invalidPortEnv)).toThrowError(ConfigValidationError);

    const nonNumericPort = { ...VALID_DEV_ENV, PORT: 'not-a-port' };
    expect(() => loadConfig(nonNumericPort)).toThrowError(ConfigValidationError);
  });

  it('6. rejects invalid boolean strings without accidental coercion', () => {
    const invalidBoolEnv = { ...VALID_DEV_ENV, COOKIE_SECURE: 'yes' };
    expect(() => loadConfig(invalidBoolEnv)).toThrowError(ConfigValidationError);

    const numericBoolEnv = { ...VALID_DEV_ENV, COOKIE_SECURE: '1' };
    expect(() => loadConfig(numericBoolEnv)).toThrowError(ConfigValidationError);
  });

  it('7. rejects malformed endpoint URL and embedded credentials (R6)', () => {
    const malformedUrlEnv = {
      ...VALID_DEV_ENV,
      UPSTREAM_ENDPOINT_URL: 'not a valid url',
    };
    expect(() => loadConfig(malformedUrlEnv)).toThrowError(ConfigValidationError);

    const badProtocolEnv = {
      ...VALID_DEV_ENV,
      UPSTREAM_ENDPOINT_URL: 'ftp://example.com/bad',
    };
    expect(() => loadConfig(badProtocolEnv)).toThrowError(ConfigValidationError);

    // Negative test: Embedded credentials in URL must be rejected
    const embeddedCredsEnv = {
      ...VALID_DEV_ENV,
      UPSTREAM_ENDPOINT_URL: 'http://user:secretpassword@127.0.0.1:4010',
    };
    expect(() => loadConfig(embeddedCredsEnv)).toThrowError(ConfigValidationError);
  });

  it('8. rejects custom upstream endpoint overrides in production (R6)', () => {
    const customProdUpstream = {
      ...VALID_PROD_ENV,
      UPSTREAM_ENDPOINT_URL: 'https://api.openai.com',
    };
    expect(() => loadConfig(customProdUpstream)).toThrowError(ConfigValidationError);
    try {
      loadConfig(customProdUpstream);
    } catch (e) {
      const err = e as ConfigValidationError;
      expect(err.issues.some((i) => i.field === 'UPSTREAM_ENDPOINT_URL')).toBe(true);
      expect(err.message).toContain('prohibited in production profile');
    }
  });

  it('9. rejects insecure production cookie (COOKIE_SECURE=false)', () => {
    const insecureProd = { ...VALID_PROD_ENV, COOKIE_SECURE: 'false' };
    expect(() => loadConfig(insecureProd)).toThrowError(ConfigValidationError);
    try {
      loadConfig(insecureProd);
    } catch (e) {
      const err = e as ConfigValidationError;
      expect(err.issues.some((i) => i.field === 'COOKIE_SECURE')).toBe(true);
    }
  });

  it('10. rejects disabled TLS verification in production', () => {
    const noTlsProd = { ...VALID_PROD_ENV, TLS_VERIFY: 'false' };
    expect(() => loadConfig(noTlsProd)).toThrowError(ConfigValidationError);

    const nodeTlsRejectProd = {
      ...VALID_PROD_ENV,
      NODE_TLS_REJECT_UNAUTHORIZED: '0',
    };
    expect(() => loadConfig(nodeTlsRejectProd)).toThrowError(ConfigValidationError);
  });

  it('11. rejects production mock provider enabled', () => {
    const mockProd = { ...VALID_PROD_ENV, MOCK_PROVIDER_ENABLED: 'true' };
    expect(() => loadConfig(mockProd)).toThrowError(ConfigValidationError);
  });

  it('12. rejects production demo seeding enabled', () => {
    const demoProd = { ...VALID_PROD_ENV, DEMO_SEEDING_ENABLED: 'true' };
    expect(() => loadConfig(demoProd)).toThrowError(ConfigValidationError);
  });

  it('13. rejects unsafe Redis policy (not noeviction)', () => {
    const unsafeRedisDev = {
      ...VALID_DEV_ENV,
      REDIS_MAXMEMORY_POLICY: 'allkeys-lru',
    };
    expect(() => loadConfig(unsafeRedisDev)).toThrowError(ConfigValidationError);

    const volatileLru = {
      ...VALID_DEV_ENV,
      REDIS_MAXMEMORY_POLICY: 'volatile-lru',
    };
    expect(() => loadConfig(volatileLru)).toThrowError(ConfigValidationError);
  });

  it('14. rejects default development credentials in production', () => {
    const devPassPostgresInProd = {
      ...VALID_PROD_ENV,
      POSTGRES_PASSWORD: 'switchyard_dev_password',
    };
    expect(() => loadConfig(devPassPostgresInProd)).toThrowError(ConfigValidationError);

    const devPassRedisInProd = {
      ...VALID_PROD_ENV,
      REDIS_PASSWORD: 'switchyard_app_password',
    };
    expect(() => loadConfig(devPassRedisInProd)).toThrowError(ConfigValidationError);
  });

  it('15. rejects unknown security bypass flags', () => {
    const bypassEnv = { ...VALID_DEV_ENV, BYPASS_AUTH: 'true' };
    expect(() => loadConfig(bypassEnv)).toThrowError(ConfigValidationError);

    const rlsBypassEnv = { ...VALID_DEV_ENV, BYPASS_RLS: '1' };
    expect(() => loadConfig(rlsBypassEnv)).toThrowError(ConfigValidationError);
  });

  it('16. ensures injected synthetic secrets never appear in validation errors (Finding 1, Finding 5)', () => {
    const syntheticDbPass = 'synthetic_ultra_secret_db_pass_999';
    const syntheticRedisPass = 'synthetic_ultra_secret_redis_pass_888';
    const syntheticCustomSecret = 'synthetic_custom_secret_token_777';

    // Test A: Actually inject synthetic secrets directly into sensitive password fields along with invalid config
    const invalidWithInjectedSecrets = {
      ...VALID_PROD_ENV,
      POSTGRES_PASSWORD: syntheticDbPass,
      REDIS_PASSWORD: syntheticRedisPass,
      COOKIE_SECURE: 'false', // Triggers validation error in production
    };

    try {
      loadConfig(invalidWithInjectedSecrets);
      expect.fail('Expected loadConfig to throw ConfigValidationError');
    } catch (e) {
      const err = e as ConfigValidationError;
      expect(err.message).not.toContain(syntheticDbPass);
      expect(err.message).not.toContain(syntheticRedisPass);
      for (const issue of err.issues) {
        expect(issue.message).not.toContain(syntheticDbPass);
        expect(issue.message).not.toContain(syntheticRedisPass);
      }
    }

    // Test B: Inject synthetic secret into enum field (NODE_ENV) - must not echo secret in 'invalid_enum_value'
    const invalidEnumWithSecret = {
      ...VALID_PROD_ENV,
      NODE_ENV: syntheticCustomSecret,
    };

    try {
      loadConfig(invalidEnumWithSecret);
      expect.fail('Expected loadConfig to throw ConfigValidationError');
    } catch (e) {
      const err = e as ConfigValidationError;
      expect(err.message).not.toContain(syntheticCustomSecret);
      for (const issue of err.issues) {
        expect(issue.message).not.toContain(syntheticCustomSecret);
      }
    }
  });

  it('17. ensures no fail-open mode exists and FAIL_OPEN is rejected', () => {
    const failOpenEnv = { ...VALID_DEV_ENV, FAIL_OPEN: 'true' };
    expect(() => loadConfig(failOpenEnv)).toThrowError(ConfigValidationError);
    try {
      loadConfig(failOpenEnv);
    } catch (e) {
      const err = e as ConfigValidationError;
      expect(err.message).toContain('fail-closed');
    }
  });
});
