import { z } from 'zod';
import { isSensitiveKey } from '../logging/redaction.js';
import { formatSafeZodMessage } from '../logging/serializers.js';

export class WorkerConfigValidationError extends Error {
  public readonly issues: readonly string[];
  public readonly code = 'CONFIG_VALIDATION_FAILED';

  constructor(issues: string[]) {
    super(`Worker configuration validation failed: ${issues.join('; ')}`);
    this.name = 'WorkerConfigValidationError';
    this.issues = Object.freeze([...issues]);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

const FORBIDDEN_SECURITY_FLAGS = [
  'FAIL_OPEN',
  'ALLOW_FAIL_OPEN',
  'BYPASS_AUTH',
  'ALLOW_INSECURE_AUTH',
  'BYPASS_RLS',
  'DISABLE_TENANT_ISOLATION',
  'DISABLE_AUTH',
  'INSECURE_MODE',
] as const;

const SENSITIVE_FIELD_NAMES = new Set([
  'POSTGRES_PASSWORD',
  'REDIS_PASSWORD',
  'MASTER_KEK_V1',
  'MASTER_KEK_V2',
  'ACTIVE_KEK_VERSION',
]);

const portNumber = z.string().transform((val, ctx) => {
  const num = Number(val);
  if (!Number.isInteger(num) || num < 1 || num > 65535) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Expected integer between 1 and 65535',
    });
    return z.NEVER;
  }
  return num;
});

const positiveInt = z.string().transform((val, ctx) => {
  const num = Number(val);
  if (!Number.isInteger(num) || num < 50 || num > 300000) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Expected integer between 50 and 300000',
    });
    return z.NEVER;
  }
  return num;
});

const strictBoolean = z.string().transform((val, ctx) => {
  if (val === 'true') return true;
  if (val === 'false') return false;
  ctx.addIssue({
    code: z.ZodIssueCode.custom,
    message: 'Expected "true" or "false"',
  });
  return z.NEVER;
});

export const workerEnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']),

    // PostgreSQL - Must connect as gateway_worker (Architecture v1.2 §12.1, §19.4)
    POSTGRES_HOST: z.string().min(1).default('127.0.0.1'),
    POSTGRES_PORT: portNumber.default(5432),
    POSTGRES_DB: z.string().min(1).default('switchyard'),
    POSTGRES_USER: z.string().min(1).default('gateway_worker'),
    POSTGRES_PASSWORD: z.string().min(1),

    // Redis - Must connect under restricted worker ACL identity (Architecture v1.2 §19.4)
    REDIS_HOST: z.string().min(1).default('127.0.0.1'),
    REDIS_PORT: portNumber.default(6379),
    REDIS_USER: z.string().min(1).default('switchyard_worker'),
    REDIS_PASSWORD: z.string().min(1),
    REDIS_MAXMEMORY_POLICY: z.string().default('noeviction'),
    REDIS_TLS: strictBoolean.default(false),

    // Health file path for heartbeat and status check
    WORKER_HEALTH_FILE: z.string().default('/tmp/switchyard-worker-health.json'),

    // Bounded probe timings (Architecture v1.2 §20, §23)
    WORKER_PROBE_INTERVAL_MS: positiveInt.default(5000),
    WORKER_PROBE_TIMEOUT_MS: positiveInt.default(2000),
  })
  .passthrough();

export interface WorkerConfig {
  NODE_ENV: 'development' | 'test' | 'production';
  POSTGRES_HOST: string;
  POSTGRES_PORT: number;
  POSTGRES_DB: string;
  POSTGRES_USER: string;
  POSTGRES_PASSWORD: string;
  REDIS_HOST: string;
  REDIS_PORT: number;
  REDIS_USER: string;
  REDIS_PASSWORD: string;
  REDIS_MAXMEMORY_POLICY: string;
  REDIS_TLS: boolean;
  WORKER_HEALTH_FILE: string;
  WORKER_PROBE_INTERVAL_MS: number;
  WORKER_PROBE_TIMEOUT_MS: number;
}

export function parseWorkerConfig(
  rawEnv: Record<string, string | undefined> = process.env,
): WorkerConfig {
  const issues: string[] = [];

  // Check 1: Forbidden security flags
  for (const flag of FORBIDDEN_SECURITY_FLAGS) {
    if (flag in rawEnv && rawEnv[flag] !== undefined && rawEnv[flag] !== '') {
      issues.push(`Forbidden security flag detected: ${flag}`);
    }
  }

  // Check 2: Worker must never have KEKs or provider key decryption material (Architecture §14, §19.4)
  const kekVars = ['MASTER_KEK_V1', 'MASTER_KEK_V2', 'ACTIVE_KEK_VERSION'];
  for (const v of kekVars) {
    if (rawEnv[v] !== undefined && rawEnv[v] !== '') {
      issues.push(
        `Worker runtime must not have access to provider encryption keys or KEKs: ${v} is forbidden`,
      );
    }
  }

  // Check 3: Schema parse using safe formatting to prevent raw value leakage
  const parseResult = workerEnvSchema.safeParse(rawEnv);
  if (!parseResult.success) {
    for (const issue of parseResult.error.issues) {
      const fieldPath = issue.path.join('.') || 'environment';
      const isSensitive = SENSITIVE_FIELD_NAMES.has(fieldPath) || isSensitiveKey(fieldPath);
      const safeMessage = isSensitive
        ? 'Invalid value provided for sensitive credential'
        : formatSafeZodMessage(issue);
      issues.push(`${fieldPath}: ${safeMessage}`);
    }
  }

  // Check 4: Invariant - PostgreSQL identity must strictly be gateway_worker (never interpolate raw user input)
  const pgUser = rawEnv.POSTGRES_USER ?? 'gateway_worker';
  if (pgUser !== 'gateway_worker') {
    issues.push(
      "POSTGRES_USER: Worker must connect under the restricted 'gateway_worker' database role",
    );
  }

  // Check 5: Invariant - Redis identity must strictly be restricted worker ACL identity, never default or gateway_app
  const redisUser = rawEnv.REDIS_USER ?? 'switchyard_worker';
  if (redisUser === 'default' || redisUser === 'gateway_app') {
    issues.push(
      'REDIS_USER: Worker cannot use default or gateway_app Redis identity; a dedicated restricted worker ACL identity is required',
    );
  }

  if (issues.length > 0) {
    throw new WorkerConfigValidationError(issues);
  }

  return parseResult.data as WorkerConfig;
}
