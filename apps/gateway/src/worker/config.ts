import { z } from 'zod';

export class WorkerConfigValidationError extends Error {
  public readonly issues: string[];

  constructor(issues: string[]) {
    super(`Worker configuration validation failed: ${issues.join('; ')}`);
    this.name = 'WorkerConfigValidationError';
    this.issues = issues;
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

  // Check 3: Schema parse
  const parseResult = workerEnvSchema.safeParse(rawEnv);
  if (!parseResult.success) {
    for (const issue of parseResult.error.issues) {
      const fieldPath = issue.path.join('.');
      issues.push(`${fieldPath}: ${issue.message}`);
    }
  }

  // Check 4: Invariant - PostgreSQL identity must strictly be gateway_worker
  const pgUser = rawEnv.POSTGRES_USER ?? 'gateway_worker';
  if (pgUser !== 'gateway_worker') {
    issues.push(
      `Worker must connect under the restricted 'gateway_worker' database role (attempted: '${pgUser}')`,
    );
  }

  // Check 5: Invariant - Redis identity must strictly be restricted worker ACL identity, never default or gateway_app
  const redisUser = rawEnv.REDIS_USER ?? 'switchyard_worker';
  if (redisUser === 'default' || redisUser === 'gateway_app') {
    issues.push(
      `Worker cannot use '${redisUser}' Redis identity; a dedicated restricted worker ACL identity is required`,
    );
  }

  if (issues.length > 0) {
    throw new WorkerConfigValidationError(issues);
  }

  return parseResult.data as WorkerConfig;
}
