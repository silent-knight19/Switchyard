import { z } from 'zod';
import type { ConfigIssue } from './errors.js';
import { isSensitiveKey } from '../logging/redaction.js';
import { formatSafeZodMessage } from '../logging/serializers.js';

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
  'SESSION_SECRET',
  'COOKIE_SECRET',
  'CSRF_SECRET',
  'MASTER_KEY',
  'KEK',
  'DEK',
  'API_KEY',
]);

const strictBoolean = z.string().transform((val, ctx) => {
  if (val === 'true') return true;
  if (val === 'false') return false;
  ctx.addIssue({
    code: z.ZodIssueCode.custom,
    message: 'Expected "true" or "false"',
  });
  return z.NEVER;
});

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

export const rawEnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']),
    PORT: portNumber.default(3000),
    HOST: z.string().min(1).default('127.0.0.1'),

    // PostgreSQL
    POSTGRES_HOST: z.string().min(1).default('127.0.0.1'),
    POSTGRES_PORT: portNumber.default(5432),
    POSTGRES_DB: z.string().min(1).default('switchyard'),
    POSTGRES_USER: z.string().min(1).default('switchyard'),
    POSTGRES_PASSWORD: z.string().min(1).default('switchyard_dev_password'),

    // Redis
    REDIS_HOST: z.string().min(1).default('127.0.0.1'),
    REDIS_PORT: portNumber.default(6379),
    REDIS_USER: z.string().min(1).default('switchyard_app'),
    REDIS_PASSWORD: z.string().min(1).default('switchyard_app_password'),
    REDIS_MAXMEMORY_POLICY: z.string().default('noeviction'),
    REDIS_TLS: strictBoolean.default(false),

    // Security & Feature Flags
    COOKIE_SECURE: strictBoolean.default(false),
    TLS_VERIFY: strictBoolean.default(true),
    MOCK_PROVIDER_ENABLED: strictBoolean.default(false),
    DEMO_SEEDING_ENABLED: strictBoolean.default(false),

    // Optional Upstream Endpoints
    UPSTREAM_ENDPOINT_URL: z
      .string()
      .refine(
        (val) => {
          try {
            const url = new URL(val);
            if (url.protocol !== 'http:' && url.protocol !== 'https:') {
              return false;
            }
            // Reject embedded credentials in URLs (e.g. http://user:pass@host)
            if (url.username || url.password) {
              return false;
            }
            return true;
          } catch {
            return false;
          }
        },
        {
          message:
            'Malformed endpoint URL: expected valid http:// or https:// URL without embedded credentials',
        },
      )
      .optional(),
  })
  .superRefine((data, ctx) => {
    // Invariant: Redis maxmemory-policy must be noeviction across all profiles
    if (data.REDIS_MAXMEMORY_POLICY !== 'noeviction') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['REDIS_MAXMEMORY_POLICY'],
        message: 'Unsafe Redis policy: must be "noeviction" to prevent silent monetary eviction',
      });
    }

    // Invariants for production profile
    if (data.NODE_ENV === 'production') {
      // Invariant (R6): Production upstream origin restrictions
      if (data.UPSTREAM_ENDPOINT_URL !== undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['UPSTREAM_ENDPOINT_URL'],
          message:
            'Custom upstream endpoint URL overrides are prohibited in production profile pending provider allowlist specification',
        });
      }
      if (!data.COOKIE_SECURE) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['COOKIE_SECURE'],
          message: 'Production profile requires secure cookies (COOKIE_SECURE=true)',
        });
      }

      if (!data.TLS_VERIFY) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['TLS_VERIFY'],
          message: 'Production profile requires TLS verification (TLS_VERIFY=true)',
        });
      }

      if (data.MOCK_PROVIDER_ENABLED) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['MOCK_PROVIDER_ENABLED'],
          message: 'Mock provider is prohibited in production profile',
        });
      }

      if (data.DEMO_SEEDING_ENABLED) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['DEMO_SEEDING_ENABLED'],
          message: 'Demo seeding is prohibited in production profile',
        });
      }

      // Default development credentials must be rejected in production
      const insecureDevPasswords = [
        'switchyard_dev_password',
        'switchyard_app_password',
        'password',
        'postgres',
        'admin',
        'root',
      ];
      if (insecureDevPasswords.includes(data.POSTGRES_PASSWORD)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['POSTGRES_PASSWORD'],
          message: 'Default development credentials are prohibited in production profile',
        });
      }
      if (insecureDevPasswords.includes(data.REDIS_PASSWORD)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['REDIS_PASSWORD'],
          message: 'Default development credentials are prohibited in production profile',
        });
      }
    }
  });

export type GatewayConfig = z.infer<typeof rawEnvSchema>;

export function parseConfig(envInput: Record<string, string | undefined>):
  | {
      success: true;
      data: GatewayConfig;
    }
  | {
      success: false;
      issues: ConfigIssue[];
    } {
  const issues: ConfigIssue[] = [];

  // Check 1: Forbidden fail-open or security bypass flags
  for (const flag of FORBIDDEN_SECURITY_FLAGS) {
    if (flag in envInput && envInput[flag] !== undefined && envInput[flag] !== '') {
      issues.push({
        field: flag,
        message: 'Forbidden security bypass flag detected. Switchyard is strictly fail-closed.',
      });
    }
  }

  // Check 2: Node.js global TLS rejection setting
  if (envInput['NODE_ENV'] === 'production' && envInput['NODE_TLS_REJECT_UNAUTHORIZED'] === '0') {
    issues.push({
      field: 'NODE_TLS_REJECT_UNAUTHORIZED',
      message: 'Disabling Node TLS verification is prohibited in production.',
    });
  }

  const result = rawEnvSchema.safeParse(envInput);

  if (!result.success) {
    for (const zodIssue of result.error.issues) {
      const field = zodIssue.path.join('.') || 'environment';
      // Ensure no sensitive values are echoed in error messages
      const isSensitive = SENSITIVE_FIELD_NAMES.has(field) || isSensitiveKey(field);
      const safeMessage = isSensitive
        ? 'Invalid value provided for sensitive credential'
        : formatSafeZodMessage(zodIssue);

      issues.push({
        field,
        message: safeMessage,
      });
    }
  }

  if (issues.length > 0) {
    return { success: false, issues };
  }

  return { success: true, data: result.data as GatewayConfig };
}
