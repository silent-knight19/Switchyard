import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import type pg from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { BootstrapError } from '../auth/types.js';
import { EnvelopeVault } from '../vault/envelope.js';
import { parseSeedDevConfig, SeedDevError } from './seed-dev/config.js';
import {
  readPasswordFromStdin,
  SeedPasswordError,
  type PasswordInputStream,
} from './seed-dev/password.js';
import {
  runSeedDev,
  SEED_EXIT_CONFLICT,
  SEED_EXIT_FAILURE,
  SEED_EXIT_INVALID_CONFIGURATION,
  SEED_EXIT_SUCCESS,
  type SeedDevDependencies,
} from './seed-dev/run.js';

const ORG_ID = '11111111-1111-4111-8111-111111111111';
const ADMIN_EMAIL = 'demo-admin@example.test';

function resolveSourcePath(relative: string): string {
  const candidates = [
    path.join(process.cwd(), 'src', 'db', relative),
    path.join(process.cwd(), 'apps', 'gateway', 'src', 'db', relative),
  ];
  const found = candidates.find((candidate) => fs.existsSync(candidate));
  if (found === undefined) {
    throw new Error(`Could not locate seed source file ${relative}`);
  }
  return found;
}

function baseEnv(
  overrides: Record<string, string | undefined> = {},
): Record<string, string | undefined> {
  const env: Record<string, string | undefined> = {
    NODE_ENV: 'development',
    DEMO_SEEDING_ENABLED: 'true',
    DEMO_ORG_ID: ORG_ID,
    DEMO_ORG_NAME: 'Local Demo Organization',
    DEMO_ADMIN_EMAIL: ADMIN_EMAIL,
    DEMO_MONTHLY_BUDGET_MICRODOLLARS: '0',
    POSTGRES_HOST: '127.0.0.1',
    POSTGRES_PORT: '5432',
    POSTGRES_DB: 'switchyard',
    POSTGRES_USER: 'gateway_app',
    POSTGRES_PASSWORD: crypto.randomBytes(18).toString('hex'),
    MASTER_KEK_V1: crypto.randomBytes(32).toString('base64url'),
    ACTIVE_KEK_VERSION: '1',
  };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) {
      delete env[key];
    } else {
      env[key] = value;
    }
  }
  return env;
}

function configError(env: Record<string, string | undefined>): SeedDevError {
  try {
    parseSeedDevConfig(env);
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(SeedDevError);
    return error as SeedDevError;
  }
  throw new Error('Expected parseSeedDevConfig to reject the configuration');
}

function passwordError(stream: PasswordInputStream): Promise<SeedPasswordError> {
  return readPasswordFromStdin(stream).then(
    () => {
      throw new Error('Expected readPasswordFromStdin to reject the input');
    },
    (error: unknown) => {
      expect(error).toBeInstanceOf(SeedPasswordError);
      return error as SeedPasswordError;
    },
  );
}

class TestInputStream extends Readable {
  public reads = 0;
  private readonly payload: Buffer | null;

  constructor(payload: Buffer | null) {
    super();
    this.payload = payload;
  }

  public get isTTY(): boolean {
    return false;
  }

  public override _read(): void {
    this.reads += 1;
    if (this.payload !== null) {
      this.push(this.payload);
    }
    this.push(null);
  }
}

interface FakePoolOptions {
  lookupRows?: Array<Array<{ id: string; org_id: string; role: string }>>;
  identity?: {
    current_user: string;
    session_user: string;
    is_superuser: boolean;
    bypasses_rls: boolean;
  };
}

function createFakePool(options: FakePoolOptions = {}): {
  pool: pg.Pool;
  state: { queries: string[]; ended: boolean; identityCalls: number };
} {
  const state = { queries: [] as string[], ended: false, identityCalls: 0 };
  let lookupIndex = 0;

  const pool = {
    query: async (text: string) => {
      state.queries.push(text);
      if (text.includes('pg_catalog.pg_roles')) {
        state.identityCalls += 1;
        const identity = options.identity ?? {
          current_user: 'gateway_app',
          session_user: 'gateway_app',
          is_superuser: false,
          bypasses_rls: false,
        };
        return { rows: [identity], rowCount: 1, command: 'SELECT', oid: 0, fields: [] };
      }
      if (text.includes('lookup_user_for_login')) {
        const rows = options.lookupRows?.[lookupIndex] ?? [];
        lookupIndex += 1;
        return { rows, rowCount: rows.length, command: 'SELECT', oid: 0, fields: [] };
      }
      throw new Error(`Unexpected query in seed unit test: ${text}`);
    },
    end: async () => {
      state.ended = true;
    },
  };

  return { pool: pool as unknown as pg.Pool, state };
}

function createDependencies(
  pool: pg.Pool,
  overrides: Partial<SeedDevDependencies> = {},
): SeedDevDependencies & {
  createPool: ReturnType<typeof vi.fn>;
  bootstrap: ReturnType<typeof vi.fn>;
} {
  const createPool = vi.fn(() => pool);
  const bootstrap = vi.fn(async () => ({
    orgId: ORG_ID,
    adminUserId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  }));
  const verifyExistingEnvelope = vi.fn(async () => undefined);
  return {
    createPool,
    bootstrap,
    createVault: (keyring) => new EnvelopeVault(keyring),
    verifyExistingEnvelope,
    ...overrides,
  } as SeedDevDependencies & {
    createPool: ReturnType<typeof vi.fn>;
    bootstrap: ReturnType<typeof vi.fn>;
  };
}

async function executeRun(params: {
  env?: Record<string, string | undefined>;
  password?: string | null;
  dependencies?: Partial<SeedDevDependencies>;
  argv?: string[];
}): Promise<{
  code: number;
  stdout: string;
  stderr: string;
  stdin: TestInputStream;
}> {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const stdin = new TestInputStream(
    params.password === null || params.password === undefined
      ? null
      : Buffer.from(params.password, 'utf8'),
  );

  const code = await runSeedDev({
    env: params.env ?? baseEnv(),
    stdin,
    stdout: { write: (chunk) => stdout.push(chunk) },
    stderr: { write: (chunk) => stderr.push(chunk) },
    ...(params.argv === undefined ? {} : { argv: params.argv }),
    ...(params.dependencies === undefined ? {} : { dependencies: params.dependencies }),
  });

  return { code, stdout: stdout.join(''), stderr: stderr.join(''), stdin };
}

describe('SW-P1-B02 seed configuration', () => {
  it('accepts a valid explicit development configuration with safe defaults', () => {
    const env = baseEnv();
    const config = parseSeedDevConfig(env);

    expect(config.orgId).toBe(ORG_ID);
    expect(config.orgName).toBe('Local Demo Organization');
    expect(config.adminEmail).toBe(ADMIN_EMAIL);
    expect(config.monthlyBudgetMicrodollars).toBe(0n);
    expect(config.target).toBe('local');
    expect(config.activeKekVersion).toBe(1);
    expect(config.database).toEqual({
      host: '127.0.0.1',
      port: 5432,
      database: 'switchyard',
      user: 'gateway_app',
      password: env.POSTGRES_PASSWORD,
    });
  });

  it('accepts an explicit nonnegative budget and the approved Compose target', () => {
    const config = parseSeedDevConfig(
      baseEnv({
        DEMO_MONTHLY_BUDGET_MICRODOLLARS: '5000000',
        DEMO_SEEDING_TARGET: 'compose',
        POSTGRES_HOST: 'postgres',
      }),
    );
    expect(config.monthlyBudgetMicrodollars).toBe(5000000n);
    expect(config.target).toBe('compose');
    expect(config.database.host).toBe('postgres');
  });

  it('requires the explicit DEMO_SEEDING_ENABLED=true flag', () => {
    expect(configError(baseEnv({ DEMO_SEEDING_ENABLED: undefined })).code).toBe('SEEDING_DISABLED');
    expect(configError(baseEnv({ DEMO_SEEDING_ENABLED: 'false' })).code).toBe('SEEDING_DISABLED');
    expect(configError(baseEnv({ DEMO_SEEDING_ENABLED: '1' })).code).toBe('SEEDING_DISABLED');
  });

  it('rejects production even when DEMO_SEEDING_ENABLED=true', () => {
    expect(
      configError(baseEnv({ NODE_ENV: 'production', DEMO_SEEDING_ENABLED: 'true' })).code,
    ).toBe('PRODUCTION_FORBIDDEN');
  });

  it('rejects the test profile and missing NODE_ENV for executable CLI configuration', () => {
    expect(configError(baseEnv({ NODE_ENV: 'test' })).code).toBe('ENVIRONMENT_FORBIDDEN');
    expect(configError(baseEnv({ NODE_ENV: undefined })).code).toBe('ENVIRONMENT_FORBIDDEN');
    expect(configError(baseEnv({ NODE_ENV: 'staging' })).code).toBe('ENVIRONMENT_FORBIDDEN');
  });

  it('rejects non-canonical or malformed organization UUIDs', () => {
    expect(configError(baseEnv({ DEMO_ORG_ID: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' })).code).toBe(
      'INVALID_ORG_ID',
    );
    expect(configError(baseEnv({ DEMO_ORG_ID: 'not-a-uuid' })).code).toBe('INVALID_ORG_ID');
    expect(configError(baseEnv({ DEMO_ORG_ID: undefined })).code).toBe('INVALID_ORG_ID');
    expect(configError(baseEnv({ DEMO_ORG_ID: '11111111-1111-4111-8111-11111111111g' })).code).toBe(
      'INVALID_ORG_ID',
    );
  });

  it('rejects invalid organization names', () => {
    expect(configError(baseEnv({ DEMO_ORG_NAME: '' })).code).toBe('INVALID_ORG_NAME');
    expect(configError(baseEnv({ DEMO_ORG_NAME: '   ' })).code).toBe('INVALID_ORG_NAME');
    expect(configError(baseEnv({ DEMO_ORG_NAME: 'a'.repeat(256) })).code).toBe('INVALID_ORG_NAME');
    expect(configError(baseEnv({ DEMO_ORG_NAME: 'bad\u0000name' })).code).toBe('INVALID_ORG_NAME');
    expect(configError(baseEnv({ DEMO_ORG_NAME: undefined })).code).toBe('INVALID_ORG_NAME');
  });

  it('requires a canonical administrator email', () => {
    expect(configError(baseEnv({ DEMO_ADMIN_EMAIL: 'Admin@Example.test' })).code).toBe(
      'INVALID_ADMIN_EMAIL',
    );
    expect(configError(baseEnv({ DEMO_ADMIN_EMAIL: 'not-an-email' })).code).toBe(
      'INVALID_ADMIN_EMAIL',
    );
    expect(configError(baseEnv({ DEMO_ADMIN_EMAIL: ' demo@example.test ' })).code).toBe(
      'INVALID_ADMIN_EMAIL',
    );
    expect(configError(baseEnv({ DEMO_ADMIN_EMAIL: undefined })).code).toBe('INVALID_ADMIN_EMAIL');
  });

  it('rejects invalid or out-of-range budgets', () => {
    for (const value of ['-1', '1.5', '1e3', ' 1', '+1', 'abc', '1000000000000001']) {
      expect(configError(baseEnv({ DEMO_MONTHLY_BUDGET_MICRODOLLARS: value })).code).toBe(
        'INVALID_BUDGET',
      );
    }
  });

  it('rejects missing, malformed, all-zero, and version-inconsistent KEK configuration', () => {
    expect(
      configError(
        baseEnv({
          MASTER_KEK_V1: undefined,
          MASTER_KEK_V2: undefined,
          ACTIVE_KEK_VERSION: undefined,
        }),
      ).code,
    ).toBe('MISSING_KEK');
    expect(configError(baseEnv({ MASTER_KEK_V1: 'AAAA' })).code).toBe('INVALID_KEK');
    expect(
      configError(baseEnv({ MASTER_KEK_V1: Buffer.alloc(32).toString('base64url') })).code,
    ).toBe('INVALID_KEK');
    expect(configError(baseEnv({ ACTIVE_KEK_VERSION: undefined })).code).toBe('INVALID_KEK');
    expect(configError(baseEnv({ ACTIVE_KEK_VERSION: '3' })).code).toBe('INVALID_KEK');
    expect(
      configError(
        baseEnv({
          MASTER_KEK_V1: undefined,
          MASTER_KEK_V2: crypto.randomBytes(32).toString('base64url'),
          ACTIVE_KEK_VERSION: '1',
        }),
      ).code,
    ).toBe('INVALID_KEK');
  });

  it('rejects remote, wildcard, private-network and non-Compose hostnames', () => {
    for (const host of ['db.example.com', '10.0.0.5', '192.168.1.5', '0.0.0.0', 'postgres']) {
      expect(configError(baseEnv({ POSTGRES_HOST: host })).code).toBe('INVALID_DATABASE_TARGET');
    }
  });

  it('requires the approved Compose hostname when DEMO_SEEDING_TARGET=compose', () => {
    expect(
      configError(baseEnv({ DEMO_SEEDING_TARGET: 'compose', POSTGRES_HOST: '127.0.0.1' })).code,
    ).toBe('INVALID_DATABASE_TARGET');
    expect(configError(baseEnv({ DEMO_SEEDING_TARGET: 'staging' })).code).toBe(
      'INVALID_SEED_TARGET',
    );
  });

  it('rejects privileged or non-runtime database identities and connection overrides', () => {
    for (const user of [
      'switchyard',
      'postgres',
      'gateway_owner',
      'gateway_migrator',
      'gateway_auth_executor',
      'gateway_ops_executor',
      'gateway_worker',
      '',
    ]) {
      expect(configError(baseEnv({ POSTGRES_USER: user })).code).toBe(
        'UNSUPPORTED_DATABASE_IDENTITY',
      );
    }
    expect(configError(baseEnv({ DATABASE_URL: 'postgres://example/db' })).code).toBe(
      'UNSUPPORTED_CONNECTION_OVERRIDE',
    );
    expect(configError(baseEnv({ PGPASSWORD: 'override' })).code).toBe(
      'UNSUPPORTED_CONNECTION_OVERRIDE',
    );
    expect(configError(baseEnv({ PGPASSFILE: '/tmp/pgpass' })).code).toBe(
      'UNSUPPORTED_CONNECTION_OVERRIDE',
    );
    expect(configError(baseEnv({ PGOPTIONS: '-c role=gateway_owner' })).code).toBe(
      'UNSUPPORTED_CONNECTION_OVERRIDE',
    );
    expect(configError(baseEnv({ MIGRATE_POSTGRES_USER: 'gateway_migrator' })).code).toBe(
      'UNSUPPORTED_CONNECTION_OVERRIDE',
    );
    expect(configError(baseEnv({ BOOTSTRAP_POSTGRES_USER: 'switchyard' })).code).toBe(
      'UNSUPPORTED_CONNECTION_OVERRIDE',
    );
  });

  it('rejects invalid ports, database names, and missing database credentials', () => {
    for (const port of ['0', '65536', 'abc', '5432.0', '']) {
      expect(configError(baseEnv({ POSTGRES_PORT: port })).code).toBe('INVALID_DATABASE_PORT');
    }
    expect(configError(baseEnv({ POSTGRES_DB: 'bad name' })).code).toBe('INVALID_DATABASE_NAME');
    expect(configError(baseEnv({ POSTGRES_PASSWORD: undefined })).code).toBe(
      'MISSING_DATABASE_CREDENTIAL',
    );
    expect(configError(baseEnv({ POSTGRES_PASSWORD: '' })).code).toBe(
      'MISSING_DATABASE_CREDENTIAL',
    );
  });
});

describe('SW-P1-B02 bounded stdin password input', () => {
  it('preserves password contents exactly without trimming or transforming them', async () => {
    await expect(
      readPasswordFromStdin(Readable.from([Buffer.from('  Spaced Password!  ')])),
    ).resolves.toBe('  Spaced Password!  ');
    // A trailing newline is part of the password; documentation uses printf '%s' rather than echo.
    await expect(readPasswordFromStdin(Readable.from([Buffer.from('pw\n')]))).resolves.toBe('pw\n');
  });

  it('rejects empty input', async () => {
    expect((await passwordError(Readable.from([]))).code).toBe('EMPTY_PASSWORD');
  });

  it('accepts exactly 128 UTF-8 bytes and rejects 129 bytes', async () => {
    await expect(
      readPasswordFromStdin(Readable.from([Buffer.from('a'.repeat(128))])),
    ).resolves.toBe('a'.repeat(128));
    expect((await passwordError(Readable.from([Buffer.from('a'.repeat(129))]))).code).toBe(
      'PASSWORD_TOO_LONG',
    );
    await expect(
      readPasswordFromStdin(Readable.from([Buffer.from('é'.repeat(64), 'utf8')])),
    ).resolves.toBe('é'.repeat(64));
    expect((await passwordError(Readable.from([Buffer.from('é'.repeat(65), 'utf8')]))).code).toBe(
      'PASSWORD_TOO_LONG',
    );
  });

  it('reassembles UTF-8 sequences split across stream chunks', async () => {
    const encoded = Buffer.from('é', 'utf8');
    await expect(
      readPasswordFromStdin(Readable.from([encoded.subarray(0, 1), encoded.subarray(1)])),
    ).resolves.toBe('é');
    expect((await passwordError(Readable.from([encoded.subarray(0, 1)]))).code).toBe(
      'INVALID_PASSWORD_ENCODING',
    );
  });

  it('rejects malformed UTF-8 without echoing the bytes', async () => {
    const error = await passwordError(Readable.from([Buffer.from([0xff, 0xfe, 0xfd])]));
    expect(error.code).toBe('INVALID_PASSWORD_ENCODING');
    expect(error.message).not.toContain('255');
  });

  it('rejects interactive stdin because no no-echo mechanism is implemented', async () => {
    const stream = Readable.from([]) as unknown as PasswordInputStream & { isTTY: boolean };
    Object.defineProperty(stream, 'isTTY', { value: true });
    const error = await passwordError(stream);
    expect(error.code).toBe('INTERACTIVE_STDIN_FORBIDDEN');
  });

  it('bounds oversized input before collecting an unbounded buffer', async () => {
    const error = await passwordError(Readable.from([Buffer.alloc(1024, 0x41)]));
    expect(error.code).toBe('PASSWORD_TOO_LONG');
  });

  it('reports stdin read failures as a controlled classification', async () => {
    const stream = new Readable({
      read() {
        this.destroy(new Error('synthetic stdin failure with CANARY_STDIN'));
      },
    });
    const error = await passwordError(stream);
    expect(error.code).toBe('STDIN_READ_FAILED');
    expect(error.message).not.toContain('CANARY_STDIN');
  });
});

describe('SW-P1-B02 seed CLI behavior', () => {
  it('creates the demo account and reports only safe operational metadata', async () => {
    const env = baseEnv();
    const password = 'CANARY_ADMIN_PASSWORD_9f2c!';
    const { pool, state } = createFakePool({ lookupRows: [[]] });
    const dependencies = createDependencies(pool);

    const result = await executeRun({ env, password, dependencies });

    expect(result.code).toBe(SEED_EXIT_SUCCESS);
    expect(result.stdout).toContain('Demo organization provisioned');
    expect(result.stdout).toContain('Status: CREATED');
    expect(result.stdout).toContain(ORG_ID);
    expect(state.ended).toBe(true);
    expect(dependencies.bootstrap).toHaveBeenCalledTimes(1);
    expect(dependencies.createPool).toHaveBeenCalledTimes(1);

    const combined = result.stdout + result.stderr;
    for (const secret of [password, env.MASTER_KEK_V1 ?? '', env.POSTGRES_PASSWORD ?? '']) {
      expect(combined).not.toContain(secret);
    }
    expect(combined).not.toContain('$argon2');
    expect(combined).not.toContain('wrappedDek');
    expect(combined).not.toContain('authTag');

    // No Gateway singleton advisory lock and no HTTP server startup.
    for (const query of state.queries) {
      expect(query.toLowerCase()).not.toContain('advisory');
    }
    expect(state.identityCalls).toBe(1);
  });

  it('returns ALREADY_PRESENT for the matching existing demo identity without rewriting it', async () => {
    const { pool, state } = createFakePool({
      lookupRows: [[{ id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', org_id: ORG_ID, role: 'admin' }]],
    });
    const dependencies = createDependencies(pool);

    const result = await executeRun({ password: 'irrelevant-password', dependencies });

    expect(result.code).toBe(SEED_EXIT_SUCCESS);
    expect(result.stdout).toContain('Status: ALREADY_PRESENT');
    expect(dependencies.bootstrap).not.toHaveBeenCalled();
    expect(dependencies.createPool).toHaveBeenCalledTimes(1);
    expect(state.ended).toBe(true);
  });

  it('requires envelope authentication before returning ALREADY_PRESENT', async () => {
    const { pool } = createFakePool({
      lookupRows: [[{ id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', org_id: ORG_ID, role: 'admin' }]],
    });
    const verifier = vi.fn(async () => undefined);
    const deps = createDependencies(pool, { verifyExistingEnvelope: verifier });
    const outcome = await executeRun({ password: 'irrelevant-password', dependencies: deps });
    expect(outcome.code).toBe(SEED_EXIT_SUCCESS);
    expect(outcome.stdout).toContain('Status: ALREADY_PRESENT');
    expect(verifier).toHaveBeenCalledOnce();
    expect(deps.bootstrap).not.toHaveBeenCalled();
  });

  it('fails closed when an existing DEK envelope cannot be authenticated', async () => {
    const { pool } = createFakePool({
      lookupRows: [[{ id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', org_id: ORG_ID, role: 'admin' }]],
    });
    const deps = createDependencies(pool, {
      verifyExistingEnvelope: vi.fn(async () => {
        throw new SeedDevError(
          'EXISTING_ENVELOPE_INVALID',
          'The existing organization envelope is incompatible with the configured KEK',
        );
      }),
    });
    const outcome = await executeRun({ password: 'irrelevant-password', dependencies: deps });
    expect(outcome.code).toBe(SEED_EXIT_FAILURE);
    expect(outcome.stdout).toBe('');
    expect(outcome.stderr).toContain('EXISTING_ENVELOPE_INVALID');
    expect(deps.bootstrap).not.toHaveBeenCalled();
  });

  it('returns CONFLICT for an email owned by another organization or a non-admin role', async () => {
    for (const row of [
      {
        id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        org_id: '22222222-2222-4222-8222-222222222222',
        role: 'admin',
      },
      { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', org_id: ORG_ID, role: 'member' },
    ]) {
      const { pool, state } = createFakePool({ lookupRows: [[row]] });
      const dependencies = createDependencies(pool);
      const result = await executeRun({ password: 'irrelevant-password', dependencies });

      expect(result.code).toBe(SEED_EXIT_CONFLICT);
      expect(result.stdout).toContain('Status: CONFLICT');
      expect(dependencies.bootstrap).not.toHaveBeenCalled();
      expect(state.ended).toBe(true);
    }
  });

  it('resolves a concurrent duplicate as ALREADY_PRESENT only after re-verifying identity', async () => {
    const { pool } = createFakePool({
      lookupRows: [
        [],
        [{ id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', org_id: ORG_ID, role: 'admin' }],
      ],
    });
    const dependencies = createDependencies(pool, {
      bootstrap: vi.fn(async () => {
        throw new BootstrapError('DUPLICATE_RESOURCE', 'synthetic duplicate');
      }),
    });

    const result = await executeRun({ password: 'irrelevant-password', dependencies });

    expect(result.code).toBe(SEED_EXIT_SUCCESS);
    expect(result.stdout).toContain('Status: ALREADY_PRESENT');
    expect(dependencies.bootstrap).toHaveBeenCalledTimes(1);
  });

  it('resolves a concurrent duplicate against a different organization as CONFLICT', async () => {
    const { pool } = createFakePool({
      lookupRows: [
        [],
        [
          {
            id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            org_id: '22222222-2222-4222-8222-222222222222',
            role: 'admin',
          },
        ],
      ],
    });
    const dependencies = createDependencies(pool, {
      bootstrap: vi.fn(async () => {
        throw new BootstrapError('DUPLICATE_RESOURCE', 'synthetic duplicate');
      }),
    });

    const result = await executeRun({ password: 'irrelevant-password', dependencies });

    expect(result.code).toBe(SEED_EXIT_CONFLICT);
    expect(result.stdout).toContain('Status: CONFLICT');
  });

  it('never prints driver or bootstrap error details on failure', async () => {
    const { pool } = createFakePool({ lookupRows: [[]] });
    const dependencies = createDependencies(pool, {
      bootstrap: vi.fn(async () => {
        throw new BootstrapError(
          'BOOTSTRAP_DATABASE_ERROR',
          'connection postgres://gateway_app:CANARY_DB_PASSWORD@host/db failed with CANARY_DRIVER',
        );
      }),
    });

    const result = await executeRun({
      password: 'CANARY_ADMIN_PASSWORD',
      dependencies,
    });

    expect(result.code).toBe(SEED_EXIT_FAILURE);
    expect(result.stderr).toContain('BOOTSTRAP_DATABASE_ERROR');
    expect(result.stderr).not.toContain('CANARY_DRIVER');
    expect(result.stderr).not.toContain('CANARY_DB_PASSWORD');
    expect(result.stderr).not.toContain('CANARY_ADMIN_PASSWORD');
  });

  it('allowlists arbitrary authentication and bootstrap failure codes before writing stderr', async () => {
    const canary = 'CANARY_SECRET\\nINJECTED_LINE';
    for (const error of [
      Object.assign(new Error('untrusted'), { reason: canary }),
      Object.assign(new Error('untrusted'), { reason: 'RATE_LIMITED\\nINJECTED_LINE' }),
      new BootstrapError(canary, 'untrusted'),
    ]) {
      const { pool } = createFakePool({ lookupRows: [[]] });
      const deps = createDependencies(pool, {
        bootstrap: vi.fn(async () => {
          throw error;
        }),
      });
      const output = await executeRun({ password: 'CANARY_ADMIN_PASSWORD', dependencies: deps });
      expect(output.code).toBe(SEED_EXIT_FAILURE);
      expect(output.stderr).toContain('UNEXPECTED_ERROR');
      expect(output.stderr).not.toContain('CANARY_SECRET');
      expect(output.stderr).not.toContain('INJECTED_LINE');
      expect(output.stdout).toBe('');
    }

    const { pool } = createFakePool({ lookupRows: [[]] });
    const deps = createDependencies(pool, {
      bootstrap: vi.fn(async () => {
        throw Object.assign(new Error('untrusted'), { reason: 'SERVICE_UNAVAILABLE' });
      }),
    });
    const allowed = await executeRun({ password: 'valid-password', dependencies: deps });
    expect(allowed.stderr).toContain('SERVICE_UNAVAILABLE');
  });

  it('returns cleanup failure instead of claiming successful provisioning when pool.end rejects', async () => {
    const { pool } = createFakePool({ lookupRows: [[]] });
    pool.end = vi.fn(async () => {
      throw new Error('CANARY_DB_PASSWORD');
    });
    const deps = createDependencies(pool);
    const result = await executeRun({ password: 'valid-password', dependencies: deps });
    expect(result.code).toBe(SEED_EXIT_FAILURE);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('DATABASE_CLEANUP_FAILED');
    expect(result.stderr).not.toContain('CANARY_DB_PASSWORD');
  });

  it('bounds cleanup when pool.end never settles', async () => {
    const { pool } = createFakePool({ lookupRows: [[]] });
    pool.end = vi.fn(() => new Promise<void>(() => {}));
    const deps = createDependencies(pool);
    const started = Date.now();
    const result = await executeRun({ password: 'valid-password', dependencies: deps });
    expect(Date.now() - started).toBeLessThan(3_500);
    expect(result.code).toBe(SEED_EXIT_FAILURE);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('DATABASE_CLEANUP_FAILED');
  }, 6_000);

  it('fails closed before creating any pool for production or missing enablement', async () => {
    for (const env of [
      baseEnv({ NODE_ENV: 'production', DEMO_SEEDING_ENABLED: 'true' }),
      baseEnv({ NODE_ENV: 'test' }),
      baseEnv({ DEMO_SEEDING_ENABLED: 'false' }),
    ]) {
      const { pool } = createFakePool();
      const dependencies = createDependencies(pool);
      const result = await executeRun({
        env,
        password: 'CANARY_ADMIN_PASSWORD',
        dependencies,
      });

      expect(result.code).toBe(SEED_EXIT_INVALID_CONFIGURATION);
      expect(dependencies.createPool).not.toHaveBeenCalled();
      expect(result.stdin.reads).toBe(0);
      expect(result.stdout + result.stderr).not.toContain('CANARY_ADMIN_PASSWORD');
    }
  });

  it('fails closed before creating any pool for invalid KEK or unsupported database identity', async () => {
    for (const env of [
      baseEnv({ MASTER_KEK_V1: undefined, ACTIVE_KEK_VERSION: undefined }),
      baseEnv({ MASTER_KEK_V1: 'not-canonical' }),
      baseEnv({ POSTGRES_USER: 'gateway_migrator' }),
      baseEnv({ POSTGRES_HOST: 'db.example.com' }),
    ]) {
      const { pool } = createFakePool();
      const dependencies = createDependencies(pool);
      const result = await executeRun({
        env,
        password: 'CANARY_ADMIN_PASSWORD',
        dependencies,
      });
      expect(result.code).toBe(SEED_EXIT_INVALID_CONFIGURATION);
      expect(dependencies.createPool).not.toHaveBeenCalled();
      expect(result.stdin.reads).toBe(0);
    }
  });

  it('rejects command-line arguments, including --password forms, before connecting', async () => {
    const { pool } = createFakePool();
    const dependencies = createDependencies(pool);
    const result = await executeRun({
      password: 'CANARY_ADMIN_PASSWORD',
      dependencies,
      argv: ['--password=CANARY_ARGUMENT_SECRET'],
    });

    expect(result.code).toBe(SEED_EXIT_INVALID_CONFIGURATION);
    expect(dependencies.createPool).not.toHaveBeenCalled();
    expect(result.stdin.reads).toBe(0);
    expect(result.stdout + result.stderr).not.toContain('CANARY_ARGUMENT_SECRET');
  });

  it('rejects a missing password without creating a pool', async () => {
    const { pool } = createFakePool();
    const dependencies = createDependencies(pool);
    const result = await executeRun({ password: null, dependencies });

    expect(result.code).toBe(SEED_EXIT_INVALID_CONFIGURATION);
    expect(result.stderr).toContain('EMPTY_PASSWORD');
    expect(dependencies.createPool).not.toHaveBeenCalled();
  });

  it('rejects an overlong password without creating a pool', async () => {
    const { pool } = createFakePool();
    const dependencies = createDependencies(pool);
    const result = await executeRun({ password: 'a'.repeat(129), dependencies });

    expect(result.code).toBe(SEED_EXIT_INVALID_CONFIGURATION);
    expect(result.stderr).toContain('PASSWORD_TOO_LONG');
    expect(dependencies.createPool).not.toHaveBeenCalled();
  });

  it('verifies the effective role is non-superuser, non-bypassing gateway_app', async () => {
    for (const identity of [
      {
        current_user: 'switchyard',
        session_user: 'switchyard',
        is_superuser: true,
        bypasses_rls: false,
      },
      {
        current_user: 'gateway_app',
        session_user: 'gateway_app',
        is_superuser: false,
        bypasses_rls: true,
      },
    ]) {
      const { pool } = createFakePool({ lookupRows: [[]], identity });
      const dependencies = createDependencies(pool);
      const result = await executeRun({ password: 'irrelevant-password', dependencies });

      expect(result.code).toBe(SEED_EXIT_FAILURE);
      expect(result.stderr).toContain('UNSUPPORTED_DATABASE_IDENTITY');
      expect(dependencies.bootstrap).not.toHaveBeenCalled();
    }
  });

  it('contains no HTTP server, singleton lock, or Redis dependency in the executable path', () => {
    const cliSource = fs.readFileSync(resolveSourcePath('seed-dev.ts'), 'utf8');
    const runSource = fs.readFileSync(resolveSourcePath('seed-dev/run.ts'), 'utf8');
    const combined = `${cliSource}\n${runSource}`;

    expect(combined).not.toContain('startServer');
    expect(combined).not.toContain('server.js');
    expect(combined).not.toContain('app.js');
    expect(combined).not.toContain('.listen(');
    expect(combined).not.toContain('pg_advisory_lock');
    expect(combined).not.toContain('ioredis');
    expect(combined).not.toContain('LoginRateLimiter');
  });

  it('is not wired into Compose, migrations, Gateway startup, or the worker', () => {
    const repositoryRoot = fs.existsSync(path.join(process.cwd(), 'docker-compose.yml'))
      ? process.cwd()
      : path.resolve(process.cwd(), '..', '..');

    for (const relative of [
      'docker-compose.yml',
      'Dockerfile',
      'apps/gateway/src/db/migrate.ts',
      'apps/gateway/src/index.ts',
      'apps/gateway/src/worker-main.ts',
    ]) {
      const source = fs.readFileSync(path.join(repositoryRoot, relative), 'utf8');
      expect(source, relative).not.toContain('seed-dev');
      expect(source, relative).not.toContain('seed:dev');
      expect(source, relative).not.toContain('DEMO_SEEDING_ENABLED');
    }
  });
});
