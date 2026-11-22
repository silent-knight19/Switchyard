import pg from 'pg';
import { bootstrapOrganizationWithAdmin } from '../../auth/bootstrap.js';
import type { AuthenticationError } from '../../auth/types.js';
import { BootstrapError, type InternalBootstrapParams } from '../../auth/types.js';
import { EnvelopeVault } from '../../vault/envelope.js';
import type { KekKeyring } from '../../vault/kek.js';
import {
  parseSeedDevConfig,
  SeedDevError,
  type SeedDevConfig,
  type SeedDevDatabaseTarget,
  type SeedDevEnvironment,
} from './config.js';
import { readPasswordFromStdin, SeedPasswordError, type PasswordInputStream } from './password.js';

/**
 * Explicit development-only demo account provisioning (SW-P1-B02).
 *
 * This module is intentionally independent of the Fastify HTTP server and of Redis. It validates
 * the development-only configuration, reads the administrator password from stdin, connects as the
 * restricted `gateway_app` role, creates a real organization DEK envelope with the existing
 * `EnvelopeVault`, and delegates atomic organization + administrator creation to the existing
 * privileged bootstrap operation.
 */

export type SeedStatus = 'CREATED' | 'ALREADY_PRESENT' | 'CONFLICT';

export const SEED_EXIT_SUCCESS = 0;
export const SEED_EXIT_FAILURE = 1;
export const SEED_EXIT_INVALID_CONFIGURATION = 2;
export const SEED_EXIT_CONFLICT = 3;

export interface SeedResult {
  readonly status: SeedStatus;
  readonly orgId: string;
}

export interface SeedDevDependencies {
  createPool(target: SeedDevDatabaseTarget): pg.Pool;
  bootstrap(
    pool: pg.Pool,
    params: InternalBootstrapParams,
  ): Promise<{ orgId: string; adminUserId: string }>;
  createVault(keyring: KekKeyring): Pick<EnvelopeVault, 'createOrganizationEnvelope'>;
}

export interface OutputWriter {
  write(chunk: string): unknown;
}

export interface RunSeedDevOptions {
  env: SeedDevEnvironment;
  stdin: PasswordInputStream;
  stdout: OutputWriter;
  stderr: OutputWriter;
  argv?: readonly string[];
  dependencies?: Partial<SeedDevDependencies>;
}

interface ExistingAdminRow {
  id: string;
  org_id: string;
  role: string;
}

function createDefaultPool(target: SeedDevDatabaseTarget): pg.Pool {
  const pool = new pg.Pool({
    host: target.host,
    port: target.port,
    database: target.database,
    user: target.user,
    password: target.password,
    max: 1,
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 1_000,
    query_timeout: 10_000,
    statement_timeout: 10_000,
    application_name: 'switchyard-seed-dev',
  });
  // A short-lived pool can still observe a late idle-client error after an operation failed.
  // Query failures are handled at the call site; this listener only prevents an unhandled event.
  pool.on('error', () => undefined);
  return pool;
}

const DEFAULT_DEPENDENCIES: SeedDevDependencies = {
  createPool: createDefaultPool,
  bootstrap: (pool, params) => bootstrapOrganizationWithAdmin(pool, params),
  createVault: (keyring) => new EnvelopeVault(keyring),
};

async function lookupExistingAdmin(
  pool: pg.Pool,
  canonicalEmail: string,
): Promise<ExistingAdminRow | undefined> {
  const { rows } = await pool.query<ExistingAdminRow>(
    'SELECT id, org_id, role FROM app_private.lookup_user_for_login($1)',
    [canonicalEmail],
  );
  return rows[0];
}

/**
 * Verify the effective database identity after connecting. Configuration already requires
 * `gateway_app`, but a drifted role must not silently execute the privileged bootstrap as a
 * superuser or RLS-bypassing role.
 */
async function verifyDatabaseIdentity(pool: pg.Pool, expectedUser: string): Promise<void> {
  const { rows } = await pool.query<{
    current_user: string;
    session_user: string;
    is_superuser: boolean;
    bypasses_rls: boolean;
  }>(
    `SELECT
       current_user::text AS current_user,
       session_user::text AS session_user,
       r.rolsuper AS is_superuser,
       r.rolbypassrls AS bypasses_rls
     FROM pg_catalog.pg_roles r
     WHERE r.rolname = current_user`,
  );

  const identity = rows[0];
  if (
    !identity ||
    identity.current_user !== expectedUser ||
    identity.session_user !== expectedUser ||
    identity.is_superuser !== false ||
    identity.bypasses_rls !== false
  ) {
    throw new SeedDevError(
      'UNSUPPORTED_DATABASE_IDENTITY',
      'Connected database role is not the restricted non-bypassing gateway_app runtime role',
    );
  }
}

function classifyExisting(row: ExistingAdminRow, config: SeedDevConfig): SeedStatus {
  return row.org_id === config.orgId && row.role === 'admin' ? 'ALREADY_PRESENT' : 'CONFLICT';
}

/**
 * Provision or verify the demo account. The stable organization UUID plus the canonical admin
 * email and admin role identify an existing demo account; an arbitrary email collision or a
 * different organization is reported as CONFLICT without modifying any record.
 */
export async function seedDemoAccount(
  pool: pg.Pool,
  config: SeedDevConfig,
  adminPassword: string,
  dependencies: SeedDevDependencies = DEFAULT_DEPENDENCIES,
): Promise<SeedResult> {
  await verifyDatabaseIdentity(pool, config.database.user);

  const existing = await lookupExistingAdmin(pool, config.adminEmail);
  if (existing) {
    return { status: classifyExisting(existing, config), orgId: config.orgId };
  }

  const vault = dependencies.createVault(config.keyring);
  const envelope = vault.createOrganizationEnvelope(config.orgId);

  const params: InternalBootstrapParams = {
    orgId: config.orgId,
    orgName: config.orgName,
    monthlyBudgetMicrodollars: config.monthlyBudgetMicrodollars,
    kekVersion: envelope.kekVersion,
    wrappedDek: envelope.wrappedDek,
    dekIv: envelope.dekIv,
    dekAuthTag: envelope.dekAuthTag,
    adminEmail: config.adminEmail,
    adminPassword,
  };

  try {
    await dependencies.bootstrap(pool, params);
    return { status: 'CREATED', orgId: config.orgId };
  } catch (error: unknown) {
    if (error instanceof BootstrapError && error.code === 'DUPLICATE_RESOURCE') {
      // A concurrent invocation may have created the same demo identity after our pre-check.
      const raced = await lookupExistingAdmin(pool, config.adminEmail);
      if (raced) {
        return { status: classifyExisting(raced, config), orgId: config.orgId };
      }
      return { status: 'CONFLICT', orgId: config.orgId };
    }
    throw error;
  }
}

function writeStatus(stdout: OutputWriter, result: SeedResult): void {
  if (result.status === 'CREATED') {
    stdout.write('Demo organization provisioned\n');
  } else if (result.status === 'ALREADY_PRESENT') {
    stdout.write('Demo organization already exists\n');
  } else {
    stdout.write(
      'Demo seed conflict: existing identity does not match the requested demo organization\n',
    );
  }
  stdout.write(`Status: ${result.status}\n`);
  stdout.write(`Organization: ${result.orgId}\n`);
}

function writeRejection(stderr: OutputWriter, error: SeedDevError): void {
  stderr.write(`Demo seeding rejected: ${error.message} (${error.code})\n`);
}

function writePasswordRejection(stderr: OutputWriter, error: SeedPasswordError): void {
  stderr.write(`Demo seeding rejected: ${error.message} (${error.code})\n`);
}

function writeOperationalFailure(stderr: OutputWriter, error: unknown): void {
  if (error instanceof SeedDevError) {
    writeRejection(stderr, error);
    return;
  }
  if (error instanceof BootstrapError) {
    stderr.write(`Demo seeding failed: ${error.code}\n`);
    return;
  }
  const authReason =
    error instanceof Error && 'reason' in error && typeof error.reason === 'string'
      ? (error as AuthenticationError).reason
      : undefined;
  if (authReason !== undefined) {
    stderr.write(`Demo seeding failed: ${authReason}\n`);
    return;
  }
  stderr.write('Demo seeding failed: UNEXPECTED_ERROR\n');
}

async function runSeedDevInternal(options: RunSeedDevOptions): Promise<number> {
  const { env, stdin, stdout, stderr } = options;
  const argv = options.argv ?? [];

  if (argv.length > 0) {
    writeRejection(
      stderr,
      new SeedDevError(
        'INVALID_ARGUMENTS',
        'Command-line arguments are not supported; provide the administrator password on stdin',
      ),
    );
    return SEED_EXIT_INVALID_CONFIGURATION;
  }

  let config: SeedDevConfig;
  try {
    config = parseSeedDevConfig(env);
  } catch (error: unknown) {
    if (error instanceof SeedDevError) {
      writeRejection(stderr, error);
      return SEED_EXIT_INVALID_CONFIGURATION;
    }
    stderr.write('Demo seeding rejected: INVALID_CONFIGURATION\n');
    return SEED_EXIT_INVALID_CONFIGURATION;
  }

  let adminPassword: string;
  try {
    adminPassword = await readPasswordFromStdin(stdin);
  } catch (error: unknown) {
    if (error instanceof SeedPasswordError) {
      writePasswordRejection(stderr, error);
      return SEED_EXIT_INVALID_CONFIGURATION;
    }
    stderr.write('Demo seeding rejected: INVALID_PASSWORD\n');
    return SEED_EXIT_INVALID_CONFIGURATION;
  }

  const dependencies: SeedDevDependencies = {
    ...DEFAULT_DEPENDENCIES,
    ...options.dependencies,
  };

  let pool: pg.Pool | undefined;
  try {
    pool = dependencies.createPool(config.database);
    const result = await seedDemoAccount(pool, config, adminPassword, dependencies);
    writeStatus(stdout, result);
    return result.status === 'CONFLICT' ? SEED_EXIT_CONFLICT : SEED_EXIT_SUCCESS;
  } catch (error: unknown) {
    writeOperationalFailure(stderr, error);
    return SEED_EXIT_FAILURE;
  } finally {
    // Drop the reference to the immutable password string as early as possible.
    adminPassword = '';
    if (pool) {
      try {
        await pool.end();
      } catch {
        // Cleanup failures are intentionally not reported with driver details.
      }
    }
  }
}

/**
 * Execute the developer CLI and return a stable, non-sensitive exit status:
 * 0 = CREATED or ALREADY_PRESENT, 2 = invalid configuration/input, 3 = identity conflict,
 * 1 = operational failure.
 */
export async function runSeedDev(options: RunSeedDevOptions): Promise<number> {
  try {
    return await runSeedDevInternal(options);
  } finally {
    try {
      options.stdin.destroy?.();
    } catch {
      // stdin teardown is best-effort and must never mask the seeding result.
    }
  }
}
