import crypto from 'node:crypto';
import pg from 'pg';
import { bootstrapOrganizationWithAdmin } from '../../auth/bootstrap.js';
import type { AuthenticationError } from '../../auth/types.js';
import { BootstrapError, type InternalBootstrapParams } from '../../auth/types.js';
import { EnvelopeVault, type OrganizationDekEnvelope } from '../../vault/envelope.js';
import { withTenant } from '../tenant.js';
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
  verifyExistingEnvelope(pool: pg.Pool, config: SeedDevConfig): Promise<void>;
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

interface StoredEnvelopeRow {
  kek_version: number;
  wrapped_dek: Buffer;
  dek_iv: Buffer;
  dek_auth_tag: Buffer;
}

const POOL_END_TIMEOUT_MS = 1_500;
const CLIENT_CLOSE_TIMEOUT_MS = 1_000;
const activeClients = new WeakMap<pg.Pool, Set<pg.PoolClient>>();

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
  const clients = new Set<pg.PoolClient>();
  pool.on('connect', (client: pg.PoolClient) => clients.add(client));
  pool.on('remove', (client: pg.PoolClient) => clients.delete(client));
  activeClients.set(pool, clients);
  return pool;
}

/**
 * Verify the stored DEK envelope inside the existing tenant/RLS boundary.
 * Encrypt a synthetic byte through the existing vault to authenticate the wrapped DEK without
 * disclosing it or adding another cryptographic implementation or database privilege.
 */
async function verifyExistingOrganizationEnvelope(
  pool: pg.Pool,
  config: SeedDevConfig,
): Promise<void> {
  let envelope: OrganizationDekEnvelope | undefined;
  try {
    envelope = await withTenant(pool, config.orgId, async (client) => {
      const { rows } = await client.query<StoredEnvelopeRow>(
        `SELECT kek_version, wrapped_dek, dek_iv, dek_auth_tag
           FROM public.organizations WHERE id = $1`,
        [config.orgId],
      );
      const row = rows[0];
      if (!row) return undefined;
      return {
        kekVersion: row.kek_version,
        wrappedDek: row.wrapped_dek,
        dekIv: row.dek_iv,
        dekAuthTag: row.dek_auth_tag,
      };
    });
    if (!envelope) throw new Error('Organization not found in tenant context');

    const probe = Buffer.from([0x01]);
    try {
      const result = new EnvelopeVault(config.keyring).encryptProviderCredential({
        orgId: config.orgId,
        providerKeyId: crypto.randomUUID(),
        provider: 'openai',
        plaintext: probe,
        organizationEnvelope: envelope,
      });
      result.ciphertext.fill(0);
      result.iv.fill(0);
      result.authTag.fill(0);
    } finally {
      probe.fill(0);
    }
  } catch {
    throw new SeedDevError(
      'EXISTING_ENVELOPE_INVALID',
      'The existing organization envelope is incompatible with the configured KEK',
    );
  } finally {
    envelope?.wrappedDek.fill(0);
    envelope?.dekIv.fill(0);
    envelope?.dekAuthTag.fill(0);
  }
}

/**
 * Graceful pool shutdown with a bounded deadline. On timeout, actively request closure of
 * tracked PostgreSQL clients instead of only abandoning an unresolved pool.end() promise.
 * The driver cannot guarantee closure of a pathologically stuck underlying transport;
 * report cleanup failure rather than claim success in that case.
 */
async function closePoolBoundedly(pool: pg.Pool): Promise<boolean> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const end = Promise.resolve()
    .then(() => pool.end())
    .then(
      () => true,
      () => false,
    );
  const closed = await Promise.race([
    end,
    new Promise<false>((resolve) => {
      timeout = setTimeout(() => resolve(false), POOL_END_TIMEOUT_MS);
    }),
  ]);
  if (timeout) clearTimeout(timeout);
  if (closed) return true;

  const clients = activeClients.get(pool);
  if (clients && clients.size > 0) {
    let abortTimeout: ReturnType<typeof setTimeout> | undefined;
    const forced = Promise.allSettled(
      [...clients].map((client) => Promise.resolve().then(() => client.end())),
    );
    await Promise.race([
      forced,
      new Promise<void>((resolve) => {
        abortTimeout = setTimeout(resolve, CLIENT_CLOSE_TIMEOUT_MS);
      }),
    ]);
    if (abortTimeout) clearTimeout(abortTimeout);
  }
  return false;
}

const DEFAULT_DEPENDENCIES: SeedDevDependencies = {
  createPool: createDefaultPool,
  bootstrap: (pool, params) => bootstrapOrganizationWithAdmin(pool, params),
  createVault: (keyring) => new EnvelopeVault(keyring),
  verifyExistingEnvelope: verifyExistingOrganizationEnvelope,
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

async function classifyExisting(
  pool: pg.Pool,
  row: ExistingAdminRow,
  config: SeedDevConfig,
  dependencies: SeedDevDependencies,
): Promise<SeedStatus> {
  if (row.org_id !== config.orgId || row.role !== 'admin') return 'CONFLICT';
  await dependencies.verifyExistingEnvelope(pool, config);
  return 'ALREADY_PRESENT';
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
    return {
      status: await classifyExisting(pool, existing, config, dependencies),
      orgId: config.orgId,
    };
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
        return {
          status: await classifyExisting(pool, raced, config, dependencies),
          orgId: config.orgId,
        };
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

const SAFE_BOOTSTRAP_CODES = new Set([
  'INVALID_ORG_NAME',
  'INVALID_BUDGET',
  'INVALID_KEK_VERSION',
  'INVALID_DEK_MATERIAL',
  'BOOTSTRAP_FAILED',
  'DUPLICATE_RESOURCE',
  'INVALID_INPUT',
  'BOOTSTRAP_DATABASE_ERROR',
]);
const SAFE_AUTH_REASONS = new Set([
  'INVALID_CREDENTIALS',
  'RATE_LIMITED',
  'SERVICE_UNAVAILABLE',
  'INVALID_INPUT',
  'CONFIGURATION_ERROR',
]);

function writeOperationalFailure(stderr: OutputWriter, error: unknown): void {
  if (error instanceof SeedDevError) {
    writeRejection(stderr, error);
    return;
  }
  if (error instanceof BootstrapError) {
    const code = SAFE_BOOTSTRAP_CODES.has(error.code) ? error.code : 'UNEXPECTED_ERROR';
    stderr.write(`Demo seeding failed: ${code}\n`);
    return;
  }
  const authReason =
    error instanceof Error && 'reason' in error && typeof error.reason === 'string'
      ? (error as AuthenticationError).reason
      : undefined;
  if (authReason !== undefined && SAFE_AUTH_REASONS.has(authReason)) {
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
  let result: SeedResult | undefined;
  let failure: unknown;
  let cleaned = true;
  try {
    pool = dependencies.createPool(config.database);
    result = await seedDemoAccount(pool, config, adminPassword, dependencies);
  } catch (error: unknown) {
    failure = error;
  } finally {
    // Drop the reference to the immutable password string as early as possible.
    adminPassword = '';
    if (pool) cleaned = await closePoolBoundedly(pool);
  }

  if (failure !== undefined) {
    writeOperationalFailure(stderr, failure);
    if (!cleaned) stderr.write('Demo seeding failed: DATABASE_CLEANUP_FAILED\n');
    return SEED_EXIT_FAILURE;
  }
  if (!cleaned || !result) {
    stderr.write('Demo seeding failed: DATABASE_CLEANUP_FAILED\n');
    return SEED_EXIT_FAILURE;
  }
  writeStatus(stdout, result);
  return result.status === 'CONFLICT' ? SEED_EXIT_CONFLICT : SEED_EXIT_SUCCESS;
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
