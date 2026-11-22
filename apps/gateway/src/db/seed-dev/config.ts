import { isCanonicalEmail } from '../../auth/email.js';
import { inspectKekEnvironment, type KekKeyring, type KekVersion } from '../../vault/kek.js';

/**
 * Development-only demo seeding configuration (SW-P1-B02, Architecture v1.2 §23).
 *
 * This parser is intentionally separate from the Gateway runtime configuration schema. The seeder
 * is a short-lived developer CLI, not a runtime service: it must reject test/production profiles,
 * require an explicit enable flag, restrict the database target to a local development topology and
 * refuse every credential or connection override that could redirect it to an arbitrary database.
 *
 * Every error carries a stable code and a static message. Supplied values (especially passwords,
 * KEK material, connection strings and driver errors) are never reproduced.
 */

export type SeedDevErrorCode =
  | 'PRODUCTION_FORBIDDEN'
  | 'ENVIRONMENT_FORBIDDEN'
  | 'SEEDING_DISABLED'
  | 'INVALID_ARGUMENTS'
  | 'INVALID_ORG_ID'
  | 'INVALID_ORG_NAME'
  | 'INVALID_ADMIN_EMAIL'
  | 'INVALID_BUDGET'
  | 'MISSING_KEK'
  | 'INVALID_KEK'
  | 'INVALID_SEED_TARGET'
  | 'UNSUPPORTED_CONNECTION_OVERRIDE'
  | 'INVALID_DATABASE_TARGET'
  | 'UNSUPPORTED_DATABASE_IDENTITY'
  | 'INVALID_DATABASE_PORT'
  | 'INVALID_DATABASE_NAME'
  | 'MISSING_DATABASE_CREDENTIAL'
  | 'EXISTING_ENVELOPE_INVALID';

export class SeedDevError extends Error {
  public readonly code: SeedDevErrorCode;

  constructor(code: SeedDevErrorCode, message: string) {
    super(message);
    this.name = 'SeedDevError';
    this.code = code;
  }
}

export type SeedDevTarget = 'local' | 'compose';

export interface SeedDevDatabaseTarget {
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly user: 'gateway_app';
  readonly password: string;
}

export interface SeedDevConfig {
  readonly target: SeedDevTarget;
  readonly orgId: string;
  readonly orgName: string;
  readonly adminEmail: string;
  readonly monthlyBudgetMicrodollars: bigint;
  readonly keyring: KekKeyring;
  readonly activeKekVersion: KekVersion;
  readonly database: SeedDevDatabaseTarget;
}

export type SeedDevEnvironment = Record<string, string | undefined>;

/** Hosts accepted for host-based local development. */
const LOCAL_DATABASE_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

/** The only hostname accepted by the approved Docker Compose invocation. */
const COMPOSE_DATABASE_HOST = 'postgres';

/** The only runtime database role permitted to execute the demo bootstrap. */
const REQUIRED_DATABASE_USER = 'gateway_app';

/**
 * Variables that can silently redirect a PostgreSQL client to a different server, database or
 * role. The seeder refuses to operate with any of them present instead of trying to decide which
 * override wins.
 */
const UNSUPPORTED_CONNECTION_OVERRIDES = [
  'DATABASE_URL',
  'POSTGRES_URL',
  'POSTGRES_CONNECTION_STRING',
  'PGHOST',
  'PGHOSTADDR',
  'PGPORT',
  'PGDATABASE',
  'PGUSER',
  'PGPASSWORD',
  'PGPASSFILE',
  'PGOPTIONS',
  'PGSERVICE',
  'PGSERVICEFILE',
  'PGSSLMODE',
  'MIGRATE_POSTGRES_USER',
  'MIGRATE_POSTGRES_PASSWORD',
  'BOOTSTRAP_POSTGRES_USER',
  'BOOTSTRAP_POSTGRES_PASSWORD',
] as const;

const CANONICAL_LOWERCASE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const NON_NEGATIVE_INTEGER = /^(0|[1-9][0-9]*)$/;
const DATABASE_NAME = /^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$/;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;
const MAX_ORG_NAME_LENGTH = 255;
const MAX_BUDGET_MICRODOLLARS = 1000000000000000n;

function supplied(env: SeedDevEnvironment, name: string): boolean {
  return env[name] !== undefined && env[name] !== '';
}

function requireString(env: SeedDevEnvironment, name: string): string {
  const value = env[name];
  return typeof value === 'string' ? value : '';
}

function parseOrgId(value: string): string {
  if (!CANONICAL_LOWERCASE_UUID.test(value)) {
    throw new SeedDevError(
      'INVALID_ORG_ID',
      'DEMO_ORG_ID must be a canonical lowercase UUID (stable across invocations)',
    );
  }
  return value;
}

function parseOrgName(value: string): string {
  if (
    value.trim().length === 0 ||
    value.length > MAX_ORG_NAME_LENGTH ||
    CONTROL_CHARACTERS.test(value)
  ) {
    throw new SeedDevError(
      'INVALID_ORG_NAME',
      'DEMO_ORG_NAME must be 1 to 255 characters without control characters',
    );
  }
  return value;
}

function parseAdminEmail(value: string): string {
  if (!isCanonicalEmail(value)) {
    throw new SeedDevError(
      'INVALID_ADMIN_EMAIL',
      'DEMO_ADMIN_EMAIL must be canonical: trimmed, lowercase, valid, and at most 255 characters',
    );
  }
  return value;
}

function parseBudget(value: string | undefined): bigint {
  if (value === undefined || value === '') {
    return 0n;
  }
  if (!NON_NEGATIVE_INTEGER.test(value)) {
    throw new SeedDevError(
      'INVALID_BUDGET',
      'DEMO_MONTHLY_BUDGET_MICRODOLLARS must be a nonnegative base-10 integer',
    );
  }
  const budget = BigInt(value);
  if (budget > MAX_BUDGET_MICRODOLLARS) {
    throw new SeedDevError(
      'INVALID_BUDGET',
      'DEMO_MONTHLY_BUDGET_MICRODOLLARS exceeds the supported maximum of 1,000,000,000,000,000',
    );
  }
  return budget;
}

function parseKeyring(env: SeedDevEnvironment): { keyring: KekKeyring; version: KekVersion } {
  const inspection = inspectKekEnvironment({
    MASTER_KEK_V1: env.MASTER_KEK_V1,
    MASTER_KEK_V2: env.MASTER_KEK_V2,
    ACTIVE_KEK_VERSION: env.ACTIVE_KEK_VERSION,
  });

  if (inspection.status === 'absent') {
    throw new SeedDevError(
      'MISSING_KEK',
      'KEK configuration is required: supply MASTER_KEK_V1 or MASTER_KEK_V2 and ACTIVE_KEK_VERSION',
    );
  }
  if (inspection.status === 'invalid') {
    throw new SeedDevError(
      'INVALID_KEK',
      'KEK configuration is invalid: canonical unpadded base64url of exactly 32 bytes is required',
    );
  }

  return {
    keyring: inspection.keyring,
    version: inspection.keyring.activeVersion,
  };
}

function parseSeedTarget(value: string | undefined): SeedDevTarget {
  if (value === undefined || value === '' || value === 'local') {
    return 'local';
  }
  if (value === 'compose') {
    return 'compose';
  }
  throw new SeedDevError(
    'INVALID_SEED_TARGET',
    'DEMO_SEEDING_TARGET must be "local" (default) or "compose"',
  );
}

function parseDatabase(env: SeedDevEnvironment, target: SeedDevTarget): SeedDevDatabaseTarget {
  for (const name of UNSUPPORTED_CONNECTION_OVERRIDES) {
    if (supplied(env, name)) {
      throw new SeedDevError(
        'UNSUPPORTED_CONNECTION_OVERRIDE',
        `Unsupported database connection override ${name}; use POSTGRES_HOST/PORT/DB/USER/PASSWORD only`,
      );
    }
  }

  const host = (env.POSTGRES_HOST ?? '127.0.0.1').trim().toLowerCase();
  const hostAllowed =
    target === 'compose' ? host === COMPOSE_DATABASE_HOST : LOCAL_DATABASE_HOSTS.has(host);
  if (!hostAllowed) {
    throw new SeedDevError(
      'INVALID_DATABASE_TARGET',
      target === 'compose'
        ? `Docker Compose demo seeding requires POSTGRES_HOST=${COMPOSE_DATABASE_HOST}`
        : 'Host demo seeding requires loopback PostgreSQL (127.0.0.1, localhost, or ::1)',
    );
  }

  const rawPort = env.POSTGRES_PORT ?? '5432';
  const port = Number(rawPort);
  if (!/^[0-9]{1,5}$/.test(rawPort) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new SeedDevError('INVALID_DATABASE_PORT', 'POSTGRES_PORT must be an integer 1-65535');
  }

  const database = env.POSTGRES_DB ?? 'switchyard';
  if (!DATABASE_NAME.test(database)) {
    throw new SeedDevError('INVALID_DATABASE_NAME', 'POSTGRES_DB is not a supported database name');
  }

  const user = env.POSTGRES_USER ?? '';
  if (user !== REQUIRED_DATABASE_USER) {
    throw new SeedDevError(
      'UNSUPPORTED_DATABASE_IDENTITY',
      'Demo seeding must connect as the restricted gateway_app runtime role',
    );
  }

  const password = env.POSTGRES_PASSWORD ?? '';
  if (password.length === 0) {
    throw new SeedDevError(
      'MISSING_DATABASE_CREDENTIAL',
      'POSTGRES_PASSWORD for the gateway_app role is required',
    );
  }

  return {
    host,
    port,
    database,
    user: REQUIRED_DATABASE_USER,
    password,
  };
}

/**
 * Validate the complete development-only seeding contract before any keyring or database
 * connection is created. Production and non-development profiles are rejected first.
 */
export function parseSeedDevConfig(env: SeedDevEnvironment): SeedDevConfig {
  const nodeEnv = env.NODE_ENV;

  // Production always fails closed, even when DEMO_SEEDING_ENABLED=true.
  if (nodeEnv === 'production') {
    throw new SeedDevError('PRODUCTION_FORBIDDEN', 'Demo seeding is prohibited in production');
  }

  // The executable developer CLI is development-only. Automated tests use internal functions with
  // disposable databases; NODE_ENV=test is not a second CLI profile.
  if (nodeEnv !== 'development') {
    throw new SeedDevError(
      'ENVIRONMENT_FORBIDDEN',
      'Demo seeding requires NODE_ENV=development; test and other profiles are not supported',
    );
  }

  if (env.DEMO_SEEDING_ENABLED !== 'true') {
    throw new SeedDevError(
      'SEEDING_DISABLED',
      'Demo seeding is disabled; set DEMO_SEEDING_ENABLED=true explicitly',
    );
  }

  const orgId = parseOrgId(requireString(env, 'DEMO_ORG_ID'));
  const orgName = parseOrgName(requireString(env, 'DEMO_ORG_NAME'));
  const adminEmail = parseAdminEmail(requireString(env, 'DEMO_ADMIN_EMAIL'));
  const monthlyBudgetMicrodollars = parseBudget(env.DEMO_MONTHLY_BUDGET_MICRODOLLARS);
  const { keyring, version } = parseKeyring(env);
  const target = parseSeedTarget(env.DEMO_SEEDING_TARGET);
  const database = parseDatabase(env, target);

  return {
    target,
    orgId,
    orgName,
    adminEmail,
    monthlyBudgetMicrodollars,
    keyring,
    activeKekVersion: version,
    database,
  };
}
