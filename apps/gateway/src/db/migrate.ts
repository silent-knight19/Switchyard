import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';

/** Table holding applied migration versions; owned by the role that runs the migrations. */
export const MIGRATION_LEDGER_TABLE = 'gateway_migrations';

/**
 * Fixed session-level advisory lock key serializing every migration runner that targets the
 * same PostgreSQL instance (Architecture v1.2 §19.2, "apply migrations before runtime admission").
 * `pg_advisory_lock(bigint)` is cluster-wide, so a second runner on any database of the same
 * instance waits here instead of racing history inspection and migration execution.
 */
export const MIGRATION_ADVISORY_LOCK_KEY = '7312000001';

/** Default bound for waiting on the migration advisory lock. */
export const DEFAULT_LOCK_TIMEOUT_MS = 10_000;

/** Failure modes surfaced by the migration runner. */
export type MigrationErrorCode =
  | 'MIGRATION_DIRECTORY_MISSING'
  | 'MIGRATION_DUPLICATE_VERSION'
  | 'MIGRATION_ORDER_INVALID'
  | 'MIGRATION_FILE_MISSING'
  | 'MIGRATION_NAME_MISMATCH'
  | 'MIGRATION_CHECKSUM_MISMATCH'
  | 'MIGRATION_LEGACY_CHECKSUM_MISSING'
  | 'MIGRATION_LOCK_TIMEOUT'
  | 'MIGRATION_INVALID_OPTIONS'
  | 'MIGRATION_APPLY_FAILED';

/** Typed, fail-closed migration error. Integrity problems are never silently repaired. */
export class MigrationError extends Error {
  readonly code: MigrationErrorCode;

  constructor(code: MigrationErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'MigrationError';
    this.code = code;
  }
}

/** One versioned migration file parsed from `apps/gateway/src/db/migrations`. */
export interface MigrationFile {
  /** Zero-padded four-digit numeric version parsed from the file name (e.g. `'0001'`). */
  version: string;
  /** File base name without the `.sql` extension (e.g. `'0001-roles'`). */
  name: string;
  /** SQL text applied in a single transaction. */
  sql: string;
  /** Lowercase SHA-256 hex digest of the migration file bytes. */
  checksum: string;
}

/** Observable migration-run events, used for operator output and test evidence. */
export type MigrationEvent =
  | { type: 'adopted'; version: string; checksum: string }
  | { type: 'applied'; version: string }
  | { type: 'up-to-date' };

export interface RunMigrationsOptions {
  /** Override the migration directory (tests use temporary directories). */
  migrationsDir?: string;
  /**
   * Record checksums for ledger rows created before checksum support existed. Only meaningful
   * for the historical Batch A ledger; it never changes applied SQL and never invents a
   * checksum for a migration file that is absent.
   */
  adoptLegacyChecksums?: boolean;
  /** Bound on the advisory-lock wait; exceeding it fails with `MIGRATION_LOCK_TIMEOUT`. */
  lockTimeoutMs?: number;
  onEvent?: (event: MigrationEvent) => void;
}

/** Four-digit, ordered migration file naming contract: `NNNN-name.sql`. */
const MIGRATION_FILE_PATTERN = /^(\d{4})-([a-z0-9][a-z0-9-]*)\.sql$/;

function sha256(bytes: Buffer): string {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

export function checksumMigrationSql(sql: string): string {
  return sha256(Buffer.from(sql, 'utf8'));
}

function migrationFilesDir(): string {
  const candidates = [
    path.join(process.cwd(), 'src', 'db', 'migrations'),
    path.join(process.cwd(), 'dist', 'db', 'migrations'),
  ];
  const dir = candidates.find((candidate) => fs.existsSync(candidate));
  if (!dir) {
    throw new MigrationError(
      'MIGRATION_DIRECTORY_MISSING',
      'Migration directory not found; run from the gateway package root',
    );
  }
  return dir;
}

/**
 * Load, checksum, and validate the migration set. Validation is structural and happens before
 * any database access so an invalid set never partially applies.
 */
export function loadMigrationFiles(dir?: string): MigrationFile[] {
  const baseDir = dir ?? migrationFilesDir();
  const byVersion = new Map<string, MigrationFile>();

  for (const entry of fs.readdirSync(baseDir, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const match = MIGRATION_FILE_PATTERN.exec(entry.name);
    if (!match) continue;
    const version = match[1];
    if (version === undefined) continue;
    const bytes = fs.readFileSync(path.join(baseDir, entry.name));
    const existing = byVersion.get(version);
    if (existing) {
      throw new MigrationError(
        'MIGRATION_DUPLICATE_VERSION',
        `Duplicate migration version ${version}: ${existing.name} and ${entry.name}`,
      );
    }
    byVersion.set(version, {
      version,
      name: entry.name.slice(0, -'.sql'.length),
      sql: bytes.toString('utf8'),
      checksum: sha256(bytes),
    });
  }

  const files = [...byVersion.values()].sort((a, b) => Number(a.version) - Number(b.version));
  for (let index = 1; index < files.length; index += 1) {
    const previous = files[index - 1];
    const current = files[index];
    if (previous === undefined || current === undefined) continue;
    if (Number(current.version) !== Number(previous.version) + 1) {
      throw new MigrationError(
        'MIGRATION_ORDER_INVALID',
        `Migration versions must be contiguous; ${previous.name} is followed by ${current.name}`,
      );
    }
  }
  return files;
}

interface AppliedMigrationRow {
  version: string;
  name: string;
  checksum: string | null;
}

function isPgError(error: unknown): error is { code: string } {
  return (
    typeof error === 'object' &&
    error !== null &&
    typeof (error as { code?: unknown }).code === 'string'
  );
}

async function validateHistory(
  client: pg.PoolClient,
  files: MigrationFile[],
  adoptLegacyChecksums: boolean,
): Promise<AppliedMigrationRow[]> {
  const { rows } = await client.query<AppliedMigrationRow>(
    `SELECT version, name, checksum FROM ${MIGRATION_LEDGER_TABLE} ORDER BY version`,
  );
  const byVersion = new Map(files.map((file) => [file.version, file]));

  for (const row of rows) {
    const file = byVersion.get(row.version);
    if (!file) {
      throw new MigrationError(
        'MIGRATION_FILE_MISSING',
        `Applied migration ${row.version} (${row.name}) has no migration file; restore it before running migrations`,
      );
    }
    if (row.name !== file.name) {
      throw new MigrationError(
        'MIGRATION_NAME_MISMATCH',
        `Applied migration ${row.version} is recorded as ${row.name} but the file is ${file.name}`,
      );
    }
    if (row.checksum === null) {
      if (adoptLegacyChecksums) continue;
      throw new MigrationError(
        'MIGRATION_LEGACY_CHECKSUM_MISSING',
        `Applied migration ${row.version} has no recorded checksum (pre-checksum ledger). ` +
          'Re-run with --adopt-legacy to record the checksum of the unmodified file, or restore a verified backup.',
      );
    }
    if (row.checksum !== file.checksum) {
      throw new MigrationError(
        'MIGRATION_CHECKSUM_MISMATCH',
        `Applied migration ${row.version} (${row.name}) does not match its recorded SHA-256 checksum; ` +
          'applied migrations are immutable — add a new forward migration instead',
      );
    }
  }

  const appliedVersions = new Set(rows.map((row) => row.version));
  const pending = files.filter((file) => !appliedVersions.has(file.version));
  if (pending.length > 0 && rows.length > 0) {
    const highestApplied = Math.max(...rows.map((row) => Number(row.version)));
    const lowestPending = Math.min(...pending.map((file) => Number(file.version)));
    if (lowestPending < highestApplied) {
      throw new MigrationError(
        'MIGRATION_ORDER_INVALID',
        `Pending migration ${String(lowestPending).padStart(4, '0')} is older than applied migration ` +
          `${String(highestApplied).padStart(4, '0')}; migrations must apply in version order`,
      );
    }
  }

  return rows;
}

async function applyUnderLock(
  client: pg.PoolClient,
  files: MigrationFile[],
  options: RunMigrationsOptions,
): Promise<string[]> {
  await client.query(
    `CREATE TABLE IF NOT EXISTS ${MIGRATION_LEDGER_TABLE} (
       version TEXT PRIMARY KEY,
       name TEXT NOT NULL,
       checksum TEXT,
       applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
     )`,
  );
  await client.query(
    `ALTER TABLE ${MIGRATION_LEDGER_TABLE} ADD COLUMN IF NOT EXISTS checksum TEXT`,
  );

  const applied = await validateHistory(client, files, options.adoptLegacyChecksums === true);
  const appliedVersions = new Set(applied.map((row) => row.version));
  const pending = files.filter((file) => !appliedVersions.has(file.version));

  const filesByVersion = new Map(files.map((file) => [file.version, file]));
  for (const row of applied) {
    if (row.checksum !== null) continue;
    const file = filesByVersion.get(row.version);
    if (file === undefined) continue;
    await client.query(
      `UPDATE ${MIGRATION_LEDGER_TABLE} SET checksum = $1 WHERE version = $2 AND checksum IS NULL`,
      [file.checksum, row.version],
    );
    options.onEvent?.({ type: 'adopted', version: row.version, checksum: file.checksum });
  }

  const appliedNow: string[] = [];
  for (const file of pending) {
    await client.query('BEGIN');
    try {
      await client.query(file.sql);
      await client.query(
        `INSERT INTO ${MIGRATION_LEDGER_TABLE} (version, name, checksum) VALUES ($1, $2, $3)`,
        [file.version, file.name, file.checksum],
      );
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw new MigrationError(
        'MIGRATION_APPLY_FAILED',
        `Migration ${file.name} failed and was rolled back`,
        { cause: error },
      );
    }
    appliedNow.push(file.version);
    options.onEvent?.({ type: 'applied', version: file.version });
  }

  if (appliedNow.length === 0) options.onEvent?.({ type: 'up-to-date' });
  return appliedNow;
}

/**
 * Apply pending migrations under a session-level advisory lock. History inspection, integrity
 * validation, legacy adoption, and migration execution all happen on the same checked-out
 * connection while the lock is held, so concurrent runners cannot race the same migration.
 */
export async function runMigrations(
  pool: pg.Pool,
  options: RunMigrationsOptions = {},
): Promise<string[]> {
  const files = loadMigrationFiles(options.migrationsDir);
  const lockTimeoutMs = options.lockTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS;
  if (!Number.isInteger(lockTimeoutMs) || lockTimeoutMs <= 0) {
    throw new MigrationError(
      'MIGRATION_INVALID_OPTIONS',
      `lockTimeoutMs must be a positive integer, received ${String(lockTimeoutMs)}`,
    );
  }

  const client = await pool.connect();
  // A terminated migration backend is surfaced through the rejected query; the driver also
  // emits a late 'error' event on the connection, which must not become an uncaught exception.
  client.on('error', () => undefined);
  try {
    await client.query(`SELECT set_config('lock_timeout', $1, false)`, [`${lockTimeoutMs}ms`]);
    try {
      await client.query('SELECT pg_advisory_lock($1::bigint)', [MIGRATION_ADVISORY_LOCK_KEY]);
    } catch (error) {
      if (isPgError(error) && error.code === '55P03') {
        throw new MigrationError(
          'MIGRATION_LOCK_TIMEOUT',
          `Timed out after ${lockTimeoutMs}ms waiting for the migration advisory lock`,
          { cause: error },
        );
      }
      throw error;
    }

    try {
      return await applyUnderLock(client, files, options);
    } finally {
      await client
        .query('SELECT pg_advisory_unlock($1::bigint)', [MIGRATION_ADVISORY_LOCK_KEY])
        .catch(() => undefined);
    }
  } finally {
    await client.query(`SELECT set_config('lock_timeout', '0', false)`).catch(() => undefined);
    client.release();
  }
}

function createMigratorPool(): pg.Pool {
  return new pg.Pool({
    host: process.env.POSTGRES_HOST ?? '127.0.0.1',
    port: Number(process.env.POSTGRES_PORT ?? '5432'),
    database: process.env.POSTGRES_DB ?? 'switchyard',
    user: process.env.POSTGRES_USER ?? 'switchyard',
    password: process.env.POSTGRES_PASSWORD ?? 'switchyard_dev_password',
    connectionTimeoutMillis: 5000,
  });
}

function parseArgs(argv: string[]): { apply: boolean; adoptLegacy: boolean; dir?: string } {
  const dirIndex = argv.indexOf('--migrations-dir');
  const dir = dirIndex >= 0 ? argv[dirIndex + 1] : undefined;
  const options: { apply: boolean; adoptLegacy: boolean; dir?: string } = {
    apply: argv.includes('--apply'),
    adoptLegacy: argv.includes('--adopt-legacy'),
  };
  if (dir !== undefined) options.dir = dir;
  return options;
}

export async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const pool = createMigratorPool();
  let applied: string[];
  try {
    applied = await runMigrations(pool, {
      adoptLegacyChecksums: args.adoptLegacy,
      ...(args.dir === undefined ? {} : { migrationsDir: args.dir }),
      onEvent: (event) => {
        if (event.type === 'adopted') {
          console.log(`adopted legacy checksum ${event.version} ${event.checksum}`);
        } else if (event.type === 'applied') {
          console.log(`applied ${event.version}`);
        }
      },
    });
  } finally {
    await pool.end();
  }
  if (applied.length === 0) {
    console.log('no pending migrations');
  }
}

if (process.argv.includes('--apply')) {
  main()
    .then(() => process.exit(0))
    .catch((error: unknown) => {
      console.error('migrate failed:', error instanceof Error ? error.message : String(error));
      process.exit(1);
    });
}
