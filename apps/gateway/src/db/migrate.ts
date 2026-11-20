import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';

/** Table holding applied migration versions; owned by the role that runs the migrations. */
export const MIGRATION_LEDGER_TABLE = 'gateway_migrations';

/** One versioned migration file parsed from `apps/gateway/src/db/migrations`. */
export interface MigrationFile {
  /** Zero-padded numeric version parsed from the file name (e.g. `'0001'`). */
  version: string;
  /** File base name without the `.sql` extension (e.g. `'0001-roles'`). */
  name: string;
  /** SQL text applied in a single transaction. */
  sql: string;
}

const MIGRATION_FILE_PATTERN = /^(\d+)-(.+)\.sql$/;

function migrationFilesDir(): string {
  const candidates = [
    path.join(process.cwd(), 'src', 'db', 'migrations'),
    path.join(process.cwd(), 'dist', 'db', 'migrations'),
  ];
  const dir = candidates.find((candidate) => fs.existsSync(candidate));
  if (!dir) {
    throw new Error('Migration directory not found; run from the gateway package root');
  }
  return dir;
}

function parseMigrationFileName(fileName: string): MigrationFile | null {
  const match = MIGRATION_FILE_PATTERN.exec(fileName);
  if (!match) return null;
  const version = match[1];
  if (version === undefined) return null;
  const fileBase = fileName.slice(0, -'.sql'.length);
  return { version, name: fileBase, sql: '' };
}

export function loadMigrationFiles(dir?: string): MigrationFile[] {
  const baseDir = dir ?? migrationFilesDir();
  const files: MigrationFile[] = [];
  for (const entry of fs.readdirSync(baseDir, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const parsed = parseMigrationFileName(entry.name);
    if (parsed) {
      parsed.sql = fs.readFileSync(path.join(baseDir, entry.name), 'utf8');
      files.push(parsed);
    }
  }
  files.sort((a, b) => Number(a.version) - Number(b.version));
  return files;
}

export async function runMigrations(pool: pg.Pool): Promise<string[]> {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS ${MIGRATION_LEDGER_TABLE} (
       version TEXT PRIMARY KEY,
       name TEXT NOT NULL,
       applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
     )`,
  );

  const { rows } = await pool.query<{ version: string }>(
    `SELECT version FROM ${MIGRATION_LEDGER_TABLE}`,
  );
  const appliedVersions = new Set(rows.map((row) => row.version));

  const pending = loadMigrationFiles().filter((file) => !appliedVersions.has(file.version));
  if (pending.length === 0) return [];

  const client = await pool.connect();
  try {
    for (const file of pending) {
      await client.query('BEGIN');
      try {
        await client.query(file.sql);
        await client.query(
          `INSERT INTO ${MIGRATION_LEDGER_TABLE} (version, name) VALUES ($1, $2)`,
          [file.version, file.name],
        );
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
    return pending.map((file) => file.version);
  } finally {
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

export async function main(): Promise<void> {
  const pool = createMigratorPool();
  let applied: string[];
  try {
    applied = await runMigrations(pool);
  } finally {
    await pool.end();
  }
  if (applied.length === 0) {
    console.log('no pending migrations');
  } else {
    for (const version of applied) {
      console.log(`applied ${version}`);
    }
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
