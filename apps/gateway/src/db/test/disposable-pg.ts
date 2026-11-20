import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import pg from 'pg';
import { provisionRoles } from '../bootstrap.js';

/**
 * Disposable PostgreSQL infrastructure for the database integration suite (review finding
 * DB-01). Every test file starts its own throwaway PostgreSQL 16 container, creates
 * `switchyard_test_*` databases inside it, and destroys the container afterwards. The
 * persistent development database (`switchyard` on the Compose stack) is never contacted.
 *
 * `TEST_POSTGRES_ADMIN_URL` may point at an already-provisioned disposable cluster (for
 * example a CI service container). It must target the `postgres` maintenance database.
 */

const DEFAULT_IMAGE = 'postgres:16.8-alpine';
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

/** Only databases with this prefix may be created or dropped by tests. */
export const DISPOSABLE_DATABASE_PATTERN = /^switchyard_test_[a-z0-9_]{1,40}$/;

export const LOGIN_ROLES = [
  'gateway_migrator',
  'gateway_startup',
  'gateway_app',
  'gateway_worker',
] as const;

export type LoginRole = (typeof LOGIN_ROLES)[number];

export interface DisposableCluster {
  adminUrl: string;
  containerName: string | null;
  stop(): Promise<void>;
}

export interface DisposableDatabase {
  name: string;
  url: string;
  drop(): Promise<void>;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function docker(args: string[]): string {
  try {
    return execFileSync('docker', args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    const stderr =
      typeof error === 'object' && error !== null && 'stderr' in error
        ? String((error as { stderr?: unknown }).stderr ?? '')
        : '';
    throw new Error(
      `Docker command failed: docker ${args.join(' ')}${stderr === '' ? '' : `: ${stderr.trim()}`}. ` +
        'The database integration suite requires Docker with a reachable daemon.',
    );
  }
}

/** Refuse to touch anything that is not an explicitly disposable database name. */
export function assertSafeDisposableDatabaseName(name: string): void {
  if (name === 'switchyard' || !DISPOSABLE_DATABASE_PATTERN.test(name)) {
    throw new Error(
      `Refusing to operate on database "${name}": tests may only create or drop switchyard_test_* databases`,
    );
  }
}

/** Validate an externally supplied admin URL before any database is created or dropped. */
export function assertSafeAdminUrl(raw: string): URL {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Refusing to run the disposable database suite with NODE_ENV=production');
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('TEST_POSTGRES_ADMIN_URL is not a valid URL');
  }
  if (url.protocol !== 'postgres:' && url.protocol !== 'postgresql:') {
    throw new Error(`TEST_POSTGRES_ADMIN_URL must use the postgres protocol, got ${url.protocol}`);
  }
  const database = decodeURIComponent(url.pathname.replace(/^\//, ''));
  if (database !== 'postgres') {
    throw new Error(
      `TEST_POSTGRES_ADMIN_URL must target the "postgres" maintenance database, got "${database}"`,
    );
  }
  if (!LOOPBACK_HOSTS.has(url.hostname) && process.env.ALLOW_NON_LOOPBACK_TEST_PG !== 'true') {
    throw new Error(
      `TEST_POSTGRES_ADMIN_URL host "${url.hostname}" is not loopback; set ALLOW_NON_LOOPBACK_TEST_PG=true only for a disposable CI cluster`,
    );
  }
  return url;
}

export function withDatabase(raw: string, database: string): string {
  const url = new URL(raw);
  url.pathname = `/${database}`;
  return url.toString();
}

export function roleConnectionString(raw: string, role: LoginRole, password: string): string {
  const url = new URL(raw);
  url.username = role;
  url.password = password;
  return url.toString();
}

async function waitForPostgres(adminUrl: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    const client = new pg.Client({ connectionString: adminUrl, connectionTimeoutMillis: 1000 });
    try {
      await client.connect();
      await client.query('SELECT 1');
      await client.end();
      return;
    } catch (error) {
      lastError = error;
      await client.end().catch(() => undefined);
      await delay(250);
    }
  }
  throw new Error(
    `PostgreSQL did not become ready within ${timeoutMs}ms: ${
      lastError instanceof Error ? lastError.message : String(lastError)
    }`,
  );
}

/** Start an isolated PostgreSQL 16 cluster, or reuse an explicitly disposable admin URL. */
export async function startDisposableCluster(): Promise<DisposableCluster> {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Refusing to start a disposable PostgreSQL cluster with NODE_ENV=production');
  }

  const provided = process.env.TEST_POSTGRES_ADMIN_URL;
  if (provided !== undefined && provided !== '') {
    assertSafeAdminUrl(provided);
    await waitForPostgres(provided, 60_000);
    return { adminUrl: provided, containerName: null, stop: async () => undefined };
  }

  const containerName = `switchyard-test-pg-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  const password = crypto.randomBytes(18).toString('hex');
  docker([
    'run',
    '-d',
    '--rm',
    '--name',
    containerName,
    '--label',
    'switchyard.test=db',
    '-e',
    `POSTGRES_PASSWORD=${password}`,
    '-e',
    'POSTGRES_DB=postgres',
    '-p',
    '127.0.0.1::5432',
    process.env.TEST_POSTGRES_IMAGE ?? DEFAULT_IMAGE,
  ]);

  const stop = async (): Promise<void> => {
    try {
      docker(['rm', '-f', containerName]);
    } catch {
      // Container already gone; cleanup is best-effort but deterministic.
    }
  };

  try {
    const portOutput = docker(['port', containerName, '5432']).trim();
    const port = portOutput.slice(portOutput.lastIndexOf(':') + 1);
    if (!/^\d+$/.test(port)) {
      throw new Error(`Could not determine the mapped PostgreSQL port from "${portOutput}"`);
    }
    const adminUrl = `postgres://postgres:${password}@127.0.0.1:${port}/postgres`;
    await waitForPostgres(adminUrl, 90_000);
    return { adminUrl, containerName, stop };
  } catch (error) {
    await stop();
    throw error;
  }
}

/** Create a disposable database inside the disposable cluster. */
export async function createDisposableDatabase(
  cluster: DisposableCluster,
  label: string,
): Promise<DisposableDatabase> {
  const slug = label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 24);
  const name = `switchyard_test_${slug === '' ? 'db' : slug}_${crypto.randomBytes(6).toString('hex')}`;
  assertSafeDisposableDatabaseName(name);

  const admin = new pg.Client({ connectionString: cluster.adminUrl });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE "${name}"`);
  } finally {
    await admin.end();
  }

  return {
    name,
    url: withDatabase(cluster.adminUrl, name),
    async drop() {
      assertSafeDisposableDatabaseName(name);
      const dropper = new pg.Client({ connectionString: cluster.adminUrl });
      await dropper.connect();
      try {
        await dropper.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
      } finally {
        await dropper.end();
      }
    },
  };
}

/** Run the privileged bootstrap and set disposable test passwords for login roles. */
export async function bootstrapDatabase(
  databaseUrl: string,
  passwords: Record<LoginRole, string>,
): Promise<void> {
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    await provisionRoles(client);
    for (const role of LOGIN_ROLES) {
      const password = passwords[role];
      if (!/^[a-f0-9]{32,}$/.test(password)) {
        throw new Error('Disposable role passwords must be lowercase hex');
      }
      await client.query(`ALTER ROLE ${role} PASSWORD '${password}'`);
    }
  } finally {
    await client.end();
  }
}

export function randomPassword(): string {
  return crypto.randomBytes(24).toString('hex');
}

export function createRolePasswords(): Record<LoginRole, string> {
  return {
    gateway_migrator: randomPassword(),
    gateway_startup: randomPassword(),
    gateway_app: randomPassword(),
    gateway_worker: randomPassword(),
  };
}

/** Copy a subset of migration files into a temporary directory (upgrade/interruption tests). */
export function copyMigrationsToTempDir(
  fileNames: string[],
  sourceDir = path.join(process.cwd(), 'src', 'db', 'migrations'),
): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'switchyard-migrations-'));
  for (const fileName of fileNames) {
    fs.copyFileSync(path.join(sourceDir, fileName), path.join(dir, fileName));
  }
  return dir;
}

/** Write an inline migration set into a temporary directory. */
export function writeMigrationsToTempDir(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'switchyard-migrations-'));
  for (const [fileName, sql] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, fileName), sql, 'utf8');
  }
  return dir;
}

export function removeTempDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

export function isPgErrorWithCode(error: unknown, code: string): boolean {
  return typeof error === 'object' && error !== null && (error as { code?: unknown }).code === code;
}

/**
 * Extract the ACL entry granted to PUBLIC (the entry with an empty grantee) from a
 * `pg_namespace.nspacl` rendering. Used to prove PUBLIC holds no CREATE privilege.
 */
export function schemaAclEntryForPublic(acl: string | null): string {
  if (acl === null) return '';
  const entries = acl.replace(/^\{/, '').replace(/\}$/, '').split(',');
  return entries.find((entry) => entry.startsWith('=')) ?? '';
}
