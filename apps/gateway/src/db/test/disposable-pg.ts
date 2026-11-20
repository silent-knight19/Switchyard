import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import pg from 'pg';
import { provisionRoles } from '../bootstrap.js';

/**
 * Disposable PostgreSQL infrastructure for the database integration suite (review findings
 * DB-01, DB-13). Every test file starts its own throwaway PostgreSQL 16 container, creates
 * `switchyard_test_*` databases inside it, and destroys the container afterwards.
 *
 * The suite never accepts an externally supplied cluster URL: an environment-variable opt-in is
 * not proof that a database is disposable, and role provisioning changes cluster-wide passwords.
 * Instead, every cluster is created here and must present positive identity evidence (a Docker
 * label plus a per-run token) before any database is created or any role password is changed.
 */

const DEFAULT_IMAGE = 'postgres:16.8-alpine';

/** Docker label stamped on every cluster this module creates. */
export const CLUSTER_LABEL_KEY = 'switchyard.test';
export const CLUSTER_LABEL_VALUE = 'db';

/** Container environment variable carrying the per-run cluster identity token. */
export const CLUSTER_ID_ENV = 'SWITCHYARD_TEST_CLUSTER_ID';

/**
 * Legacy external-cluster opt-in. It is rejected outright rather than trusted (DB-13); the
 * variable is still recognised so an inherited value fails loudly instead of being ignored.
 */
export const UNSUPPORTED_ADMIN_URL_ENV = 'TEST_POSTGRES_ADMIN_URL';

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
  containerName: string;
  /** Per-run token that must match the container's identity evidence. */
  token: string;
  stop(): Promise<void>;
}

export interface DisposableDatabase {
  name: string;
  url: string;
  cluster: DisposableCluster;
  drop(): Promise<void>;
}

/** Observable container state used to prove a cluster is the disposable container we created. */
export interface ClusterIdentityEvidence {
  containerName: string;
  running: boolean;
  labels: Record<string, string>;
  environment: string[];
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

/**
 * Prove that the container behind a cluster is the disposable container this module started.
 * The label and the per-run token are stamped at creation time, so a development container that
 * happens to listen on a loopback port cannot satisfy them.
 */
export function assertClusterIdentity(
  cluster: { containerName: string; token: string },
  evidence: ClusterIdentityEvidence,
): void {
  if (evidence.containerName !== cluster.containerName) {
    throw new Error(
      `Refusing to use PostgreSQL container "${evidence.containerName}": expected the disposable ` +
        `test container "${cluster.containerName}"`,
    );
  }
  if (!evidence.running) {
    throw new Error(
      `Refusing to use PostgreSQL container "${evidence.containerName}": the container is not running`,
    );
  }
  if (evidence.labels[CLUSTER_LABEL_KEY] !== CLUSTER_LABEL_VALUE) {
    throw new Error(
      `Refusing to use PostgreSQL container "${evidence.containerName}": missing disposable-cluster ` +
        `identity label ${CLUSTER_LABEL_KEY}=${CLUSTER_LABEL_VALUE}`,
    );
  }
  const prefix = `${CLUSTER_ID_ENV}=`;
  const tokenEntry = evidence.environment.find((entry) => entry.startsWith(prefix));
  if (tokenEntry === undefined) {
    throw new Error(
      `Refusing to use PostgreSQL container "${evidence.containerName}": missing disposable-cluster identity token`,
    );
  }
  if (tokenEntry.slice(prefix.length) !== cluster.token) {
    throw new Error(
      `Refusing to use PostgreSQL container "${evidence.containerName}": disposable-cluster identity token mismatch`,
    );
  }
}

/** Read identity evidence for a container; throws when the container does not exist. */
export function readClusterIdentityEvidence(containerName: string): ClusterIdentityEvidence {
  const raw = docker(['inspect', '--format', '{{json .}}', containerName]);
  const inspected = JSON.parse(raw) as {
    Name?: string;
    State?: { Running?: boolean };
    Config?: { Labels?: Record<string, string> | null; Env?: string[] | null };
  };
  return {
    containerName: (inspected.Name ?? '').replace(/^\//, ''),
    running: inspected.State?.Running === true,
    labels: inspected.Config?.Labels ?? {},
    environment: inspected.Config?.Env ?? [],
  };
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

/** Start an isolated PostgreSQL 16 cluster and verify its disposable identity. */
export async function startDisposableCluster(): Promise<DisposableCluster> {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Refusing to start a disposable PostgreSQL cluster with NODE_ENV=production');
  }
  if (process.env[UNSUPPORTED_ADMIN_URL_ENV] !== undefined) {
    throw new Error(
      `${UNSUPPORTED_ADMIN_URL_ENV} is no longer supported: the database integration suite always ` +
        'starts its own verified disposable container. Unset the variable to run the suite.',
    );
  }

  const containerName = `switchyard-test-pg-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  const token = crypto.randomBytes(32).toString('hex');
  const password = crypto.randomBytes(18).toString('hex');
  docker([
    'run',
    '-d',
    '--rm',
    '--name',
    containerName,
    '--label',
    `${CLUSTER_LABEL_KEY}=${CLUSTER_LABEL_VALUE}`,
    '-e',
    `${CLUSTER_ID_ENV}=${token}`,
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

  const cluster: DisposableCluster = {
    adminUrl: '',
    containerName,
    token,
    stop,
  };

  try {
    const evidence = readClusterIdentityEvidence(containerName);
    assertClusterIdentity(cluster, evidence);

    const portOutput = docker(['port', containerName, '5432']).trim();
    const port = portOutput.slice(portOutput.lastIndexOf(':') + 1);
    if (!/^\d+$/.test(port)) {
      throw new Error(`Could not determine the mapped PostgreSQL port from "${portOutput}"`);
    }
    cluster.adminUrl = `postgres://postgres:${password}@127.0.0.1:${port}/postgres`;
    await waitForPostgres(cluster.adminUrl, 90_000);
    return cluster;
  } catch (error) {
    await stop();
    throw error;
  }
}

/** Re-verify the cluster identity immediately before creating a disposable database. */
function assertClusterStillDisposable(cluster: DisposableCluster): void {
  assertClusterIdentity(cluster, readClusterIdentityEvidence(cluster.containerName));
}

/** Create a disposable database inside the verified disposable cluster. */
export async function createDisposableDatabase(
  cluster: DisposableCluster,
  label: string,
): Promise<DisposableDatabase> {
  assertClusterStillDisposable(cluster);

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
    cluster,
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

/**
 * Run the privileged bootstrap and set disposable test passwords for login roles. The database
 * handle can only come from `createDisposableDatabase`, and the cluster identity is re-verified
 * first so a development cluster can never reach the `ALTER ROLE ... PASSWORD` statements.
 */
export async function bootstrapDatabase(
  database: DisposableDatabase,
  passwords: Record<LoginRole, string>,
): Promise<void> {
  assertSafeDisposableDatabaseName(database.name);
  assertClusterStillDisposable(database.cluster);

  const client = new pg.Client({ connectionString: database.url });
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
