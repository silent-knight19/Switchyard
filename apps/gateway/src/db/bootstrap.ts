import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';

/** Minimal query surface shared by `pg.Client` and `pg.PoolClient`. */
export interface SqlExecutor {
  query(sql: string): Promise<unknown>;
}

const BOOTSTRAP_SQL_FILE = 'provision-roles.sql';

/** Locate the privileged role-provisioning SQL shipped with the gateway package. */
export function bootstrapSqlPath(): string {
  const candidates = [
    path.join(process.cwd(), 'src', 'db', 'bootstrap', BOOTSTRAP_SQL_FILE),
    path.join(process.cwd(), 'dist', 'db', 'bootstrap', BOOTSTRAP_SQL_FILE),
  ];
  const found = candidates.find((candidate) => fs.existsSync(candidate));
  if (!found) {
    throw new Error('Role bootstrap SQL not found; run from the gateway package root');
  }
  return found;
}

/**
 * Provision the fixed Switchyard role matrix and schema privileges. Requires a superuser
 * session; it is intentionally separate from ordinary schema migrations because
 * `gateway_migrator` must not hold CREATEROLE (DB-07).
 */
export async function provisionRoles(client: SqlExecutor): Promise<void> {
  await client.query(fs.readFileSync(bootstrapSqlPath(), 'utf8'));
}

function createBootstrapClient(): pg.Client {
  return new pg.Client({
    host: process.env.POSTGRES_HOST ?? '127.0.0.1',
    port: Number(process.env.POSTGRES_PORT ?? '5432'),
    database: process.env.POSTGRES_DB ?? 'switchyard',
    user: process.env.BOOTSTRAP_POSTGRES_USER ?? process.env.POSTGRES_USER ?? 'switchyard',
    password:
      process.env.BOOTSTRAP_POSTGRES_PASSWORD ??
      process.env.POSTGRES_PASSWORD ??
      'switchyard_dev_password',
    connectionTimeoutMillis: 5000,
  });
}

export async function main(): Promise<void> {
  if (!process.argv.includes('--apply')) {
    console.error('usage: bootstrap:roles --apply (requires a superuser database session)');
    process.exitCode = 2;
    return;
  }

  const client = createBootstrapClient();
  await client.connect();
  try {
    await provisionRoles(client);
    const { rows } = await client.query<{
      rolname: string;
      rolcanlogin: boolean;
      rolbypassrls: boolean;
    }>(
      `SELECT rolname, rolcanlogin, rolbypassrls
       FROM pg_roles
       WHERE rolname LIKE 'gateway\\_%'
       ORDER BY rolname`,
    );
    for (const row of rows) {
      console.log(
        `role ${row.rolname} login=${String(row.rolcanlogin)} bypassrls=${String(row.rolbypassrls)}`,
      );
    }
    console.log('role bootstrap complete');
  } finally {
    await client.end();
  }
}

if (process.argv.includes('--apply')) {
  main()
    .then(() => process.exit(0))
    .catch((error: unknown) => {
      console.error('bootstrap failed:', error instanceof Error ? error.message : String(error));
      process.exit(1);
    });
}
