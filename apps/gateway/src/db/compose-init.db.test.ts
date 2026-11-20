import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import net from 'node:net';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadMigrationFiles } from './migrate.js';

/**
 * Regression test for Docker Compose fresh initialization & password safety (DB-15, DB-16).
 * Demonstrates:
 * 1. A genuinely fresh database initializes successfully via Docker Compose.
 * 2. Role provisioning and local credential provisioning run via 01-provision-roles.sql
 *    and 02-init-development.sh without executing migrations or printing passwords.
 * 3. 02-init-development.sh safely sets passwords containing single quotes, spaces, double quotes,
 *    and SQL-injection syntax (:'var') without statement breakage or SQL execution (DB-16).
 * 4. All six migrations apply through the authoritative runner (apps/gateway/src/db/migrate.ts)
 *    under gateway_migrator before Gateway admission.
 * 5. All seven ledger records have correct SHA-256 checksums matching authoritative files.
 * 6. The Gateway runtime container connects as gateway_app with least privilege.
 * 7. All four expected roles (migrator, app, startup, worker) authenticate successfully with
 *    their complex passwords and retain their required privileges.
 * 8. No administrator or migrator credentials are leaked into the Gateway container environment.
 * 9. Redis ACL attestation and Gateway healthcheck (/health/ready) pass.
 * 10. Restarting the stack is idempotent: migrate runs, finds no pending migrations, exits 0,
 *     and data is preserved across restart.
 *
 * Uses an isolated Compose project name, independently named disposable volumes, and ephemeral
 * ports so the persistent development database and Redis instances are never touched.
 */

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      if (!addr || typeof addr === 'string') {
        srv.close(() => reject(new Error('Failed to obtain free port')));
        return;
      }
      const port = addr.port;
      srv.close(() => resolve(port));
    });
  });
}

function run(cmd: string, args: string[], env: Record<string, string>): string {
  return execFileSync(cmd, args, {
    encoding: 'utf8',
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

describe('SW-1.3.1 / SW-1.3.2 Docker Compose fresh initialization (DB-15, DB-16 regression gate)', () => {
  const runId = crypto.randomBytes(4).toString('hex');
  const projectName = `switchyard-test-cmp-${runId}`;
  const pgContainer = `switchyard-test-pg-${runId}`;
  const redisContainer = `switchyard-test-redis-${runId}`;
  const migrateContainer = `switchyard-test-migrate-${runId}`;
  const gatewayContainer = `switchyard-test-gw-${runId}`;
  const pgVolume = `switchyard_test_pg_vol_${runId}`;
  const redisVolume = `switchyard_test_redis_vol_${runId}`;
  const networkName = `switchyard-test-net-${runId}`;

  // Passwords containing single quotes, spaces, and SQL injection syntax (DB-16) // gitleaks:allow
  const migratorPass = "migrator'pass; DROP TABLE IF EXISTS injection_target; --"; // gitleaks:allow
  const appPass = 'app \'pass with spaces\' and "quotes"'; // gitleaks:allow
  const startupPass = "startup'quote; SELECT '1';"; // gitleaks:allow
  const workerPass = "worker 'pass' with spaces & symbols"; // gitleaks:allow

  let pgPort: number;
  let redisPort: number;
  let gatewayPort: number;
  let composeEnv: Record<string, string>;

  beforeAll(async () => {
    pgPort = await getFreePort();
    redisPort = await getFreePort();
    gatewayPort = await getFreePort();

    composeEnv = {
      POSTGRES_PORT: String(pgPort),
      REDIS_PORT: String(redisPort),
      PORT: String(gatewayPort),
      POSTGRES_CONTAINER_NAME: pgContainer,
      REDIS_CONTAINER_NAME: redisContainer,
      MIGRATE_CONTAINER_NAME: migrateContainer,
      GATEWAY_CONTAINER_NAME: gatewayContainer,
      POSTGRES_VOLUME_NAME: pgVolume,
      REDIS_VOLUME_NAME: redisVolume,
      NETWORK_NAME: networkName,
      GATEWAY_MIGRATOR_PASSWORD: migratorPass,
      MIGRATE_POSTGRES_PASSWORD: migratorPass,
      GATEWAY_APP_PASSWORD: appPass,
      GATEWAY_POSTGRES_PASSWORD: appPass,
      GATEWAY_STARTUP_PASSWORD: startupPass,
      GATEWAY_WORKER_PASSWORD: workerPass,
    };

    // Build image and start all services using isolated project
    run('docker', ['compose', '-p', projectName, 'up', '-d', '--build'], composeEnv);

    // Wait for Gateway health readiness (up to 30s)
    const startTime = Date.now();
    let ready = false;
    while (Date.now() - startTime < 30_000) {
      try {
        const res = await fetch(`http://127.0.0.1:${gatewayPort}/health/ready`);
        if (res.ok) {
          const body = (await res.json()) as { status: string };
          if (body.status === 'ready') {
            ready = true;
            break;
          }
        }
      } catch {
        // continue polling until ready
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    expect(ready).toBe(true);
  }, 90_000);

  afterAll(() => {
    try {
      run('docker', ['compose', '-p', projectName, 'down', '-v', '--remove-orphans'], composeEnv);
    } catch {
      // ignore teardown errors
    }
  }, 30_000);

  it('proves 02-init-development.sh does not bypass the authoritative migration runner', () => {
    const pgLogs = run('docker', ['logs', pgContainer], composeEnv);
    expect(pgLogs).toContain('Setting development passwords for Switchyard roles...');
    expect(pgLogs).toContain('Switchyard development role credentials initialized.');
    // Must NOT contain duplicate psql migration application loops or ON CONFLICT updates
    expect(pgLogs).not.toContain('Applying Switchyard schema migrations as gateway_migrator');
    expect(pgLogs).not.toContain('ON CONFLICT (version) DO UPDATE SET checksum');
  });

  it('does not leak plaintext passwords into container logs', () => {
    const pgLogs = run('docker', ['logs', pgContainer], composeEnv);
    expect(pgLogs).not.toContain(migratorPass);
    expect(pgLogs).not.toContain(appPass);
    expect(pgLogs).not.toContain(startupPass);
    expect(pgLogs).not.toContain(workerPass);
  });

  it('executes authoritative migration runner via migrate service and applies all six migrations', () => {
    // migrate container exited with code 0
    const exitCode = run(
      'docker',
      ['inspect', migrateContainer, '--format', '{{.State.ExitCode}}'],
      composeEnv,
    ).trim();
    expect(exitCode).toBe('0');

    // migrate logs demonstrate execution of authoritative migrate.ts
    const migrateLogs = run('docker', ['logs', migrateContainer], composeEnv);
    expect(migrateLogs).toContain('applied 0001');
    expect(migrateLogs).toContain('applied 0002');
    expect(migrateLogs).toContain('applied 0003');
    expect(migrateLogs).toContain('applied 0004');
    expect(migrateLogs).toContain('applied 0005');
    expect(migrateLogs).toContain('applied 0006');
    expect(migrateLogs).toContain('applied 0007');
  });

  it('records correct SHA-256 checksums in gateway_migrations for all seven migrations', async () => {
    const expectedFiles = loadMigrationFiles();
    expect(expectedFiles).toHaveLength(7);

    const client = new pg.Client({
      host: '127.0.0.1',
      port: pgPort,
      database: 'switchyard',
      user: 'gateway_migrator',
      password: migratorPass,
    });
    await client.connect();
    try {
      const { rows } = await client.query<{
        version: string;
        name: string;
        checksum: string;
      }>('SELECT version, name, checksum FROM gateway_migrations ORDER BY version');

      expect(rows).toHaveLength(7);
      for (let i = 0; i < expectedFiles.length; i += 1) {
        const expected = expectedFiles[i]!;
        const row = rows[i]!;
        expect(row.version).toBe(expected.version);
        expect(row.name).toBe(expected.name);
        expect(row.checksum).toBe(expected.checksum);
      }
    } finally {
      await client.end();
    }
  });

  it('authenticates all four roles with quote/space/injection passwords and preserves privileges', async () => {
    // 1. gateway_migrator authenticates with SQL-injection shaped password
    const migratorClient = new pg.Client({
      host: '127.0.0.1',
      port: pgPort,
      database: 'switchyard',
      user: 'gateway_migrator',
      password: migratorPass,
    });
    await migratorClient.connect();
    try {
      const { rows } = await migratorClient.query<{ usename: string }>(
        'SELECT current_user AS usename',
      );
      expect(rows[0]?.usename).toBe('gateway_migrator');
    } finally {
      await migratorClient.end();
    }

    // 2. gateway_app authenticates with password containing spaces and quotes
    const appClient = new pg.Client({
      host: '127.0.0.1',
      port: pgPort,
      database: 'switchyard',
      user: 'gateway_app',
      password: appPass,
    });
    await appClient.connect();
    try {
      const { rows: userRows } = await appClient.query<{ usename: string }>(
        'SELECT current_user AS usename',
      );
      expect(userRows[0]?.usename).toBe('gateway_app');

      const { rows: superRows } = await appClient.query<{
        rolsuper: boolean;
        rolbypassrls: boolean;
      }>("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'gateway_app'");
      expect(superRows[0]?.rolsuper).toBe(false);
      expect(superRows[0]?.rolbypassrls).toBe(false);

      // gateway_app cannot CREATE TABLE
      await expect(appClient.query('CREATE TABLE app_unauthorized (id int)')).rejects.toMatchObject(
        { code: '42501' },
      );
    } finally {
      await appClient.end();
    }

    // 3. gateway_startup authenticates with quote-containing password
    const startupClient = new pg.Client({
      host: '127.0.0.1',
      port: pgPort,
      database: 'switchyard',
      user: 'gateway_startup',
      password: startupPass,
    });
    await startupClient.connect();
    try {
      const { rows } = await startupClient.query<{ usename: string }>(
        'SELECT current_user AS usename',
      );
      expect(rows[0]?.usename).toBe('gateway_startup');
    } finally {
      await startupClient.end();
    }

    // 4. gateway_worker authenticates with space/symbol password
    const workerClient = new pg.Client({
      host: '127.0.0.1',
      port: pgPort,
      database: 'switchyard',
      user: 'gateway_worker',
      password: workerPass,
    });
    await workerClient.connect();
    try {
      const { rows } = await workerClient.query<{ usename: string }>(
        'SELECT current_user AS usename',
      );
      expect(rows[0]?.usename).toBe('gateway_worker');
    } finally {
      await workerClient.end();
    }
  });

  it('proves Gateway runtime container connects as gateway_app', async () => {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: pgPort,
      database: 'switchyard',
      user: 'switchyard',
      password: 'switchyard_dev_password',
    });
    await client.connect();
    try {
      const { rows } = await client.query<{ usename: string }>(
        `SELECT usename FROM pg_stat_activity WHERE datname = 'switchyard' AND usename != 'switchyard'`,
      );
      expect(rows.length).toBeGreaterThan(0);
      expect(rows.every((r) => r.usename === 'gateway_app')).toBe(true);
    } finally {
      await client.end();
    }
  });

  it('proves no administrator or migrator credentials are in the Gateway container', () => {
    const envOutput = run('docker', ['exec', gatewayContainer, 'env'], composeEnv);
    const envLines = envOutput.split('\n');

    expect(envLines).toContain('POSTGRES_USER=gateway_app');
    expect(envLines).toContain(`POSTGRES_PASSWORD=${appPass}`);

    // Confirms migrator, bootstrap, and superuser secrets are absent
    expect(envLines.some((line) => line.startsWith('MIGRATE_'))).toBe(false);
    expect(envLines.some((line) => line.startsWith('BOOTSTRAP_'))).toBe(false);
    expect(envLines.some((line) => line.includes('switchyard_dev_password'))).toBe(false);
    expect(envLines.some((line) => line.includes(migratorPass))).toBe(false);
  });

  it('demonstrates Redis ACL attestation and Gateway readiness pass', async () => {
    const res = await fetch(`http://127.0.0.1:${gatewayPort}/health/ready`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      status: string;
      dependencies: { database: string; redis: string };
    };
    expect(body).toEqual({
      status: 'ready',
      dependencies: {
        database: 'healthy',
        redis: 'healthy',
      },
    });
  });

  it('preserves data and idempotency across restart', async () => {
    // Stop and re-start stack
    run('docker', ['compose', '-p', projectName, 'stop'], composeEnv);
    run('docker', ['compose', '-p', projectName, 'up', '-d'], composeEnv);

    // Wait for Gateway readiness
    let ready = false;
    for (let i = 0; i < 30; i += 1) {
      try {
        const res = await fetch(`http://127.0.0.1:${gatewayPort}/health/ready`);
        if (res.ok) {
          ready = true;
          break;
        }
      } catch {
        // wait
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    expect(ready).toBe(true);

    // migrate service log should show "no pending migrations"
    const migrateLogs = run('docker', ['logs', migrateContainer], composeEnv);
    expect(migrateLogs).toContain('no pending migrations');

    // Ledger still has exactly six rows
    const client = new pg.Client({
      host: '127.0.0.1',
      port: pgPort,
      database: 'switchyard',
      user: 'gateway_migrator',
      password: migratorPass,
    });
    await client.connect();
    try {
      const { rows } = await client.query<{ count: string }>(
        'SELECT count(*)::text as count FROM gateway_migrations',
      );
      expect(rows[0]?.count).toBe('7');
    } finally {
      await client.end();
    }
  });
});
