import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import net from 'node:net';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadMigrationFiles } from './migrate.js';

/**
 * Regression test for the fresh-Compose initialization path (review finding DB-15).
 * Demonstrates:
 * 1. A genuinely fresh database initializes successfully via Docker Compose.
 * 2. Role provisioning and local credential provisioning run first via 01-provision-roles.sql
 *    and 02-init-development.sh without executing migrations.
 * 3. All six migrations apply through the authoritative runner (apps/gateway/src/db/migrate.ts)
 *    under gateway_migrator before Gateway admission.
 * 4. All six ledger records have correct SHA-256 checksums matching authoritative files.
 * 5. The Gateway runtime container connects as gateway_app with least privilege.
 * 6. No administrator or migrator credentials are leaked into the Gateway container environment.
 * 7. Redis ACL attestation and Gateway healthcheck (/health/ready) pass.
 * 8. Restarting the stack is idempotent: migrate runs, finds no pending migrations, exits 0,
 *    and data is preserved across restart.
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

describe('SW-1.3.1 / SW-1.3.2 Docker Compose fresh initialization (DB-15 regression gate)', () => {
  const runId = crypto.randomBytes(4).toString('hex');
  const projectName = `switchyard-test-cmp-${runId}`;
  const pgContainer = `switchyard-test-pg-${runId}`;
  const redisContainer = `switchyard-test-redis-${runId}`;
  const migrateContainer = `switchyard-test-migrate-${runId}`;
  const gatewayContainer = `switchyard-test-gw-${runId}`;
  const pgVolume = `switchyard_test_pg_vol_${runId}`;
  const redisVolume = `switchyard_test_redis_vol_${runId}`;
  const networkName = `switchyard-test-net-${runId}`;

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
  });

  it('records correct SHA-256 checksums in gateway_migrations for all six migrations', async () => {
    const expectedFiles = loadMigrationFiles();
    expect(expectedFiles).toHaveLength(6);

    const client = new pg.Client({
      host: '127.0.0.1',
      port: pgPort,
      database: 'switchyard',
      user: 'gateway_migrator',
      password: 'switchyard_migrator_password',
    });
    await client.connect();
    try {
      const { rows } = await client.query<{
        version: string;
        name: string;
        checksum: string;
      }>('SELECT version, name, checksum FROM gateway_migrations ORDER BY version');

      expect(rows).toHaveLength(6);
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
    expect(envLines).toContain('POSTGRES_PASSWORD=switchyard_app_password');

    // Confirms migrator, bootstrap, and superuser secrets are absent
    expect(envLines.some((line) => line.startsWith('MIGRATE_'))).toBe(false);
    expect(envLines.some((line) => line.startsWith('BOOTSTRAP_'))).toBe(false);
    expect(envLines.some((line) => line.includes('switchyard_dev_password'))).toBe(false);
    expect(envLines.some((line) => line.includes('switchyard_migrator_password'))).toBe(false);
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
      password: 'switchyard_migrator_password',
    });
    await client.connect();
    try {
      const { rows } = await client.query<{ count: string }>(
        'SELECT count(*)::text as count FROM gateway_migrations',
      );
      expect(rows[0]?.count).toBe('6');
    } finally {
      await client.end();
    }
  });
});
