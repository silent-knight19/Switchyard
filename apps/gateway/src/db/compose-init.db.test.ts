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
  const workerContainer = `switchyard-test-worker-${runId}`;
  const webContainer = `switchyard-test-web-${runId}`;
  const mockContainer = `switchyard-test-mock-${runId}`;
  const pgVolume = `switchyard_test_pg_vol_${runId}`;
  const redisVolume = `switchyard_test_redis_vol_${runId}`;
  const networkName = `switchyard-test-net-${runId}`;

  // Passwords containing single quotes, spaces, and SQL injection syntax (DB-16) // gitleaks:allow
  const migratorPass = "migrator'pass; DROP TABLE IF EXISTS injection_target; --"; // gitleaks:allow
  const appPass = 'app \'pass with spaces\' and "quotes"'; // gitleaks:allow
  const startupPass = "startup'quote; SELECT '1';"; // gitleaks:allow
  const workerPass = "worker 'pass' with spaces & symbols"; // gitleaks:allow
  const mockControlSecret = 'f'.repeat(64); // gitleaks:allow

  let pgPort: number;
  let redisPort: number;
  let gatewayPort: number;
  let webPort: number;
  let composeEnv: Record<string, string>;

  beforeAll(async () => {
    pgPort = await getFreePort();
    redisPort = await getFreePort();
    gatewayPort = await getFreePort();
    webPort = await getFreePort();

    composeEnv = {
      POSTGRES_PORT: String(pgPort),
      REDIS_PORT: String(redisPort),
      PORT: String(gatewayPort),
      WEB_PORT: String(webPort),
      POSTGRES_CONTAINER_NAME: pgContainer,
      REDIS_CONTAINER_NAME: redisContainer,
      MIGRATE_CONTAINER_NAME: migrateContainer,
      GATEWAY_CONTAINER_NAME: gatewayContainer,
      WORKER_CONTAINER_NAME: workerContainer,
      WEB_CONTAINER_NAME: webContainer,
      MOCK_UPSTREAM_CONTAINER_NAME: mockContainer,
      MOCK_CONTROL_SECRET: mockControlSecret,
      POSTGRES_VOLUME_NAME: pgVolume,
      REDIS_VOLUME_NAME: redisVolume,
      NETWORK_NAME: networkName,
      GATEWAY_MIGRATOR_PASSWORD: migratorPass,
      MIGRATE_POSTGRES_PASSWORD: migratorPass,
      GATEWAY_APP_PASSWORD: appPass,
      GATEWAY_POSTGRES_PASSWORD: appPass,
      GATEWAY_STARTUP_PASSWORD: startupPass,
      GATEWAY_WORKER_USER: 'gateway_worker',
      GATEWAY_WORKER_PASSWORD: workerPass,
      REDIS_WORKER_USER: 'switchyard_worker',
      REDIS_WORKER_PASSWORD: 'switchyard_worker_password',
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

    // Wait for Mock Upstream health readiness (up to 30s)
    let mockReady = false;
    for (let i = 0; i < 30; i += 1) {
      try {
        const status = run(
          'docker',
          ['inspect', mockContainer, '--format', '{{.State.Health.Status}}'],
          composeEnv,
        ).trim();
        if (status === 'healthy') {
          mockReady = true;
          break;
        }
      } catch {
        // continue polling until ready
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    expect(mockReady).toBe(true);

    // Wait for Worker health readiness (up to 30s)
    let workerReady = false;
    for (let i = 0; i < 30; i += 1) {
      try {
        const status = run(
          'docker',
          ['inspect', workerContainer, '--format', '{{.State.Health.Status}}'],
          composeEnv,
        ).trim();
        if (status === 'healthy') {
          workerReady = true;
          break;
        }
      } catch {
        // continue polling until ready
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    expect(workerReady).toBe(true);

    // Wait for Web health readiness (up to 30s)
    let webReady = false;
    for (let i = 0; i < 30; i += 1) {
      try {
        const res = await fetch(`http://127.0.0.1:${webPort}/health/ready`);
        if (res.ok) {
          const body = (await res.json()) as { status: string };
          if (body.status === 'ready') {
            webReady = true;
            break;
          }
        }
      } catch {
        // continue polling until ready
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    expect(webReady).toBe(true);
  }, 600_000);

  afterAll(() => {
    try {
      run('docker', ['compose', '-p', projectName, 'down', '-v', '--remove-orphans'], composeEnv);
    } catch {
      // ignore teardown errors
    }
  }, 60_000);

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

    const mockLogs = run('docker', ['logs', mockContainer], composeEnv);
    expect(mockLogs).not.toContain(mockControlSecret);

    const workerLogs = run('docker', ['logs', workerContainer], composeEnv);
    expect(workerLogs).not.toContain(workerPass);
    expect(workerLogs).not.toContain(appPass);

    const webLogs = run('docker', ['logs', webContainer], composeEnv);
    expect(webLogs).not.toContain(workerPass);
    expect(webLogs).not.toContain(appPass);
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
    expect(migrateLogs).toContain('applied 0008');
    expect(migrateLogs).toContain('applied 0009');
    expect(migrateLogs).toContain('applied 0010');
    expect(migrateLogs).toContain('applied 0011');
  });

  it('records correct SHA-256 checksums in gateway_migrations for all eleven migrations', async () => {
    const expectedFiles = loadMigrationFiles();
    expect(expectedFiles).toHaveLength(11);

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

      expect(rows).toHaveLength(11);
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
      expect(rows.some((r) => r.usename === 'gateway_app')).toBe(true);
      expect(rows.some((r) => r.usename === 'gateway_worker')).toBe(true);
      expect(rows.every((r) => r.usename === 'gateway_app' || r.usename === 'gateway_worker')).toBe(
        true,
      );
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

    // Wait for Web readiness
    let webReady = false;
    for (let i = 0; i < 30; i += 1) {
      try {
        const res = await fetch(`http://127.0.0.1:${webPort}/health/ready`);
        if (res.ok) {
          webReady = true;
          break;
        }
      } catch {
        // wait
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    expect(webReady).toBe(true);

    // migrate service log should show "no pending migrations"
    const migrateLogs = run('docker', ['logs', migrateContainer], composeEnv);
    expect(migrateLogs).toContain('no pending migrations');

    // Ledger still has exactly ten rows
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
      expect(rows[0]?.count).toBe('11');
    } finally {
      await client.end();
    }
  });

  it('proves mock-upstream container runs healthy with no published host ports', () => {
    const inspectStatus = run(
      'docker',
      ['inspect', mockContainer, '--format', '{{.State.Status}}'],
      composeEnv,
    ).trim();
    expect(inspectStatus).toBe('running');

    const inspectHealth = run(
      'docker',
      ['inspect', mockContainer, '--format', '{{.State.Health.Status}}'],
      composeEnv,
    ).trim();
    expect(inspectHealth).toBe('healthy');

    const portMapping = run('docker', ['port', mockContainer], composeEnv).trim();
    expect(portMapping).toBe('');

    const portBindings = run(
      'docker',
      ['inspect', mockContainer, '--format', '{{json .HostConfig.PortBindings}}'],
      composeEnv,
    ).trim();
    expect(portBindings === 'null' || portBindings === '{}').toBe(true);
  });

  it('proves authorized access to mock-upstream over the private Compose network', () => {
    const script = [
      "fetch('http://mock-upstream:4000/v1/chat/completions', {",
      "  method: 'POST',",
      "  headers: { 'Content-Type': 'application/json' },",
      '  body: JSON.stringify({',
      "    model: 'mock-chat-v1',",
      "    messages: [{ role: 'user', content: 'private net check' }]",
      '  })',
      '})',
      '.then(r => r.json())',
      '.then(d => {',
      "  if (d.object === 'chat.completion') process.exit(0);",
      '  else process.exit(1);',
      '})',
      '.catch(() => process.exit(2));',
    ].join(' ');

    const output = run(
      'docker',
      ['exec', gatewayContainer, 'node', '-e', script],
      composeEnv,
    ).trim();
    expect(output).toBe('');
  });

  it('proves unauthorized test-control request to mock-upstream over private network returns 401', () => {
    const script = [
      "fetch('http://mock-upstream:4000/__test/abort-observations')",
      '.then(r => {',
      '  if (r.status === 401) process.exit(0);',
      '  else process.exit(1);',
      '})',
      '.catch(() => process.exit(2));',
    ].join(' ');

    const output = run(
      'docker',
      ['exec', gatewayContainer, 'node', '-e', script],
      composeEnv,
    ).trim();
    expect(output).toBe('');
  });

  it('proves authorized request can select a deterministic HTTP fault fixture over private network', () => {
    const script = [
      "fetch('http://mock-upstream:4000/v1/chat/completions', {",
      "  method: 'POST',",
      '  headers: {',
      "    'Content-Type': 'application/json',",
      "    'x-test-fixture-id': 'error.500',",
      "    'Authorization': 'Bearer ' + process.env.TEST_CONTROL_SECRET",
      '  },',
      '  body: JSON.stringify({',
      "    model: 'mock-chat-v1',",
      "    messages: [{ role: 'user', content: 'fault test' }]",
      '  })',
      '})',
      '.then(r => {',
      '  if (r.status === 500) process.exit(0);',
      '  else process.exit(1);',
      '})',
      '.catch(() => process.exit(2));',
    ].join(' ');

    const output = run(
      'docker',
      [
        'exec',
        '-e',
        `TEST_CONTROL_SECRET=${mockControlSecret}`,
        gatewayContainer,
        'node',
        '-e',
        script,
      ],
      composeEnv,
    ).trim();
    expect(output).toBe('');
  });

  it('proves all six mandatory components are running healthy in Docker Compose', async () => {
    const services = [
      { name: 'postgres', container: pgContainer },
      { name: 'redis', container: redisContainer },
      { name: 'gateway', container: gatewayContainer },
      { name: 'worker', container: workerContainer },
      { name: 'web', container: webContainer },
      { name: 'mock-upstream', container: mockContainer },
    ];

    for (const svc of services) {
      let healthy = false;
      for (let i = 0; i < 30; i += 1) {
        const health = run(
          'docker',
          ['inspect', svc.container, '--format', '{{.State.Health.Status}}'],
          composeEnv,
        ).trim();
        if (health === 'healthy') {
          healthy = true;
          break;
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
      if (!healthy) {
        const lastHealth = run(
          'docker',
          ['inspect', svc.container, '--format', '{{.State.Health.Status}}'],
          composeEnv,
        ).trim();
        const logs = run('docker', ['logs', svc.container, '--tail', '20'], composeEnv);
        throw new Error(
          `Service "${svc.name}" (${svc.container}) is not healthy! Health: "${lastHealth}". Logs:\n${logs}`,
        );
      }
      expect(healthy).toBe(true);

      const status = run(
        'docker',
        ['inspect', svc.container, '--format', '{{.State.Status}}'],
        composeEnv,
      ).trim();
      expect(status).toBe('running');
    }
  });

  it('proves worker container runs healthy with 0 published host ports and connects as gateway_worker', async () => {
    // 1. Worker publishes NO host ports
    const portMapping = run('docker', ['port', workerContainer], composeEnv).trim();
    expect(portMapping).toBe('');

    const portBindings = run(
      'docker',
      ['inspect', workerContainer, '--format', '{{json .HostConfig.PortBindings}}'],
      composeEnv,
    ).trim();
    expect(portBindings === 'null' || portBindings === '{}').toBe(true);

    // 2. Worker connects to PostgreSQL under gateway_worker identity
    const client = new pg.Client({
      host: '127.0.0.1',
      port: pgPort,
      database: 'switchyard',
      user: 'switchyard',
      password: 'switchyard_dev_password',
    });
    await client.connect();
    try {
      let foundWorker = false;
      for (let i = 0; i < 15; i += 1) {
        const { rows } = await client.query<{ usename: string }>(
          `SELECT usename FROM pg_stat_activity WHERE datname = 'switchyard' AND usename = 'gateway_worker'`,
        );
        if (rows.length > 0 && rows.some((r) => r.usename === 'gateway_worker')) {
          foundWorker = true;
          break;
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
      expect(foundWorker).toBe(true);
    } finally {
      await client.end();
    }
  });

  it('proves worker connects to Redis under worker ACL and prohibited commands are denied', () => {
    // Prohibited commands must be rejected for worker ACL identity
    for (const cmd of [
      'FLUSHALL',
      'FLUSHDB',
      'CONFIG GET maxmemory',
      'DEBUG OBJECT x',
      'SHUTDOWN',
      'REPLICAOF NO ONE',
      'KEYS *',
      'ACL LIST',
    ]) {
      const result = run(
        'docker',
        [
          'exec',
          redisContainer,
          'redis-cli',
          'ACL',
          'DRYRUN',
          'switchyard_worker',
          ...cmd.split(' '),
        ],
        composeEnv,
      ).trim();
      expect(result).toMatch(/no permissions/i);
    }
  });

  it('proves web container responds over loopback port and publishes no unauthorized host ports', async () => {
    // 1. Web health endpoint responds with ready status
    const healthRes = await fetch(`http://127.0.0.1:${webPort}/health/ready`);
    expect(healthRes.status).toBe(200);
    const healthBody = (await healthRes.json()) as { status: string; service: string };
    expect(healthBody.status).toBe('ready');
    expect(healthBody.service).toBe('web');

    // 2. Web root page responds over loopback
    const pageRes = await fetch(`http://127.0.0.1:${webPort}/`);
    expect(pageRes.status).toBe(200);
    const pageHtml = await pageRes.text();
    expect(pageHtml).toContain('Switchyard — AI Inference Gateway Control Plane');

    // 3. Port binding is strictly bound to 127.0.0.1 (not 0.0.0.0)
    const portMapping = run('docker', ['port', webContainer], composeEnv).trim();
    expect(portMapping).toContain(`127.0.0.1:${webPort}`);
    expect(portMapping).not.toContain('0.0.0.0:');
  });

  it('proves web and worker can be stopped and restarted independently without interrupting Gateway', async () => {
    // 1. Stop worker and web services independently
    run('docker', ['compose', '-p', projectName, 'stop', 'worker', 'web'], composeEnv);

    // 2. Gateway must remain operational and healthy
    const gwRes = await fetch(`http://127.0.0.1:${gatewayPort}/health/ready`);
    expect(gwRes.status).toBe(200);
    const gwBody = (await gwRes.json()) as { status: string };
    expect(gwBody.status).toBe('ready');

    // 3. Restart worker and web
    run('docker', ['compose', '-p', projectName, 'up', '-d', 'worker', 'web'], composeEnv);

    // 4. Poll for worker health recovery
    let workerRecovered = false;
    for (let i = 0; i < 30; i += 1) {
      try {
        const status = run(
          'docker',
          ['inspect', workerContainer, '--format', '{{.State.Health.Status}}'],
          composeEnv,
        ).trim();
        if (status === 'healthy') {
          workerRecovered = true;
          break;
        }
      } catch {
        // wait
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    expect(workerRecovered).toBe(true);

    // 5. Poll for web health recovery
    let webRecovered = false;
    for (let i = 0; i < 30; i += 1) {
      try {
        const res = await fetch(`http://127.0.0.1:${webPort}/health/ready`);
        if (res.ok) {
          const body = (await res.json()) as { status: string };
          if (body.status === 'ready') {
            webRecovered = true;
            break;
          }
        }
      } catch {
        // wait
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    expect(webRecovered).toBe(true);
  });

  it('proves worker detects dependency loss and recovers health when dependency is restored (WRK-01)', async () => {
    // 1. Initial state: worker CLI health check must pass with exit code 0
    const initialHealth = run(
      'docker',
      ['exec', workerContainer, 'node', 'apps/gateway/dist/worker-main.js', '--health'],
      composeEnv,
    );
    expect(initialHealth).toBe('');

    // 2. Pause isolated test Redis container to induce dependency loss
    run('docker', ['pause', redisContainer], composeEnv);

    try {
      // 3. Worker health probe must fail within bounded interval (probe interval 5s + timeout 2s)
      let workerReportedUnhealthy = false;
      for (let i = 0; i < 20; i += 1) {
        try {
          run(
            'docker',
            ['exec', workerContainer, 'node', 'apps/gateway/dist/worker-main.js', '--health'],
            composeEnv,
          );
        } catch {
          // Health probe failed as expected
          const healthJson = run(
            'docker',
            ['exec', workerContainer, 'cat', '/tmp/switchyard-worker-health.json'],
            composeEnv,
          );
          if (healthJson.includes('"status":"unhealthy"')) {
            workerReportedUnhealthy = true;
            break;
          }
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
      expect(workerReportedUnhealthy).toBe(true);
    } finally {
      // 4. Restore Redis dependency
      run('docker', ['unpause', redisContainer], composeEnv);
    }

    // 5. Worker must automatically recover and return exit code 0 on health check
    let workerRecovered = false;
    for (let i = 0; i < 20; i += 1) {
      try {
        run(
          'docker',
          ['exec', workerContainer, 'node', 'apps/gateway/dist/worker-main.js', '--health'],
          composeEnv,
        );
        const healthJson = run(
          'docker',
          ['exec', workerContainer, 'cat', '/tmp/switchyard-worker-health.json'],
          composeEnv,
        );
        if (healthJson.includes('"status":"ready"')) {
          workerRecovered = true;
          break;
        }
      } catch {
        // wait for next periodic probe
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    expect(workerRecovered).toBe(true);
  });
});
