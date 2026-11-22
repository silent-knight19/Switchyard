import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import net from 'node:net';
import type { Redis } from 'ioredis';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { verifyPassword } from '../auth/password.js';
import { LoginRateLimiter } from '../auth/rate-limiter.js';
import { AuthenticationService } from '../auth/service.js';
import { EnvelopeVault, type OrganizationDekEnvelope } from '../vault/envelope.js';
import { createKekKeyringFromEnvironment } from '../vault/kek.js';

/**
 * SW-P1-B02 Compose acceptance: the explicit development seeder inside the approved six-component
 * Docker Compose topology.
 *
 * The suite uses a unique Compose project name, disposable named volumes and ephemeral loopback
 * ports. It never contacts the developer's persistent database and removes only its own project.
 */

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close(() => reject(new Error('Failed to obtain a free loopback port')));
        return;
      }
      const port = address.port;
      server.close(() => resolve(port));
    });
  });
}

interface CommandResult {
  status: number;
  stdout: string;
  stderr: string;
}

function runDocker(args: string[], env: Record<string, string>, input?: string): CommandResult {
  const result = spawnSync('docker', args, {
    encoding: 'utf8',
    env: { ...process.env, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
    input,
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.error) {
    throw result.error;
  }
  return {
    status: result.status ?? -1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

async function waitForHttp(url: string, timeoutMs = 90_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        const body = (await response.json()) as { status?: string };
        if (body.status === 'ready') return true;
      }
    } catch {
      // poll until ready
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  return false;
}

async function waitForContainerHealthy(
  container: string,
  composeEnv: Record<string, string>,
  timeoutMs = 90_000,
): Promise<string | undefined> {
  const deadline = Date.now() + timeoutMs;
  let last: string | undefined;
  while (Date.now() < deadline) {
    const result = runDocker(
      ['inspect', '--format', '{{.State.Health.Status}}', container],
      composeEnv,
    );
    if (result.status === 0) {
      last = result.stdout.trim();
      if (last === 'healthy') return last;
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  return last;
}

function inspectEnvironment(container: string, composeEnv: Record<string, string>): string[] {
  const result = runDocker(['inspect', '--format', '{{json .Config.Env}}', container], composeEnv);
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as string[];
}

function hasEnvironmentKey(environment: string[], prefix: string): boolean {
  return environment.some((entry) => entry.startsWith(prefix));
}

describe('SW-P1-B02 Docker Compose explicit development seeding', () => {
  const runId = crypto.randomBytes(4).toString('hex');
  const projectName = `switchyard-test-seed-${runId}`;
  const pgContainer = `switchyard-test-seed-pg-${runId}`;
  const redisContainer = `switchyard-test-seed-redis-${runId}`;
  const migrateContainer = `switchyard-test-seed-migrate-${runId}`;
  const gatewayContainer = `switchyard-test-seed-gw-${runId}`;
  const workerContainer = `switchyard-test-seed-worker-${runId}`;
  const webContainer = `switchyard-test-seed-web-${runId}`;
  const mockContainer = `switchyard-test-seed-mock-${runId}`;
  const pgVolume = `switchyard_test_seed_pg_${runId}`;
  const redisVolume = `switchyard_test_seed_redis_${runId}`;
  const networkName = `switchyard-test-seed-net-${runId}`;

  const pgSuperPassword = crypto.randomBytes(24).toString('hex');
  const migratorPassword = crypto.randomBytes(24).toString('hex');
  const appPassword = crypto.randomBytes(24).toString('hex');
  const startupPassword = crypto.randomBytes(24).toString('hex');
  const workerPassword = crypto.randomBytes(24).toString('hex');
  const redisAdminPassword = crypto.randomBytes(24).toString('hex');
  const redisAppPassword = crypto.randomBytes(24).toString('hex');
  const redisWorkerPassword = crypto.randomBytes(24).toString('hex');
  const mockControlSecret = crypto.randomBytes(32).toString('hex');

  const demoOrgId = '33333333-3333-4333-8333-333333333333';
  const conflictOrgId = '44444444-4444-4444-8444-444444444444';
  const demoEmail = 'compose-demo-admin@example.test';
  const demoPassword = 'Compose-Demo-Password-2026!';
  const replacementPassword = 'Compose-Replacement-Password-2026!';
  const kek = crypto.randomBytes(32).toString('base64url');

  let pgPort: number;
  let redisPort: number;
  let gatewayPort: number;
  let webPort: number;
  let composeEnv: Record<string, string>;

  function demoEnvironment(overrides: Record<string, string> = {}): Record<string, string> {
    return {
      NODE_ENV: 'development',
      DEMO_SEEDING_ENABLED: 'true',
      DEMO_ORG_ID: demoOrgId,
      DEMO_ORG_NAME: 'Compose Demo Organization',
      DEMO_ADMIN_EMAIL: demoEmail,
      DEMO_MONTHLY_BUDGET_MICRODOLLARS: '0',
      DEMO_SEEDING_TARGET: 'compose',
      MASTER_KEK_V1: kek,
      ACTIVE_KEK_VERSION: '1',
      ...overrides,
    };
  }

  function runSeeder(environment: Record<string, string>, password: string): CommandResult {
    const args = ['compose', '-p', projectName, 'run', '--rm', '--no-deps', '-T'];
    for (const name of Object.keys(environment)) {
      // Forward the value through the CLI environment instead of embedding secret values in argv.
      args.push('-e', name);
    }
    args.push('gateway', 'node', 'apps/gateway/dist/db/seed-dev.js');
    return runDocker(args, { ...composeEnv, ...environment }, password);
  }

  async function withAdminClient<T>(callback: (client: pg.Client) => Promise<T>): Promise<T> {
    const client = new pg.Client({
      host: '127.0.0.1',
      port: pgPort,
      database: 'switchyard',
      user: 'switchyard',
      password: pgSuperPassword,
    });
    await client.connect();
    try {
      return await callback(client);
    } finally {
      await client.end();
    }
  }

  async function counts(): Promise<{ organizations: number; users: number }> {
    return withAdminClient(async (client) => {
      const { rows } = await client.query<{ organizations: string; users: string }>(
        `SELECT (SELECT count(*) FROM public.organizations)::text AS organizations,
                (SELECT count(*) FROM public.users)::text AS users`,
      );
      return {
        organizations: Number(rows[0]?.organizations ?? '0'),
        users: Number(rows[0]?.users ?? '0'),
      };
    });
  }

  async function readIdentitySnapshot(): Promise<{
    orgName: string;
    budget: string;
    passwordHash: string;
    envelope: OrganizationDekEnvelope;
  }> {
    return withAdminClient(async (client) => {
      const { rows } = await client.query<{
        org_name: string;
        budget: string;
        password_hash: string;
        kek_version: number;
        wrapped_dek: Buffer;
        dek_iv: Buffer;
        dek_auth_tag: Buffer;
      }>(
        `SELECT o.name AS org_name, o.monthly_budget_microdollars::text AS budget,
                u.password_hash, o.kek_version, o.wrapped_dek, o.dek_iv, o.dek_auth_tag
         FROM public.organizations o JOIN public.users u ON u.org_id = o.id
         WHERE o.id = $1`,
        [demoOrgId],
      );
      const row = rows[0];
      if (!row) throw new Error('Expected the seeded demo identity to exist');
      return {
        orgName: row.org_name,
        budget: row.budget,
        passwordHash: row.password_hash,
        envelope: {
          kekVersion: row.kek_version,
          wrappedDek: row.wrapped_dek,
          dekIv: row.dek_iv,
          dekAuthTag: row.dek_auth_tag,
        },
      };
    });
  }

  function assertEnvelopeRoundTrip(envelope: OrganizationDekEnvelope): void {
    const vault = new EnvelopeVault(
      createKekKeyringFromEnvironment({ MASTER_KEK_V1: kek, ACTIVE_KEK_VERSION: '1' }),
    );
    const providerKeyId = crypto.randomUUID();
    const plaintext = Buffer.from('compose-synthetic-credential-canary', 'utf8');
    try {
      const providerEnvelope = vault.encryptProviderCredential({
        orgId: demoOrgId,
        providerKeyId,
        provider: 'openai',
        plaintext,
        organizationEnvelope: envelope,
      });
      const decrypted = vault.decryptProviderCredential({
        orgId: demoOrgId,
        providerKeyId,
        provider: 'openai',
        providerEnvelope,
        organizationEnvelope: envelope,
      });
      try {
        expect(decrypted.equals(plaintext)).toBe(true);
      } finally {
        decrypted.fill(0);
      }
    } finally {
      plaintext.fill(0);
    }
  }

  async function authenticateDemo(password: string): Promise<{ orgId: string; role: string }> {
    const pool = new pg.Pool({
      host: '127.0.0.1',
      port: pgPort,
      database: 'switchyard',
      user: 'gateway_app',
      password: appPassword,
      max: 1,
    });
    try {
      const service = new AuthenticationService({
        pool,
        rateLimiter: new LoginRateLimiter({
          eval: vi.fn().mockResolvedValue(1),
        } as unknown as Redis),
      });
      const user = await service.authenticate(demoEmail, password, '127.0.0.1');
      return { orgId: user.orgId, role: user.role };
    } finally {
      await pool.end();
    }
  }

  beforeAll(async () => {
    pgPort = await getFreePort();
    redisPort = await getFreePort();
    gatewayPort = await getFreePort();
    webPort = await getFreePort();

    composeEnv = {
      POSTGRES_USER: 'switchyard',
      POSTGRES_PASSWORD: pgSuperPassword,
      POSTGRES_DB: 'switchyard',
      POSTGRES_PORT: String(pgPort),
      GATEWAY_POSTGRES_USER: 'gateway_app',
      GATEWAY_POSTGRES_PASSWORD: appPassword,
      GATEWAY_APP_PASSWORD: appPassword,
      GATEWAY_MIGRATOR_PASSWORD: migratorPassword,
      MIGRATE_POSTGRES_PASSWORD: migratorPassword,
      GATEWAY_STARTUP_PASSWORD: startupPassword,
      GATEWAY_WORKER_USER: 'gateway_worker',
      GATEWAY_WORKER_PASSWORD: workerPassword,
      REDIS_PASSWORD: redisAdminPassword,
      REDIS_APP_USER: 'switchyard_app',
      REDIS_APP_PASSWORD: redisAppPassword,
      REDIS_WORKER_USER: 'switchyard_worker',
      REDIS_WORKER_PASSWORD: redisWorkerPassword,
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
    };

    const up = runDocker(['compose', '-p', projectName, 'up', '-d', '--build'], composeEnv);
    expect(up.status, up.stderr).toBe(0);

    expect(await waitForHttp(`http://127.0.0.1:${gatewayPort}/health/ready`)).toBe(true);
    expect(await waitForHttp(`http://127.0.0.1:${webPort}/health/ready`)).toBe(true);
    for (const container of [
      pgContainer,
      redisContainer,
      gatewayContainer,
      workerContainer,
      webContainer,
      mockContainer,
    ]) {
      expect(await waitForContainerHealthy(container, composeEnv)).toBe('healthy');
    }
  }, 600_000);

  afterAll(() => {
    try {
      runDocker(['compose', '-p', projectName, 'down', '-v', '--remove-orphans'], composeEnv);
    } catch {
      // Best-effort cleanup of this test's own project and volumes only.
    }
  }, 120_000);

  it('starts all six services with no demo account before explicit seeding', async () => {
    const before = await counts();
    expect(before).toEqual({ organizations: 0, users: 0 });

    const gatewayLogs = runDocker(['logs', gatewayContainer], composeEnv);
    const workerLogs = runDocker(['logs', workerContainer], composeEnv);
    const webLogs = runDocker(['logs', webContainer], composeEnv);
    for (const logs of [gatewayLogs, workerLogs, webLogs]) {
      expect(logs.stdout + logs.stderr).not.toContain('Demo organization provisioned');
      expect(logs.stdout + logs.stderr).not.toContain('seed-dev');
    }
  }, 120_000);

  it('provisions the account only when the explicit CLI runs and verifies it end to end', async () => {
    const result = runSeeder(demoEnvironment(), demoPassword);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain('Demo organization provisioned');
    expect(result.stdout).toContain('Status: CREATED');

    expect(await counts()).toEqual({ organizations: 1, users: 1 });
    const snapshot = await readIdentitySnapshot();
    expect(snapshot.orgName).toBe('Compose Demo Organization');
    expect(snapshot.budget).toBe('0');
    expect(snapshot.passwordHash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    await expect(verifyPassword(snapshot.passwordHash, demoPassword)).resolves.toBe(true);
    assertEnvelopeRoundTrip(snapshot.envelope);

    await expect(authenticateDemo(demoPassword)).resolves.toEqual({
      orgId: demoOrgId,
      role: 'admin',
    });
    await expect(authenticateDemo(replacementPassword)).rejects.toMatchObject({
      reason: 'INVALID_CREDENTIALS',
    });
  }, 180_000);

  it('repeats safely without duplicating or mutating the seeded identity', async () => {
    const before = await readIdentitySnapshot();

    const result = runSeeder(
      demoEnvironment({
        DEMO_ORG_NAME: 'Renamed Compose Demo Organization',
        DEMO_MONTHLY_BUDGET_MICRODOLLARS: '999999',
      }),
      replacementPassword,
    );

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain('Status: ALREADY_PRESENT');
    expect(await counts()).toEqual({ organizations: 1, users: 1 });

    const after = await readIdentitySnapshot();
    expect(after.orgName).toBe(before.orgName);
    expect(after.budget).toBe(before.budget);
    expect(after.passwordHash).toBe(before.passwordHash);
    expect(after.envelope.wrappedDek.equals(before.envelope.wrappedDek)).toBe(true);
    expect(after.envelope.dekIv.equals(before.envelope.dekIv)).toBe(true);
    expect(after.envelope.dekAuthTag.equals(before.envelope.dekAuthTag)).toBe(true);

    await expect(authenticateDemo(demoPassword)).resolves.toEqual({
      orgId: demoOrgId,
      role: 'admin',
    });
    await expect(authenticateDemo(replacementPassword)).rejects.toMatchObject({
      reason: 'INVALID_CREDENTIALS',
    });
  }, 180_000);

  it('rejects an incompatible KEK on repeat without changing the demo account', async () => {
    const before = await readIdentitySnapshot();
    const result = runSeeder(
      demoEnvironment({ MASTER_KEK_V1: crypto.randomBytes(32).toString('base64url') }),
      replacementPassword,
    );
    expect(result.status).toBe(1);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('EXISTING_ENVELOPE_INVALID');
    expect(await counts()).toEqual({ organizations: 1, users: 1 });

    const after = await readIdentitySnapshot();
    expect(after.passwordHash).toBe(before.passwordHash);
    expect(after.envelope.wrappedDek.equals(before.envelope.wrappedDek)).toBe(true);
    expect(after.envelope.dekIv.equals(before.envelope.dekIv)).toBe(true);
    expect(after.envelope.dekAuthTag.equals(before.envelope.dekAuthTag)).toBe(true);
    expect(after.orgName).toBe(before.orgName);
    expect(after.budget).toBe(before.budget);
  }, 120_000);

  it('reports a conflicting organization identity as CONFLICT without creating records', async () => {
    const result = runSeeder(
      demoEnvironment({
        DEMO_ORG_ID: conflictOrgId,
        DEMO_ORG_NAME: 'Conflicting Compose Organization',
      }),
      replacementPassword,
    );

    expect(result.status).toBe(3);
    expect(result.stdout).toContain('Status: CONFLICT');
    expect(await counts()).toEqual({ organizations: 1, users: 1 });
  }, 120_000);

  it('rejects production execution before any database mutation', async () => {
    const before = await readIdentitySnapshot();

    const result = runSeeder(
      demoEnvironment({ NODE_ENV: 'production', DEMO_SEEDING_ENABLED: 'true' }),
      replacementPassword,
    );

    expect(result.status).toBe(2);
    expect(result.stderr).toContain('PRODUCTION_FORBIDDEN');
    expect(await counts()).toEqual({ organizations: 1, users: 1 });

    const after = await readIdentitySnapshot();
    expect(after.passwordHash).toBe(before.passwordHash);
    expect(after.envelope.wrappedDek.equals(before.envelope.wrappedDek)).toBe(true);
  }, 120_000);

  it('withholds KEK, database and provider secrets from worker and web runtimes', () => {
    const gatewayEnvironment = inspectEnvironment(gatewayContainer, composeEnv);
    const workerEnvironment = inspectEnvironment(workerContainer, composeEnv);
    const webEnvironment = inspectEnvironment(webContainer, composeEnv);

    for (const environment of [gatewayEnvironment, workerEnvironment, webEnvironment]) {
      expect(hasEnvironmentKey(environment, 'MASTER_KEK')).toBe(false);
      expect(hasEnvironmentKey(environment, 'ACTIVE_KEK_VERSION')).toBe(false);
      expect(hasEnvironmentKey(environment, 'DEMO_SEEDING')).toBe(false);
      expect(hasEnvironmentKey(environment, 'OPENAI_API_KEY')).toBe(false);
    }

    for (const prefix of ['POSTGRES_', 'REDIS_']) {
      expect(hasEnvironmentKey(webEnvironment, prefix)).toBe(false);
    }
    expect(hasEnvironmentKey(workerEnvironment, 'POSTGRES_PASSWORD')).toBe(true);
    expect(hasEnvironmentKey(workerEnvironment, 'MASTER_KEK_V1')).toBe(false);
  }, 60_000);

  it('remains healthy and preserves the seeded identity across a normal restart', async () => {
    const before = await readIdentitySnapshot();

    const stop = runDocker(['compose', '-p', projectName, 'stop'], composeEnv);
    expect(stop.status, stop.stderr).toBe(0);
    const restart = runDocker(['compose', '-p', projectName, 'up', '-d'], composeEnv);
    expect(restart.status, restart.stderr).toBe(0);

    expect(await waitForHttp(`http://127.0.0.1:${gatewayPort}/health/ready`)).toBe(true);
    expect(await waitForHttp(`http://127.0.0.1:${webPort}/health/ready`)).toBe(true);
    for (const container of [
      pgContainer,
      redisContainer,
      gatewayContainer,
      workerContainer,
      webContainer,
      mockContainer,
    ]) {
      expect(await waitForContainerHealthy(container, composeEnv)).toBe('healthy');
    }

    expect(await counts()).toEqual({ organizations: 1, users: 1 });
    const after = await readIdentitySnapshot();
    expect(after.passwordHash).toBe(before.passwordHash);
    expect(after.envelope.wrappedDek.equals(before.envelope.wrappedDek)).toBe(true);
    expect(after.envelope.dekIv.equals(before.envelope.dekIv)).toBe(true);
    expect(after.envelope.dekAuthTag.equals(before.envelope.dekAuthTag)).toBe(true);
    assertEnvelopeRoundTrip(after.envelope);

    const gatewayLogs = runDocker(['logs', gatewayContainer], composeEnv);
    expect(gatewayLogs.stdout + gatewayLogs.stderr).not.toContain('Demo organization provisioned');
  }, 300_000);
});
