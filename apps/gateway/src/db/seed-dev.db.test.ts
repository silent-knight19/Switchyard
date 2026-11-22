import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import type { Redis } from 'ioredis';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { hashPassword, verifyPassword } from '../auth/password.js';
import { LoginRateLimiter } from '../auth/rate-limiter.js';
import { AuthenticationService } from '../auth/service.js';
import { EnvelopeVault, type OrganizationDekEnvelope } from '../vault/envelope.js';
import { createKekKeyringFromEnvironment, type KekKeyring } from '../vault/kek.js';
import { runMigrations } from './migrate.js';
import {
  runSeedDev,
  SEED_EXIT_CONFLICT,
  SEED_EXIT_FAILURE,
  SEED_EXIT_INVALID_CONFIGURATION,
  SEED_EXIT_SUCCESS,
} from './seed-dev/run.js';
import { withTenant } from './tenant.js';
import {
  bootstrapDatabase,
  createDisposableDatabase,
  createRolePasswords,
  roleConnectionString,
  startDisposableCluster,
  type DisposableCluster,
  type DisposableDatabase,
} from './test/disposable-pg.js';

const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
const ORG_B_ID = '22222222-2222-4222-8222-222222222222';
const ADMIN_A_EMAIL = 'demo-admin@example.test';
const ADMIN_B_EMAIL = 'other-admin@example.test';
const ADMIN_PASSWORD = 'Correct-Horse-Demo-2026!';
const OTHER_PASSWORD = 'Different-Horse-Demo-2026!';

function newKek(): string {
  return crypto.randomBytes(32).toString('base64url');
}

function seedEnv(
  db: DisposableDatabase,
  passwords: ReturnType<typeof createRolePasswords>,
  options: {
    kek?: string;
    orgId?: string;
    orgName?: string;
    adminEmail?: string;
    budget?: string;
    adminPassword?: string;
  } = {},
): Record<string, string | undefined> {
  const url = new URL(db.url);
  return {
    NODE_ENV: 'development',
    DEMO_SEEDING_ENABLED: 'true',
    DEMO_ORG_ID: options.orgId ?? ORG_A_ID,
    DEMO_ORG_NAME: options.orgName ?? 'Local Demo Organization',
    DEMO_ADMIN_EMAIL: options.adminEmail ?? ADMIN_A_EMAIL,
    DEMO_MONTHLY_BUDGET_MICRODOLLARS: options.budget ?? '0',
    POSTGRES_HOST: url.hostname,
    POSTGRES_PORT: url.port,
    POSTGRES_DB: db.name,
    POSTGRES_USER: 'gateway_app',
    POSTGRES_PASSWORD: passwords.gateway_app,
    MASTER_KEK_V1: options.kek ?? newKek(),
    ACTIVE_KEK_VERSION: '1',
  };
}

async function runSeed(
  env: Record<string, string | undefined>,
  password: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const code = await runSeedDev({
    env,
    stdin: Readable.from([Buffer.from(password, 'utf8')]),
    stdout: { write: (chunk) => stdout.push(chunk) },
    stderr: { write: (chunk) => stderr.push(chunk) },
  });
  return { code, stdout: stdout.join(''), stderr: stderr.join('') };
}

interface DatabaseHandle {
  db: DisposableDatabase;
  admin: pg.Client;
}

async function createMigratedDatabase(
  cluster: DisposableCluster,
  passwords: ReturnType<typeof createRolePasswords>,
  label: string,
): Promise<DatabaseHandle> {
  const db = await createDisposableDatabase(cluster, label);
  await bootstrapDatabase(db, passwords);

  const migrator = new pg.Pool({
    connectionString: roleConnectionString(db.url, 'gateway_migrator', passwords.gateway_migrator),
  });
  try {
    await runMigrations(migrator);
  } finally {
    await migrator.end();
  }

  const admin = new pg.Client({ connectionString: db.url });
  await admin.connect();
  return { db, admin };
}

async function closeDatabase(handle: DatabaseHandle | undefined): Promise<void> {
  if (!handle) return;
  await handle.admin.end().catch(() => undefined);
  await handle.db.drop().catch(() => undefined);
}

async function countRows(admin: pg.Client, table: 'organizations' | 'users'): Promise<number> {
  const { rows } = await admin.query<{ count: string }>(
    `SELECT count(*)::text AS count FROM public.${table}`,
  );
  return Number(rows[0]?.count ?? '0');
}

async function readEnvelope(admin: pg.Client, orgId: string): Promise<OrganizationDekEnvelope> {
  const { rows } = await admin.query<{
    kek_version: number;
    wrapped_dek: Buffer;
    dek_iv: Buffer;
    dek_auth_tag: Buffer;
  }>(
    `SELECT kek_version, wrapped_dek, dek_iv, dek_auth_tag
     FROM public.organizations WHERE id = $1`,
    [orgId],
  );
  const row = rows[0];
  if (!row) throw new Error('Expected a persisted organization envelope');
  return {
    kekVersion: row.kek_version,
    wrappedDek: row.wrapped_dek,
    dekIv: row.dek_iv,
    dekAuthTag: row.dek_auth_tag,
  };
}

function keyring(kek: string): KekKeyring {
  return createKekKeyringFromEnvironment({
    MASTER_KEK_V1: kek,
    ACTIVE_KEK_VERSION: '1',
  });
}

/** Prove the persisted DEK unwraps and round-trips a synthetic provider credential. */
function assertEnvelopeRoundTrip(
  keyringValue: KekKeyring,
  orgId: string,
  envelope: OrganizationDekEnvelope,
): void {
  const vault = new EnvelopeVault(keyringValue);
  const providerKeyId = crypto.randomUUID();
  const plaintext = Buffer.from('synthetic-provider-credential-canary', 'utf8');
  try {
    const providerEnvelope = vault.encryptProviderCredential({
      orgId,
      providerKeyId,
      provider: 'openai',
      plaintext,
      organizationEnvelope: envelope,
    });
    const decrypted = vault.decryptProviderCredential({
      orgId,
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

describe('SW-P1-B02 development seeding PostgreSQL integration', () => {
  let cluster: DisposableCluster;
  const passwords = createRolePasswords();

  beforeAll(async () => {
    cluster = await startDisposableCluster();
  }, 120_000);

  afterAll(async () => {
    if (cluster) await cluster.stop();
  }, 60_000);

  describe('first creation, authentication, envelope and RLS', () => {
    let handle: DatabaseHandle | undefined;
    let appPool: pg.Pool | undefined;
    let seededKek: string;
    let env: Record<string, string | undefined>;
    let seedResult: { code: number; stdout: string; stderr: string };

    beforeAll(async () => {
      handle = await createMigratedDatabase(cluster, passwords, 'seed_dev_first');
      seededKek = newKek();
      env = seedEnv(handle.db, passwords, { kek: seededKek });
      seedResult = await runSeed(env, ADMIN_PASSWORD);

      appPool = new pg.Pool({
        connectionString: roleConnectionString(handle.db.url, 'gateway_app', passwords.gateway_app),
      });
    }, 120_000);

    afterAll(async () => {
      if (appPool) await appPool.end();
      await closeDatabase(handle);
    }, 60_000);

    it('creates exactly one organization and one initial admin as CREATED', async () => {
      expect(seedResult.code).toBe(SEED_EXIT_SUCCESS);
      expect(seedResult.stdout).toContain('Status: CREATED');
      expect(seedResult.stderr).toBe('');

      const admin = handle!.admin;
      expect(await countRows(admin, 'organizations')).toBe(1);
      expect(await countRows(admin, 'users')).toBe(1);

      const { rows: orgRows } = await admin.query<{
        id: string;
        name: string;
        monthly_budget_microdollars: string;
        kek_version: number;
        wrapped_dek: Buffer;
        dek_iv: Buffer;
        dek_auth_tag: Buffer;
      }>(
        `SELECT id, name, monthly_budget_microdollars::text AS monthly_budget_microdollars,
                kek_version, wrapped_dek, dek_iv, dek_auth_tag
         FROM public.organizations`,
      );
      const org = orgRows[0]!;
      expect(org.id).toBe(ORG_A_ID);
      expect(org.name).toBe('Local Demo Organization');
      expect(org.monthly_budget_microdollars).toBe('0');
      expect(org.kek_version).toBe(1);
      expect(org.wrapped_dek).toHaveLength(33);
      expect(org.wrapped_dek[0]).toBe(1);
      expect(org.dek_iv).toHaveLength(12);
      expect(org.dek_auth_tag).toHaveLength(16);

      const { rows: userRows } = await admin.query<{
        id: string;
        org_id: string;
        email_normalized: string;
        role: string;
        password_hash: string;
      }>(
        `SELECT id, org_id, email_normalized, role, password_hash
         FROM public.users`,
      );
      const user = userRows[0]!;
      expect(user.org_id).toBe(ORG_A_ID);
      expect(user.email_normalized).toBe(ADMIN_A_EMAIL);
      expect(user.role).toBe('admin');
      expect(user.password_hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
      await expect(verifyPassword(user.password_hash, ADMIN_PASSWORD)).resolves.toBe(true);
      expect(seedResult.stdout).not.toContain(user.password_hash);
    });

    it('authenticates through the existing AuthenticationService with the seeded password', async () => {
      const redis = { eval: vi.fn().mockResolvedValue(1) } as unknown as Redis;
      const service = new AuthenticationService({
        pool: appPool!,
        rateLimiter: new LoginRateLimiter(redis),
      });

      const authenticated = await service.authenticate(ADMIN_A_EMAIL, ADMIN_PASSWORD, '127.0.0.1');
      expect(authenticated.orgId).toBe(ORG_A_ID);
      expect(authenticated.role).toBe('admin');
      expect(authenticated.emailNormalized).toBe(ADMIN_A_EMAIL);

      await expect(
        service.authenticate(ADMIN_A_EMAIL, OTHER_PASSWORD, '127.0.0.1'),
      ).rejects.toMatchObject({ reason: 'INVALID_CREDENTIALS' });
    });

    it('proves the persisted DEK envelope decrypts and resists wrong org, wrong KEK and tampering', async () => {
      const admin = handle!.admin;
      const envelope = await readEnvelope(admin, ORG_A_ID);
      const correct = keyring(seededKek);

      assertEnvelopeRoundTrip(correct, ORG_A_ID, envelope);
      expect(() => assertEnvelopeRoundTrip(correct, ORG_B_ID, envelope)).toThrow();
      expect(() => assertEnvelopeRoundTrip(keyring(newKek()), ORG_A_ID, envelope)).toThrow();

      const tampered: OrganizationDekEnvelope = {
        ...envelope,
        wrappedDek: Buffer.from(envelope.wrappedDek),
      };
      tampered.wrappedDek[1] = tampered.wrappedDek[1]! ^ 0xff;
      expect(() => assertEnvelopeRoundTrip(correct, ORG_A_ID, tampered)).toThrow();
    });

    it('enforces tenant RLS: no-context access and cross-tenant access return zero rows', async () => {
      const direct = await appPool!.query<{ id: string }>('SELECT id FROM public.users');
      expect(direct.rows).toHaveLength(0);

      const ownTenant = await withTenant(appPool!, ORG_A_ID, async (client) => {
        const result = await client.query<{ id: string; role: string }>(
          'SELECT id, role FROM public.users',
        );
        return result.rows;
      });
      expect(ownTenant).toHaveLength(1);
      expect(ownTenant[0]?.role).toBe('admin');

      const crossTenant = await withTenant(appPool!, ORG_B_ID, async (client) => {
        const result = await client.query<{ id: string }>('SELECT id FROM public.users');
        return result.rows;
      });
      expect(crossTenant).toHaveLength(0);
    });

    it('runs as the non-superuser, non-bypassing gateway_app role', async () => {
      const { rows } = await appPool!.query<{
        current_user: string;
        session_user: string;
        is_superuser: boolean;
        bypasses_rls: boolean;
      }>(
        `SELECT current_user::text AS current_user, session_user::text AS session_user,
                r.rolsuper AS is_superuser, r.rolbypassrls AS bypasses_rls
         FROM pg_catalog.pg_roles r WHERE r.rolname = current_user`,
      );
      expect(rows[0]).toEqual({
        current_user: 'gateway_app',
        session_user: 'gateway_app',
        is_superuser: false,
        bypasses_rls: false,
      });
    });
  });

  describe('idempotency: repeated invocation never mutates the demo identity', () => {
    let handle: DatabaseHandle | undefined;
    let seededKek: string;
    let env: Record<string, string | undefined>;
    let firstResult: { code: number; stdout: string; stderr: string };

    beforeAll(async () => {
      handle = await createMigratedDatabase(cluster, passwords, 'seed_dev_repeat');
      seededKek = newKek();
      env = seedEnv(handle.db, passwords, { kek: seededKek });
      firstResult = await runSeed(env, ADMIN_PASSWORD);
    }, 120_000);

    afterAll(async () => {
      await closeDatabase(handle);
    }, 60_000);

    it('returns ALREADY_PRESENT on a repeat without resetting password, role, budget or envelope', async () => {
      expect(firstResult.code).toBe(SEED_EXIT_SUCCESS);

      const admin = handle!.admin;
      const before = await admin.query<{
        org_name: string;
        budget: string;
        kek_version: number;
        wrapped_dek: Buffer;
        dek_iv: Buffer;
        dek_auth_tag: Buffer;
        user_id: string;
        role: string;
        password_hash: string;
      }>(
        `SELECT o.name AS org_name, o.monthly_budget_microdollars::text AS budget,
                o.kek_version, o.wrapped_dek, o.dek_iv, o.dek_auth_tag,
                u.id AS user_id, u.role, u.password_hash
         FROM public.organizations o JOIN public.users u ON u.org_id = o.id
         WHERE o.id = $1`,
        [ORG_A_ID],
      );
      expect(before.rows).toHaveLength(1);

      // Change the requested budget, organization name and password; identity must not mutate.
      const repeatEnv = seedEnv(handle!.db, passwords, {
        kek: seededKek,
        budget: '999999',
        orgName: 'Renamed Demo Organization',
      });
      const repeat = await runSeed(repeatEnv, OTHER_PASSWORD);

      expect(repeat.code).toBe(SEED_EXIT_SUCCESS);
      expect(repeat.stdout).toContain('Status: ALREADY_PRESENT');
      expect(await countRows(admin, 'organizations')).toBe(1);
      expect(await countRows(admin, 'users')).toBe(1);

      const after = await admin.query<{
        org_name: string;
        budget: string;
        kek_version: number;
        wrapped_dek: Buffer;
        dek_iv: Buffer;
        dek_auth_tag: Buffer;
        user_id: string;
        role: string;
        password_hash: string;
      }>(
        `SELECT o.name AS org_name, o.monthly_budget_microdollars::text AS budget,
                o.kek_version, o.wrapped_dek, o.dek_iv, o.dek_auth_tag,
                u.id AS user_id, u.role, u.password_hash
         FROM public.organizations o JOIN public.users u ON u.org_id = o.id
         WHERE o.id = $1`,
        [ORG_A_ID],
      );

      const beforeRow = before.rows[0]!;
      const afterRow = after.rows[0]!;
      expect(afterRow.org_name).toBe(beforeRow.org_name);
      expect(afterRow.budget).toBe(beforeRow.budget);
      expect(afterRow.kek_version).toBe(beforeRow.kek_version);
      expect(afterRow.wrapped_dek.equals(beforeRow.wrapped_dek)).toBe(true);
      expect(afterRow.dek_iv.equals(beforeRow.dek_iv)).toBe(true);
      expect(afterRow.dek_auth_tag.equals(beforeRow.dek_auth_tag)).toBe(true);
      expect(afterRow.user_id).toBe(beforeRow.user_id);
      expect(afterRow.role).toBe('admin');
      expect(afterRow.password_hash).toBe(beforeRow.password_hash);

      // The original password still works and the replacement password was never applied.
      await expect(verifyPassword(afterRow.password_hash, ADMIN_PASSWORD)).resolves.toBe(true);
      await expect(verifyPassword(afterRow.password_hash, OTHER_PASSWORD)).resolves.toBe(false);

      const envelope = await readEnvelope(admin, ORG_A_ID);
      assertEnvelopeRoundTrip(keyring(seededKek), ORG_A_ID, envelope);
    });

    it('rejects a valid but incompatible KEK on repeat without mutating persisted records', async () => {
      const admin = handle!.admin;
      const before = await admin.query<{
        wrapped_dek: Buffer;
        dek_iv: Buffer;
        dek_auth_tag: Buffer;
        password_hash: string;
      }>(
        `SELECT o.wrapped_dek, o.dek_iv, o.dek_auth_tag, u.password_hash
         FROM public.organizations o JOIN public.users u ON u.org_id = o.id
         WHERE o.id = $1`,
        [ORG_A_ID],
      );
      expect(before.rows).toHaveLength(1);

      const incompatible = seedEnv(handle!.db, passwords, { kek: newKek() });
      const result = await runSeed(incompatible, OTHER_PASSWORD);
      expect(result.code).toBe(SEED_EXIT_FAILURE);
      expect(result.stdout).toBe('');
      expect(result.stderr).toContain('EXISTING_ENVELOPE_INVALID');

      const after = await admin.query<{
        wrapped_dek: Buffer;
        dek_iv: Buffer;
        dek_auth_tag: Buffer;
        password_hash: string;
      }>(
        `SELECT o.wrapped_dek, o.dek_iv, o.dek_auth_tag, u.password_hash
         FROM public.organizations o JOIN public.users u ON u.org_id = o.id
         WHERE o.id = $1`,
        [ORG_A_ID],
      );
      expect(await countRows(admin, 'organizations')).toBe(1);
      expect(await countRows(admin, 'users')).toBe(1);
      expect(after.rows[0]?.wrapped_dek.equals(before.rows[0]!.wrapped_dek)).toBe(true);
      expect(after.rows[0]?.dek_iv.equals(before.rows[0]!.dek_iv)).toBe(true);
      expect(after.rows[0]?.dek_auth_tag.equals(before.rows[0]!.dek_auth_tag)).toBe(true);
      expect(after.rows[0]?.password_hash).toBe(before.rows[0]?.password_hash);
      assertEnvelopeRoundTrip(keyring(seededKek), ORG_A_ID, await readEnvelope(admin, ORG_A_ID));
    });

    it('fails closed on tampered existing envelope and leaves the original account intact', async () => {
      const admin = handle!.admin;
      const original = await readEnvelope(admin, ORG_A_ID);
      const tampered = Buffer.from(original.dekAuthTag);
      tampered[0] = tampered[0]! ^ 0xff;
      await admin.query('UPDATE public.organizations SET dek_auth_tag = $1 WHERE id = $2', [
        tampered,
        ORG_A_ID,
      ]);
      try {
        const result = await runSeed(env, OTHER_PASSWORD);
        expect(result.code).toBe(SEED_EXIT_FAILURE);
        expect(result.stdout).toBe('');
        expect(result.stderr).toContain('EXISTING_ENVELOPE_INVALID');
        expect(await countRows(admin, 'organizations')).toBe(1);
        expect(await countRows(admin, 'users')).toBe(1);
      } finally {
        await admin.query('UPDATE public.organizations SET dek_auth_tag = $1 WHERE id = $2', [
          original.dekAuthTag,
          ORG_A_ID,
        ]);
      }
      assertEnvelopeRoundTrip(keyring(seededKek), ORG_A_ID, await readEnvelope(admin, ORG_A_ID));
    });
  });

  describe('concurrent seeding preserves exactly-one semantics', () => {
    let handle: DatabaseHandle | undefined;
    let env: Record<string, string | undefined>;

    beforeAll(async () => {
      handle = await createMigratedDatabase(cluster, passwords, 'seed_dev_concurrent');
      env = seedEnv(handle.db, passwords, { kek: newKek() });
    }, 120_000);

    afterAll(async () => {
      await closeDatabase(handle);
    }, 60_000);

    it('runs two seeders concurrently and persists exactly one organization and admin', async () => {
      const [first, second] = await Promise.all([
        runSeed(env, ADMIN_PASSWORD),
        runSeed(env, ADMIN_PASSWORD),
      ]);

      expect(first.code).toBe(SEED_EXIT_SUCCESS);
      expect(second.code).toBe(SEED_EXIT_SUCCESS);

      const statuses = [first.stdout, second.stdout]
        .map((output) => (output.includes('Status: CREATED') ? 'CREATED' : 'ALREADY_PRESENT'))
        .sort();
      expect(statuses).toEqual(['ALREADY_PRESENT', 'CREATED']);

      const admin = handle!.admin;
      expect(await countRows(admin, 'organizations')).toBe(1);
      expect(await countRows(admin, 'users')).toBe(1);

      const { rows } = await admin.query<{ org_id: string; role: string }>(
        'SELECT org_id, role FROM public.users',
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]?.org_id).toBe(ORG_A_ID);
      expect(rows[0]?.role).toBe('admin');
    });
  });

  describe('conflicts and failure atomicity', () => {
    let handle: DatabaseHandle | undefined;

    beforeAll(async () => {
      handle = await createMigratedDatabase(cluster, passwords, 'seed_dev_conflict');
    }, 120_000);

    afterAll(async () => {
      await closeDatabase(handle);
    }, 60_000);

    it('reports CONFLICT for an email already owned by another organization', async () => {
      const seeded = await runSeed(
        seedEnv(handle!.db, passwords, { kek: newKek(), orgId: ORG_A_ID }),
        ADMIN_PASSWORD,
      );
      expect(seeded.code).toBe(SEED_EXIT_SUCCESS);

      const conflict = await runSeed(
        seedEnv(handle!.db, passwords, {
          kek: newKek(),
          orgId: ORG_B_ID,
          orgName: 'Conflicting Organization',
          adminEmail: ADMIN_A_EMAIL,
        }),
        OTHER_PASSWORD,
      );

      expect(conflict.code).toBe(SEED_EXIT_CONFLICT);
      expect(conflict.stdout).toContain('Status: CONFLICT');
      expect(await countRows(handle!.admin, 'organizations')).toBe(1);
      expect(await countRows(handle!.admin, 'users')).toBe(1);
    });

    it('reports CONFLICT for a duplicate organization ID without creating an orphan user', async () => {
      const conflict = await runSeed(
        seedEnv(handle!.db, passwords, {
          kek: newKek(),
          orgId: ORG_A_ID,
          adminEmail: ADMIN_B_EMAIL,
        }),
        OTHER_PASSWORD,
      );

      expect(conflict.code).toBe(SEED_EXIT_CONFLICT);
      const { rows } = await handle!.admin.query<{ count: string }>(
        'SELECT count(*)::text AS count FROM public.users WHERE email_normalized = $1',
        [ADMIN_B_EMAIL],
      );
      expect(rows[0]?.count).toBe('0');
      expect(await countRows(handle!.admin, 'organizations')).toBe(1);
      expect(await countRows(handle!.admin, 'users')).toBe(1);
    });

    it('reports CONFLICT for an existing member identity instead of promoting it', async () => {
      // Test fixture: create a member account in an unrelated organization as the privileged
      // observer. The seeder must not promote or adopt it.
      const memberEmail = 'existing-member@example.test';
      const memberPasswordHash = await hashPassword(OTHER_PASSWORD);
      await handle!.admin.query(
        `INSERT INTO public.organizations
           (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
         VALUES ($1, 'Member Org', 0, 1, $2, $3, $4)`,
        [
          ORG_B_ID,
          Buffer.from([1, ...crypto.randomBytes(32)]),
          crypto.randomBytes(12),
          crypto.randomBytes(16),
        ],
      );
      await handle!.admin.query(
        `INSERT INTO public.users (id, org_id, email_normalized, password_hash, role)
         VALUES ($1, $2, $3, $4, 'member')`,
        [crypto.randomUUID(), ORG_B_ID, memberEmail, memberPasswordHash],
      );

      const conflict = await runSeed(
        seedEnv(handle!.db, passwords, {
          kek: newKek(),
          orgId: ORG_A_ID,
          adminEmail: memberEmail,
        }),
        OTHER_PASSWORD,
      );

      expect(conflict.code).toBe(SEED_EXIT_CONFLICT);
      const { rows } = await handle!.admin.query<{ role: string }>(
        'SELECT role FROM public.users WHERE email_normalized = $1',
        [memberEmail],
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]?.role).toBe('member');
    });
  });

  describe('invalid input leaves zero orphan records', () => {
    let handle: DatabaseHandle | undefined;

    beforeAll(async () => {
      handle = await createMigratedDatabase(cluster, passwords, 'seed_dev_invalid');
    }, 120_000);

    afterAll(async () => {
      await closeDatabase(handle);
    }, 60_000);

    it('rejects invalid configuration or password before any database mutation', async () => {
      const cases: Array<{
        env: Record<string, string | undefined>;
        password: string;
        expectedCode: number;
      }> = [
        {
          env: seedEnv(handle!.db, passwords, { adminEmail: 'Not-Canonical@Example.test' }),
          password: ADMIN_PASSWORD,
          expectedCode: SEED_EXIT_INVALID_CONFIGURATION,
        },
        {
          env: seedEnv(handle!.db, passwords, { orgName: '   ' }),
          password: ADMIN_PASSWORD,
          expectedCode: SEED_EXIT_INVALID_CONFIGURATION,
        },
        {
          env: seedEnv(handle!.db, passwords, { budget: '-1' }),
          password: ADMIN_PASSWORD,
          expectedCode: SEED_EXIT_INVALID_CONFIGURATION,
        },
        {
          env: seedEnv(handle!.db, passwords, { kek: 'not-a-kek' }),
          password: ADMIN_PASSWORD,
          expectedCode: SEED_EXIT_INVALID_CONFIGURATION,
        },
        {
          env: seedEnv(handle!.db, passwords, { orgId: 'not-a-uuid' }),
          password: ADMIN_PASSWORD,
          expectedCode: SEED_EXIT_INVALID_CONFIGURATION,
        },
        {
          env: seedEnv(handle!.db, passwords),
          password: 'a'.repeat(129),
          expectedCode: SEED_EXIT_INVALID_CONFIGURATION,
        },
        {
          env: seedEnv(handle!.db, passwords),
          password: '',
          expectedCode: SEED_EXIT_INVALID_CONFIGURATION,
        },
      ];

      for (const testCase of cases) {
        const result = await runSeed(testCase.env, testCase.password);
        expect(result.code).toBe(testCase.expectedCode);
      }

      expect(await countRows(handle!.admin, 'organizations')).toBe(0);
      expect(await countRows(handle!.admin, 'users')).toBe(0);
    });

    it('rejects a non-runtime database identity before connecting', async () => {
      const env = seedEnv(handle!.db, passwords);
      env.POSTGRES_USER = 'gateway_migrator';
      const result = await runSeed(env, ADMIN_PASSWORD);

      expect(result.code).toBe(SEED_EXIT_INVALID_CONFIGURATION);
      expect(await countRows(handle!.admin, 'organizations')).toBe(0);
      expect(await countRows(handle!.admin, 'users')).toBe(0);
    });

    it('reports a controlled failure for an unreachable database without leaking secrets', async () => {
      const env = seedEnv(handle!.db, passwords);
      env.POSTGRES_PORT = '1';
      const passwordCanary = 'CANARY_DB_PASSWORD_4a1';
      const kekCanary = newKek();
      env.POSTGRES_PASSWORD = passwords.gateway_app;
      env.MASTER_KEK_V1 = kekCanary;

      const result = await runSeed(env, passwordCanary);

      expect(result.code).toBe(SEED_EXIT_FAILURE);
      expect(result.stdout).toBe('');
      expect(result.stderr).not.toContain(passwordCanary);
      expect(result.stderr).not.toContain(passwords.gateway_app);
      expect(result.stderr).not.toContain(kekCanary);
    });
  });
});
