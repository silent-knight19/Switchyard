import crypto from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuthenticationService } from '../auth/service.js';
import type { LoginRateLimiter } from '../auth/rate-limiter.js';
import { runMigrations } from '../db/migrate.js';
import { withTenant } from '../db/tenant.js';
import {
  bootstrapDatabase,
  createDisposableDatabase,
  createRolePasswords,
  roleConnectionString,
  startDisposableCluster,
  type DisposableCluster,
  type DisposableDatabase,
} from '../db/test/disposable-pg.js';
import {
  AES_GCM_IV_BYTES,
  AES_GCM_TAG_BYTES,
  EnvelopeVault,
  ENVELOPE_FORMAT_VERSION,
  type OrganizationDekEnvelope,
  type ProviderCredentialEnvelope,
} from './envelope.js';
import { VaultError } from './errors.js';
import { KekKeyring } from './kek.js';

const ORG_A = '11111111-1111-4111-8111-111111111111';
const ORG_B = '22222222-2222-4222-8222-222222222222';
const ORG_LEGACY = '33333333-3333-4333-8333-333333333333';
const PROVIDER_KEY_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const PROVIDER_KEY_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PROVIDER_KEY_C = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

const ADMIN_PASSWORD = 'Synthetic-Admin-Password-2026!';
const CANARY = Buffer.from('sk-synthetic-db-canary-provider-credential-42f1', 'utf8');
const CANARY_B = Buffer.from('sk-synthetic-db-canary-provider-credential-b7c2', 'utf8');

function fakeRateLimiter(): LoginRateLimiter {
  return {
    assertNotRateLimited: async () => undefined,
  } as unknown as LoginRateLimiter;
}

function captureError(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => null,
    (error: unknown) => error,
  );
}

function errorCode(error: unknown): unknown {
  return typeof error === 'object' && error !== null
    ? (error as { code?: unknown }).code
    : undefined;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function expectSqlState(promise: Promise<unknown>, sqlState: string): Promise<unknown> {
  const error = await captureError(promise);
  expect(
    errorCode(error),
    `expected SQLSTATE ${sqlState}, got ${String(errorCode(error))}: ${errorMessage(error)}`,
  ).toBe(sqlState);
  return error;
}

function expectVaultReason(error: unknown, reason: VaultError['reason']): void {
  expect(error).toBeInstanceOf(VaultError);
  expect((error as VaultError).reason).toBe(reason);
}

function independentUnwrapDek(
  orgId: string,
  envelope: OrganizationDekEnvelope,
  kek: Buffer,
): Buffer {
  const decipher = crypto.createDecipheriv('aes-256-gcm', kek, envelope.dekIv, {
    authTagLength: AES_GCM_TAG_BYTES,
  });
  decipher.setAAD(Buffer.from(`dek:${orgId}:v${envelope.kekVersion}`, 'utf8'));
  decipher.setAuthTag(envelope.dekAuthTag);
  return Buffer.concat([decipher.update(envelope.wrappedDek.subarray(1)), decipher.final()]);
}

function independentEncryptProvider(
  dek: Buffer,
  orgId: string,
  providerKeyId: string,
  provider: string,
  plaintext: Buffer,
): ProviderCredentialEnvelope {
  const iv = crypto.randomBytes(AES_GCM_IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv, {
    authTagLength: AES_GCM_TAG_BYTES,
  });
  cipher.setAAD(Buffer.from(`pk:${orgId}:${providerKeyId}:${provider}`, 'utf8'));
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    ciphertext: Buffer.concat([Buffer.from([ENVELOPE_FORMAT_VERSION]), encrypted]),
    iv,
    authTag: cipher.getAuthTag(),
  };
}

describe('SW-1.7.1/SW-1.7.2 envelope vault PostgreSQL 16 integration', () => {
  let cluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();

  let adminClient: pg.Client;
  let appPool: pg.Pool;
  let workerClient: pg.Client;
  let isolationPool: pg.Pool;
  let brokenPool: pg.Pool;

  const KEK_V1 = crypto.randomBytes(32);
  const KEK_V2 = crypto.randomBytes(32);

  let vaultV1: EnvelopeVault;
  let vaultBothActiveV2: EnvelopeVault;
  let vaultV2Only: EnvelopeVault;
  let authService: AuthenticationService;

  let orgAEnvelope: OrganizationDekEnvelope;
  let orgBEnvelope: OrganizationDekEnvelope;

  async function loadOrgEnvelope(pool: pg.Pool, orgId: string): Promise<OrganizationDekEnvelope> {
    return withTenant(pool, orgId, async (client) => {
      const { rows } = await client.query<{
        kek_version: number;
        wrapped_dek: Buffer;
        dek_iv: Buffer;
        dek_auth_tag: Buffer;
      }>('SELECT kek_version, wrapped_dek, dek_iv, dek_auth_tag FROM organizations WHERE id = $1', [
        orgId,
      ]);
      const row = rows[0];
      if (!row) {
        throw new Error('Organization envelope not found');
      }
      return {
        kekVersion: row.kek_version,
        wrappedDek: row.wrapped_dek,
        dekIv: row.dek_iv,
        dekAuthTag: row.dek_auth_tag,
      };
    });
  }

  async function loadProviderEnvelope(
    pool: pg.Pool,
    orgId: string,
    providerKeyId: string,
  ): Promise<ProviderCredentialEnvelope> {
    return withTenant(pool, orgId, async (client) => {
      const { rows } = await client.query<{
        ciphertext: Buffer;
        iv: Buffer;
        auth_tag: Buffer;
      }>('SELECT ciphertext, iv, auth_tag FROM provider_keys WHERE id = $1', [providerKeyId]);
      const row = rows[0];
      if (!row) {
        throw new Error('Provider credential envelope not found');
      }
      return { ciphertext: row.ciphertext, iv: row.iv, authTag: row.auth_tag };
    });
  }

  async function persistProviderCredential(
    orgId: string,
    providerKeyId: string,
    plaintext: Buffer,
    vault: EnvelopeVault = vaultBothActiveV2,
  ): Promise<ProviderCredentialEnvelope> {
    const organizationEnvelope = await loadOrgEnvelope(appPool, orgId);
    const encrypted = vault.encryptProviderCredential({
      orgId,
      providerKeyId,
      provider: 'openai',
      plaintext,
      organizationEnvelope,
    });

    await withTenant(appPool, orgId, async (client) => {
      await client.query(
        `INSERT INTO provider_keys (
           id, org_id, provider, label, key_hint, ciphertext, iv, auth_tag, is_active
         ) VALUES ($1, $2, 'openai', 'Synthetic test credential', 'test', $3, $4, $5, TRUE)
         ON CONFLICT (id) DO UPDATE SET
           ciphertext = EXCLUDED.ciphertext,
           iv = EXCLUDED.iv,
           auth_tag = EXCLUDED.auth_tag,
           is_active = EXCLUDED.is_active`,
        [providerKeyId, orgId, encrypted.ciphertext, encrypted.iv, encrypted.authTag],
      );
    });

    return encrypted;
  }

  async function bootstrapOrg(
    orgId: string,
    orgName: string,
    adminEmail: string,
    envelope: OrganizationDekEnvelope,
  ): Promise<void> {
    await authService.bootstrapOrganizationWithAdmin({
      orgId,
      orgName,
      monthlyBudgetMicrodollars: 1_000_000n,
      kekVersion: envelope.kekVersion,
      wrappedDek: envelope.wrappedDek,
      dekIv: envelope.dekIv,
      dekAuthTag: envelope.dekAuthTag,
      adminUserId: crypto.randomUUID(),
      adminEmail,
      adminPassword: ADMIN_PASSWORD,
    });
  }

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    db = await createDisposableDatabase(cluster, 'envelope_vault');
    await bootstrapDatabase(db, passwords);

    const migrator = new pg.Pool({
      connectionString: roleConnectionString(
        db.url,
        'gateway_migrator',
        passwords.gateway_migrator,
      ),
    });
    try {
      await runMigrations(migrator);
    } finally {
      await migrator.end();
    }

    adminClient = new pg.Client({ connectionString: db.url });
    await adminClient.connect();

    appPool = new pg.Pool({
      connectionString: roleConnectionString(db.url, 'gateway_app', passwords.gateway_app),
      max: 4,
    });
    workerClient = new pg.Client({
      connectionString: roleConnectionString(db.url, 'gateway_worker', passwords.gateway_worker),
    });
    await workerClient.connect();
    isolationPool = new pg.Pool({
      connectionString: roleConnectionString(db.url, 'gateway_app', passwords.gateway_app),
      max: 1,
    });
    brokenPool = new pg.Pool({
      connectionString: roleConnectionString(db.url, 'gateway_app', passwords.gateway_app),
      max: 1,
    });

    vaultV1 = new EnvelopeVault(new KekKeyring({ activeVersion: 1, keys: { 1: KEK_V1 } }));
    vaultBothActiveV2 = new EnvelopeVault(
      new KekKeyring({ activeVersion: 2, keys: { 1: KEK_V1, 2: KEK_V2 } }),
    );
    vaultV2Only = new EnvelopeVault(new KekKeyring({ activeVersion: 2, keys: { 2: KEK_V2 } }));

    authService = new AuthenticationService({
      pool: appPool,
      rateLimiter: fakeRateLimiter(),
    });

    orgAEnvelope = vaultV1.createOrganizationEnvelope(ORG_A);
    orgBEnvelope = vaultV1.createOrganizationEnvelope(ORG_B);
    await bootstrapOrg(ORG_A, 'Org Alpha', 'admin@alpha.example.test', orgAEnvelope);
    await bootstrapOrg(ORG_B, 'Org Beta', 'admin@beta.example.test', orgBEnvelope);
  }, 240_000);

  afterAll(async () => {
    await isolationPool?.end().catch(() => undefined);
    await brokenPool?.end().catch(() => undefined);
    await appPool?.end().catch(() => undefined);
    await workerClient?.end().catch(() => undefined);
    await adminClient?.end().catch(() => undefined);
    await db?.drop().catch(() => undefined);
    await cluster?.stop();
  }, 60_000);

  it('DB-01 persists the organization envelope through the accepted bootstrap path', async () => {
    const { rows } = await adminClient.query<{
      kek_version: number;
      wrapped_dek: Buffer;
      dek_iv: Buffer;
      dek_auth_tag: Buffer;
    }>('SELECT kek_version, wrapped_dek, dek_iv, dek_auth_tag FROM organizations WHERE id = $1', [
      ORG_A,
    ]);
    const row = rows[0];
    expect(row).toBeDefined();
    expect(row?.kek_version).toBe(1);
    expect(Buffer.from(row?.wrapped_dek as Buffer).equals(orgAEnvelope.wrappedDek)).toBe(true);
    expect(Buffer.from(row?.dek_iv as Buffer).equals(orgAEnvelope.dekIv)).toBe(true);
    expect(Buffer.from(row?.dek_auth_tag as Buffer).equals(orgAEnvelope.dekAuthTag)).toBe(true);
    expect(row?.wrapped_dek).toHaveLength(33);
  });

  it('DB-02 loads the organization envelope under tenant context and authenticates the DEK', async () => {
    const loaded = await loadOrgEnvelope(appPool, ORG_A);
    const providerEnvelope = vaultBothActiveV2.encryptProviderCredential({
      orgId: ORG_A,
      providerKeyId: PROVIDER_KEY_A,
      provider: 'openai',
      plaintext: CANARY,
      organizationEnvelope: loaded,
    });
    const plaintext = vaultBothActiveV2.decryptProviderCredential({
      orgId: ORG_A,
      providerKeyId: PROVIDER_KEY_A,
      provider: 'openai',
      providerEnvelope,
      organizationEnvelope: loaded,
    });
    expect(plaintext.equals(CANARY)).toBe(true);
    plaintext.fill(0);
  });

  it('DB-03 persists provider ciphertext, IV and tag with gateway_app under withTenant', async () => {
    const stored = await persistProviderCredential(ORG_A, PROVIDER_KEY_A, CANARY);
    const { rows } = await adminClient.query<{
      ciphertext: Buffer;
      iv: Buffer;
      auth_tag: Buffer;
    }>('SELECT ciphertext, iv, auth_tag FROM provider_keys WHERE id = $1', [PROVIDER_KEY_A]);
    const row = rows[0];
    expect(row).toBeDefined();
    expect(Buffer.from(row?.ciphertext as Buffer).equals(stored.ciphertext)).toBe(true);
    expect(Buffer.from(row?.iv as Buffer).equals(stored.iv)).toBe(true);
    expect(Buffer.from(row?.auth_tag as Buffer).equals(stored.authTag)).toBe(true);
    expect(row?.ciphertext[0]).toBe(ENVELOPE_FORMAT_VERSION);
  });

  it('DB-04 decrypts the persisted provider credential with exact byte equality', async () => {
    await persistProviderCredential(ORG_A, PROVIDER_KEY_A, CANARY);
    const organizationEnvelope = await loadOrgEnvelope(appPool, ORG_A);
    const providerEnvelope = await loadProviderEnvelope(appPool, ORG_A, PROVIDER_KEY_A);
    const plaintext = vaultBothActiveV2.decryptProviderCredential({
      orgId: ORG_A,
      providerKeyId: PROVIDER_KEY_A,
      provider: 'openai',
      providerEnvelope,
      organizationEnvelope,
    });
    expect(plaintext.equals(CANARY)).toBe(true);
    plaintext.fill(0);
  });

  it('DB-05 stores neither plaintext provider credentials nor plaintext DEKs', async () => {
    await persistProviderCredential(ORG_A, PROVIDER_KEY_A, CANARY);
    const organizationEnvelope = await loadOrgEnvelope(appPool, ORG_A);
    const providerEnvelope = await loadProviderEnvelope(appPool, ORG_A, PROVIDER_KEY_A);
    const dek = independentUnwrapDek(ORG_A, organizationEnvelope, KEK_V1);

    const { rows: orgRows } = await adminClient.query<{
      wrapped_dek: Buffer;
      dek_iv: Buffer;
      dek_auth_tag: Buffer;
    }>('SELECT wrapped_dek, dek_iv, dek_auth_tag FROM organizations WHERE id = $1', [ORG_A]);
    const orgRow = orgRows[0];
    expect(orgRow).toBeDefined();
    for (const value of [orgRow?.wrapped_dek, orgRow?.dek_iv, orgRow?.dek_auth_tag]) {
      expect(Buffer.from(value as Buffer).includes(CANARY)).toBe(false);
      expect(Buffer.from(value as Buffer).includes(dek)).toBe(false);
    }

    for (const value of [
      providerEnvelope.ciphertext,
      providerEnvelope.iv,
      providerEnvelope.authTag,
    ]) {
      expect(value.includes(CANARY)).toBe(false);
      expect(value.includes(dek)).toBe(false);
    }
    expect(JSON.stringify(providerEnvelope)).not.toContain(CANARY.toString('utf8'));
    dek.fill(0);
  });

  it('DB-06 denies cross-tenant reads of organization envelopes and provider credentials', async () => {
    const orgBEnvelopeLoaded = await loadOrgEnvelope(appPool, ORG_B);
    await persistProviderCredential(ORG_B, PROVIDER_KEY_B, CANARY_B, vaultBothActiveV2);
    expect(orgBEnvelopeLoaded.wrappedDek).toHaveLength(33);

    const orgRows = await withTenant(appPool, ORG_A, async (client) => {
      return (await client.query('SELECT id FROM organizations WHERE id = $1', [ORG_B])).rows;
    });
    expect(orgRows).toEqual([]);

    const providerRows = await withTenant(appPool, ORG_A, async (client) => {
      return (await client.query('SELECT id FROM provider_keys WHERE org_id = $1', [ORG_B])).rows;
    });
    expect(providerRows).toEqual([]);

    const providerById = await withTenant(appPool, ORG_A, async (client) => {
      return (await client.query('SELECT id FROM provider_keys WHERE id = $1', [PROVIDER_KEY_B]))
        .rows;
    });
    expect(providerById).toEqual([]);
  });

  it('DB-07 rejects cross-record encrypted material substitution', async () => {
    await persistProviderCredential(ORG_A, PROVIDER_KEY_A, CANARY);
    await persistProviderCredential(ORG_A, PROVIDER_KEY_C, CANARY_B);
    const organizationEnvelope = await loadOrgEnvelope(appPool, ORG_A);
    const ciphertextA = await loadProviderEnvelope(appPool, ORG_A, PROVIDER_KEY_A);
    const ciphertextC = await loadProviderEnvelope(appPool, ORG_A, PROVIDER_KEY_C);

    expect(() =>
      vaultBothActiveV2.decryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: PROVIDER_KEY_C,
        provider: 'openai',
        providerEnvelope: ciphertextA,
        organizationEnvelope,
      }),
    ).toThrowError(VaultError);

    expect(() =>
      vaultBothActiveV2.decryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: PROVIDER_KEY_A,
        provider: 'openai',
        providerEnvelope: ciphertextC,
        organizationEnvelope,
      }),
    ).toThrowError(VaultError);
  });

  it('DB-08 rejects cross-organization DEK substitution', async () => {
    await persistProviderCredential(ORG_A, PROVIDER_KEY_A, CANARY);
    const organizationEnvelopeA = await loadOrgEnvelope(appPool, ORG_A);
    const organizationEnvelopeB = await loadOrgEnvelope(appPool, ORG_B);
    const ciphertextA = await loadProviderEnvelope(appPool, ORG_A, PROVIDER_KEY_A);

    let error: unknown;
    try {
      vaultBothActiveV2.decryptProviderCredential({
        orgId: ORG_B,
        providerKeyId: PROVIDER_KEY_A,
        provider: 'openai',
        providerEnvelope: ciphertextA,
        organizationEnvelope: organizationEnvelopeB,
      });
    } catch (caught) {
      error = caught;
    }
    expectVaultReason(error, 'AUTHENTICATION_FAILED');
    expect(organizationEnvelopeA.wrappedDek.equals(organizationEnvelopeB.wrappedDek)).toBe(false);
  });

  it('DB-09 rejects altered provider identity metadata', async () => {
    const organizationEnvelope = await loadOrgEnvelope(appPool, ORG_A);
    const dek = independentUnwrapDek(ORG_A, organizationEnvelope, KEK_V1);
    const anthropicBound = independentEncryptProvider(
      dek,
      ORG_A,
      PROVIDER_KEY_A,
      'anthropic',
      CANARY,
    );
    dek.fill(0);

    let error: unknown;
    try {
      vaultBothActiveV2.decryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: PROVIDER_KEY_A,
        provider: 'openai',
        providerEnvelope: anthropicBound,
        organizationEnvelope,
      });
    } catch (caught) {
      error = caught;
    }
    expectVaultReason(error, 'AUTHENTICATION_FAILED');

    expect(() =>
      vaultBothActiveV2.decryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: PROVIDER_KEY_A,
        provider: 'anthropic',
        providerEnvelope: anthropicBound,
        organizationEnvelope,
      }),
    ).toThrowError(VaultError);
  });

  it('DB-10 rejects tampering with ciphertext, IV or authentication tag', async () => {
    await persistProviderCredential(ORG_A, PROVIDER_KEY_A, CANARY);
    const organizationEnvelope = await loadOrgEnvelope(appPool, ORG_A);
    const providerEnvelope = await loadProviderEnvelope(appPool, ORG_A, PROVIDER_KEY_A);

    const tamperedCiphertext = {
      ciphertext: Buffer.from(providerEnvelope.ciphertext),
      iv: Buffer.from(providerEnvelope.iv),
      authTag: Buffer.from(providerEnvelope.authTag),
    };
    tamperedCiphertext.ciphertext[1] = (tamperedCiphertext.ciphertext[1] as number) ^ 0xff;

    const tamperedIv = {
      ciphertext: Buffer.from(providerEnvelope.ciphertext),
      iv: Buffer.from(providerEnvelope.iv),
      authTag: Buffer.from(providerEnvelope.authTag),
    };
    tamperedIv.iv[0] = (tamperedIv.iv[0] as number) ^ 0xff;

    const tamperedTag = {
      ciphertext: Buffer.from(providerEnvelope.ciphertext),
      iv: Buffer.from(providerEnvelope.iv),
      authTag: Buffer.from(providerEnvelope.authTag),
    };
    tamperedTag.authTag[0] = (tamperedTag.authTag[0] as number) ^ 0xff;

    for (const envelope of [tamperedCiphertext, tamperedIv, tamperedTag]) {
      let error: unknown;
      try {
        vaultBothActiveV2.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: PROVIDER_KEY_A,
          provider: 'openai',
          providerEnvelope: envelope,
          organizationEnvelope,
        });
      } catch (caught) {
        error = caught;
      }
      expectVaultReason(error, 'AUTHENTICATION_FAILED');
    }
  });

  it('DB-11 denies gateway_worker reads of secret-bearing columns', async () => {
    await expectSqlState(workerClient.query('SELECT wrapped_dek FROM organizations'), '42501');
    await expectSqlState(workerClient.query('SELECT dek_iv FROM organizations'), '42501');
    await expectSqlState(workerClient.query('SELECT dek_auth_tag FROM organizations'), '42501');
    await expectSqlState(workerClient.query('SELECT ciphertext FROM provider_keys'), '42501');
    await expectSqlState(workerClient.query('SELECT iv FROM provider_keys'), '42501');
    await expectSqlState(workerClient.query('SELECT auth_tag FROM provider_keys'), '42501');
  });

  it('DB-12 preserves gateway_worker access to non-secret metadata only', async () => {
    await persistProviderCredential(ORG_A, PROVIDER_KEY_A, CANARY);
    await workerClient.query('BEGIN');
    try {
      await workerClient.query("SELECT pg_catalog.set_config('app.current_org_id', $1, true)", [
        ORG_A,
      ]);
      const orgRows = await workerClient.query<{
        id: string;
        name: string;
        monthly_budget_microdollars: string;
        kek_version: number;
        created_at: Date;
      }>(
        `SELECT id, name, monthly_budget_microdollars, kek_version, created_at
         FROM organizations WHERE id = $1`,
        [ORG_A],
      );
      expect(orgRows.rows).toHaveLength(1);
      expect(orgRows.rows[0]?.name).toBe('Org Alpha');

      const providerRows = await workerClient.query<{
        id: string;
        org_id: string;
        provider: string;
        label: string;
        key_hint: string;
        is_active: boolean;
        created_at: Date;
      }>(
        `SELECT id, org_id, provider, label, key_hint, is_active, created_at
         FROM provider_keys WHERE id = $1`,
        [PROVIDER_KEY_A],
      );
      expect(providerRows.rows).toHaveLength(1);
      expect(providerRows.rows[0]?.provider).toBe('openai');
    } finally {
      await workerClient.query('ROLLBACK');
    }
  });

  it('DB-13 fails closed when the historical KEK is missing', async () => {
    const organizationEnvelope = await loadOrgEnvelope(appPool, ORG_A);
    expect(organizationEnvelope.kekVersion).toBe(1);

    let error: unknown;
    try {
      vaultV2Only.encryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: PROVIDER_KEY_A,
        provider: 'openai',
        plaintext: CANARY,
        organizationEnvelope,
      });
    } catch (caught) {
      error = caught;
    }
    expectVaultReason(error, 'UNKNOWN_KEK_VERSION');

    await persistProviderCredential(ORG_A, PROVIDER_KEY_A, CANARY);
    const providerEnvelope = await loadProviderEnvelope(appPool, ORG_A, PROVIDER_KEY_A);
    let decryptError: unknown;
    try {
      vaultV2Only.decryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: PROVIDER_KEY_A,
        provider: 'openai',
        providerEnvelope,
        organizationEnvelope,
      });
    } catch (caught) {
      decryptError = caught;
    }
    expectVaultReason(decryptError, 'UNKNOWN_KEK_VERSION');
  });

  it('DB-14 rejects malformed legacy dummy envelopes instead of treating them as encryption', async () => {
    await adminClient.query(
      `INSERT INTO organizations (
         id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag
       ) VALUES ($1, 'Legacy Org', 1000000, 1, $2, $3, $4)`,
      [
        ORG_LEGACY,
        Buffer.from([ENVELOPE_FORMAT_VERSION, 0x02]),
        Buffer.from([0x03, 0x04]),
        Buffer.from([0x05, 0x06]),
      ],
    );

    const legacyEnvelope = await loadOrgEnvelope(appPool, ORG_LEGACY);
    let error: unknown;
    try {
      vaultBothActiveV2.encryptProviderCredential({
        orgId: ORG_LEGACY,
        providerKeyId: PROVIDER_KEY_A,
        provider: 'openai',
        plaintext: CANARY,
        organizationEnvelope: legacyEnvelope,
      });
    } catch (caught) {
      error = caught;
    }
    expectVaultReason(error, 'UNSUPPORTED_FORMAT');
  });

  it('DB-15 fails closed on a controlled PostgreSQL read outage without plaintext fallback', async () => {
    await persistProviderCredential(ORG_A, PROVIDER_KEY_A, CANARY);
    await brokenPool.end();
    const error = await captureError(loadOrgEnvelope(brokenPool, ORG_A));
    expect(error).not.toBeNull();
    expect(error).not.toBeInstanceOf(VaultError);
    expect(errorMessage(error)).not.toContain(CANARY.toString('utf8'));
    expect(errorMessage(error)).not.toContain(KEK_V1.toString('base64url'));

    const organizationEnvelope = await loadOrgEnvelope(appPool, ORG_A);
    const providerEnvelope = await loadProviderEnvelope(appPool, ORG_A, PROVIDER_KEY_A);
    const plaintext = vaultBothActiveV2.decryptProviderCredential({
      orgId: ORG_A,
      providerKeyId: PROVIDER_KEY_A,
      provider: 'openai',
      providerEnvelope,
      organizationEnvelope,
    });
    expect(plaintext.equals(CANARY)).toBe(true);
    plaintext.fill(0);
  });

  it('DB-16 releases pooled connections without retaining tenant context', async () => {
    await persistProviderCredential(ORG_A, PROVIDER_KEY_A, CANARY);
    await persistProviderCredential(ORG_B, PROVIDER_KEY_B, CANARY_B, vaultBothActiveV2);

    const before = await isolationPool.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
    const backendPid = before.rows[0]?.pid;

    const crossA = await withTenant(isolationPool, ORG_A, async (client) => {
      return (await client.query('SELECT id FROM provider_keys WHERE id = $1', [PROVIDER_KEY_B]))
        .rows;
    });
    expect(crossA).toEqual([]);

    const afterA = await isolationPool.query<{
      pid: number;
      org: string | null;
    }>("SELECT pg_backend_pid() AS pid, current_setting('app.current_org_id', true) AS org");
    expect(afterA.rows[0]?.pid).toBe(backendPid);
    expect(afterA.rows[0]?.org ?? '').toBe('');

    const crossB = await withTenant(isolationPool, ORG_B, async (client) => {
      return (await client.query('SELECT id FROM provider_keys WHERE id = $1', [PROVIDER_KEY_A]))
        .rows;
    });
    expect(crossB).toEqual([]);

    const afterB = await isolationPool.query<{
      pid: number;
      org: string | null;
    }>("SELECT pg_backend_pid() AS pid, current_setting('app.current_org_id', true) AS org");
    expect(afterB.rows[0]?.pid).toBe(backendPid);
    expect(afterB.rows[0]?.org ?? '').toBe('');
  });
});
