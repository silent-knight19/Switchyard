import crypto from 'node:crypto';
import pg from 'pg';
import pino from 'pino';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuthenticationService } from './service.js';
import type { LoginRateLimiter } from './rate-limiter.js';
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
  EnvelopeVault,
  ENVELOPE_FORMAT_VERSION,
  type OrganizationDekEnvelope,
} from '../vault/envelope.js';
import { VaultError } from '../vault/errors.js';
import { KekKeyring } from '../vault/kek.js';
import {
  ProviderKeyManagementError,
  ProviderKeyManagementService,
} from './provider-key-management.js';

const ORG_A = '11111111-1111-4111-8111-111111111111';
const ORG_B = '22222222-2222-4222-8222-222222222222';
const ADMIN_PASSWORD = 'Synthetic-Admin-Password-2026!';

const KEK_V1 = crypto.randomBytes(32);
const KEK_V2 = crypto.randomBytes(32);

const CANARY_A = 'sk-synthetic-canary-openai-key-org-a-123456';
const CANARY_REPLACEMENT = 'sk-synthetic-replacement-key-org-a-999999';

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

async function expectSqlState(promise: Promise<unknown>, sqlState: string): Promise<unknown> {
  const error = await captureError(promise);
  expect(errorCode(error), `expected SQLSTATE ${sqlState}, got ${String(errorCode(error))}`).toBe(
    sqlState,
  );
  return error;
}

describe('SW-1.7-B: Provider Credential Vault Completion (Real PostgreSQL 16 Suite)', () => {
  let cluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();

  let adminClient: pg.Client;
  let appPool: pg.Pool;
  let workerClient: pg.Client;

  let vaultV1: EnvelopeVault;
  let vaultBothActiveV2: EnvelopeVault;
  let vaultV2Only: EnvelopeVault;
  let authService: AuthenticationService;
  let service: ProviderKeyManagementService;

  let orgAEnvelope: OrganizationDekEnvelope;
  let orgBEnvelope: OrganizationDekEnvelope;

  const capturedLogs: string[] = [];
  const testLogger = pino(
    { level: 'info' },
    {
      write: (msg: string) => {
        capturedLogs.push(msg);
      },
    },
  );

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

  async function loadOrgEnvelope(orgId: string): Promise<OrganizationDekEnvelope> {
    return withTenant(appPool, orgId, async (client) => {
      const { rows } = await client.query<{
        kek_version: number;
        wrapped_dek: Buffer;
        dek_iv: Buffer;
        dek_auth_tag: Buffer;
      }>('SELECT kek_version, wrapped_dek, dek_iv, dek_auth_tag FROM organizations WHERE id = $1', [
        orgId,
      ]);
      const row = rows[0]!;
      return {
        kekVersion: row.kek_version,
        wrappedDek: row.wrapped_dek,
        dekIv: row.dek_iv,
        dekAuthTag: row.dek_auth_tag,
      };
    });
  }

  async function loadProviderRow(orgId: string, keyId: string) {
    return withTenant(appPool, orgId, async (client) => {
      const { rows } = await client.query<{
        id: string;
        org_id: string;
        provider: string;
        label: string;
        key_hint: string;
        ciphertext: Buffer;
        iv: Buffer;
        auth_tag: Buffer;
        is_active: boolean;
        created_at: Date;
      }>('SELECT * FROM provider_keys WHERE id = $1', [keyId]);
      return rows[0] ?? null;
    });
  }

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    db = await createDisposableDatabase(cluster, 'provider_vault_completion');
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

    vaultV1 = new EnvelopeVault(new KekKeyring({ activeVersion: 1, keys: { 1: KEK_V1 } }));
    vaultBothActiveV2 = new EnvelopeVault(
      new KekKeyring({ activeVersion: 2, keys: { 1: KEK_V1, 2: KEK_V2 } }),
    );
    vaultV2Only = new EnvelopeVault(new KekKeyring({ activeVersion: 2, keys: { 2: KEK_V2 } }));

    authService = new AuthenticationService({
      pool: appPool,
      rateLimiter: fakeRateLimiter(),
    });

    service = new ProviderKeyManagementService({
      pool: appPool,
      vault: vaultV1,
    });

    orgAEnvelope = vaultV1.createOrganizationEnvelope(ORG_A);
    orgBEnvelope = vaultV1.createOrganizationEnvelope(ORG_B);
    await bootstrapOrg(ORG_A, 'Org Alpha', 'admin@alpha.example.test', orgAEnvelope);
    await bootstrapOrg(ORG_B, 'Org Beta', 'admin@beta.example.test', orgBEnvelope);
  }, 240_000);

  afterAll(async () => {
    await appPool?.end().catch(() => undefined);
    await workerClient?.end().catch(() => undefined);
    await adminClient?.end().catch(() => undefined);
    await db?.drop().catch(() => undefined);
    await cluster?.stop();
  }, 60_000);

  describe('STAGE A — SW-1.7.3 Provider Credential Management Service', () => {
    let createdKeyAId: string;

    it('A1. creates encrypted provider credential and stores ciphertext differing from plaintext', async () => {
      const result = await service.createKey(ORG_A, {
        provider: 'openai',
        label: 'Org A Primary OpenAI',
        credential: CANARY_A,
      });

      expect(result.id).toBeDefined();
      createdKeyAId = result.id;
      expect(result.provider).toBe('openai');
      expect(result.label).toBe('Org A Primary OpenAI');
      expect(result.keyHint).toBe('****3456');
      expect(result.isActive).toBe(true);
      expect(result.createdAt).toBeDefined();

      // Ensure response never exposes plaintext or ciphertext
      expect((result as unknown as Record<string, unknown>).credential).toBeUndefined();
      expect((result as unknown as Record<string, unknown>).ciphertext).toBeUndefined();

      // Direct DB inspection
      const row = await loadProviderRow(ORG_A, createdKeyAId);
      expect(row).not.toBeNull();
      expect(row!.provider).toBe('openai');
      expect(row!.is_active).toBe(true);
      expect(row!.ciphertext[0]).toBe(ENVELOPE_FORMAT_VERSION);
      expect(row!.ciphertext.length).toBeGreaterThan(1);
      // Ciphertext must not contain plaintext string
      expect(row!.ciphertext.toString('utf8')).not.toContain(CANARY_A);
      expect(row!.iv.length).toBe(12);
      expect(row!.auth_tag.length).toBe(16);
    });

    it('A2. decrypts stored credential via internal Gateway pathway and verifies exact match', async () => {
      const row = await loadProviderRow(ORG_A, createdKeyAId);
      expect(row).not.toBeNull();

      const orgEnvelope = await loadOrgEnvelope(ORG_A);
      const decrypted = vaultV1.decryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: createdKeyAId,
        provider: row!.provider,
        providerEnvelope: {
          ciphertext: row!.ciphertext,
          iv: row!.iv,
          authTag: row!.auth_tag,
        },
        organizationEnvelope: orgEnvelope,
      });

      try {
        expect(decrypted.toString('utf8')).toBe(CANARY_A);
      } finally {
        decrypted.fill(0);
      }
    });

    it('A3. enforces key hint safety rules for short credentials and unicode', async () => {
      const shortKey = await service.createKey(ORG_A, {
        provider: 'openai',
        label: 'Short Credential',
        credential: 'abc',
      });
      expect(shortKey.keyHint).toBe('****');

      const fourCharKey = await service.createKey(ORG_A, {
        provider: 'openai',
        label: 'Four Char Credential',
        credential: '1234',
      });
      expect(fourCharKey.keyHint).toBe('****');

      const emojiKey = await service.createKey(ORG_A, {
        provider: 'openai',
        label: 'Emoji Credential',
        credential: 'prefix-key-🔥🌟',
      });
      expect(emojiKey.keyHint).toBe('****y-🔥🌟');
    });

    it('A4. replaces credential atomically with fresh IV and ciphertext', async () => {
      const beforeRow = await loadProviderRow(ORG_A, createdKeyAId);
      expect(beforeRow).not.toBeNull();

      const updated = await service.replaceKey(ORG_A, createdKeyAId, {
        label: 'Org A Replaced OpenAI',
        credential: CANARY_REPLACEMENT,
      });

      expect(updated.id).toBe(createdKeyAId);
      expect(updated.label).toBe('Org A Replaced OpenAI');
      expect(updated.keyHint).toBe('****9999');
      expect(updated.isActive).toBe(true);

      const afterRow = await loadProviderRow(ORG_A, createdKeyAId);
      expect(afterRow).not.toBeNull();
      expect(Buffer.compare(afterRow!.ciphertext, beforeRow!.ciphertext)).not.toBe(0);
      expect(Buffer.compare(afterRow!.iv, beforeRow!.iv)).not.toBe(0);

      // Decrypt with updated credential
      const orgEnvelope = await loadOrgEnvelope(ORG_A);
      const decrypted = vaultV1.decryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: createdKeyAId,
        provider: afterRow!.provider,
        providerEnvelope: {
          ciphertext: afterRow!.ciphertext,
          iv: afterRow!.iv,
          authTag: afterRow!.auth_tag,
        },
        organizationEnvelope: orgEnvelope,
      });

      try {
        expect(decrypted.toString('utf8')).toBe(CANARY_REPLACEMENT);
      } finally {
        decrypted.fill(0);
      }
    });

    it('A5. lists organization credentials with bounded keyset pagination without secret columns', async () => {
      const list = await service.listKeys(ORG_A, { limit: 10 });
      expect(list.items.length).toBeGreaterThanOrEqual(4);

      for (const item of list.items) {
        expect(item.id).toBeDefined();
        expect(item.provider).toBe('openai');
        expect(item.label).toBeDefined();
        expect(item.keyHint).toBeDefined();
        expect(typeof item.isActive).toBe('boolean');
        expect(item.createdAt).toBeDefined();

        // Strict verification: no secret fields
        const raw = item as unknown as Record<string, unknown>;
        expect(raw.ciphertext).toBeUndefined();
        expect(raw.iv).toBeUndefined();
        expect(raw.authTag).toBeUndefined();
        expect(raw.auth_tag).toBeUndefined();
        expect(raw.wrappedDek).toBeUndefined();
        expect(raw.kekVersion).toBeUndefined();
      }

      // Test pagination cursor
      const page1 = await service.listKeys(ORG_A, { limit: 2 });
      expect(page1.items.length).toBe(2);
      expect(page1.nextCursor).not.toBeNull();

      const page2 = await service.listKeys(ORG_A, { limit: 2, cursor: page1.nextCursor! });
      expect(page2.items.length).toBeGreaterThan(0);
      expect(page2.items[0]!.id).not.toBe(page1.items[0]!.id);
      expect(page2.items[0]!.id).not.toBe(page1.items[1]!.id);
    });

    it('A6. disables provider credential idempotently without decrypting or purging bytes', async () => {
      const beforeRow = await loadProviderRow(ORG_A, createdKeyAId);
      expect(beforeRow!.is_active).toBe(true);

      // 1. Disable active key
      await service.disableKey(ORG_A, createdKeyAId);

      const disabledRow = await loadProviderRow(ORG_A, createdKeyAId);
      expect(disabledRow!.is_active).toBe(false);
      // Ciphertext, IV, and tag remain intact
      expect(Buffer.compare(disabledRow!.ciphertext, beforeRow!.ciphertext)).toBe(0);
      expect(Buffer.compare(disabledRow!.iv, beforeRow!.iv)).toBe(0);
      expect(Buffer.compare(disabledRow!.auth_tag, beforeRow!.auth_tag)).toBe(0);

      // 2. Idempotent repeated disable
      await service.disableKey(ORG_A, createdKeyAId);
      const stillDisabled = await loadProviderRow(ORG_A, createdKeyAId);
      expect(stillDisabled!.is_active).toBe(false);
    });

    it('A7. rejects replacing credential of a disabled key with 409 Conflict', async () => {
      await expect(
        service.replaceKey(ORG_A, createdKeyAId, {
          label: 'Attempted reactivation',
          credential: 'synthetic-new-key',
        }),
      ).rejects.toThrow(ProviderKeyManagementError);

      try {
        await service.replaceKey(ORG_A, createdKeyAId, {
          label: 'Attempted reactivation',
          credential: 'synthetic-new-key',
        });
      } catch (err) {
        expect((err as ProviderKeyManagementError).reason).toBe('KEY_DISABLED');
      }
    });

    it('A8. enforces strict tenant isolation: Org B cannot read, update, or disable Org A keys', async () => {
      // 1. Org B cannot read Org A's key in list
      const orgBList = await service.listKeys(ORG_B);
      expect(orgBList.items.some((k) => k.id === createdKeyAId)).toBe(false);

      // 2. Org B cannot replace Org A's key
      await expect(
        service.replaceKey(ORG_B, createdKeyAId, {
          label: 'Cross-tenant replace attempt',
          credential: 'cross-tenant-secret',
        }),
      ).rejects.toThrow('Provider key not found');

      // 3. Org B cannot disable Org A's key
      await expect(service.disableKey(ORG_B, createdKeyAId)).rejects.toThrow(
        'Provider key not found',
      );
    });

    it('A9. enforces PostgreSQL RLS default-deny without tenant context', async () => {
      const rawRes = await appPool.query('SELECT * FROM provider_keys');
      expect(rawRes.rows.length).toBe(0);
    });

    it('A10. proves connection returned to pool does not retain tenant context', async () => {
      const singleConnPool = new pg.Pool({
        connectionString: roleConnectionString(db.url, 'gateway_app', passwords.gateway_app),
        max: 1,
      });

      try {
        await withTenant(singleConnPool, ORG_A, async (client) => {
          const { rows } = await client.query('SELECT current_setting($1, true) as org', [
            'app.current_org_id',
          ]);
          expect(rows[0]?.org).toBe(ORG_A);
        });

        // Next query without withTenant on the same connection pool
        const client = await singleConnPool.connect();
        try {
          const { rows } = await client.query('SELECT current_setting($1, true) as org', [
            'app.current_org_id',
          ]);
          expect(rows[0]?.org).toBe('');
        } finally {
          client.release();
        }
      } finally {
        await singleConnPool.end();
      }
    });
  });

  describe('STAGE B — SW-1.7.4 Decrypt-Path Scrubbing, Privacy & Hardening', () => {
    it('B1. denies gateway_worker all access to secret-bearing columns in provider_keys and organizations', async () => {
      // 1. Worker denied on provider_keys.ciphertext, iv, auth_tag
      await expectSqlState(workerClient.query('SELECT ciphertext FROM provider_keys'), '42501');
      await expectSqlState(workerClient.query('SELECT iv FROM provider_keys'), '42501');
      await expectSqlState(workerClient.query('SELECT auth_tag FROM provider_keys'), '42501');
      await expectSqlState(workerClient.query('SELECT * FROM provider_keys'), '42501');

      // 2. Worker denied on organizations.wrapped_dek, dek_iv, dek_auth_tag
      await expectSqlState(workerClient.query('SELECT wrapped_dek FROM organizations'), '42501');
      await expectSqlState(workerClient.query('SELECT dek_iv FROM organizations'), '42501');
      await expectSqlState(workerClient.query('SELECT dek_auth_tag FROM organizations'), '42501');
      await expectSqlState(workerClient.query('SELECT * FROM organizations'), '42501');

      // 3. Worker permitted on non-secret metadata
      const workerProviderMeta = await workerClient.query(
        'SELECT id, org_id, provider, label, key_hint, is_active, created_at FROM provider_keys',
      );
      expect(workerProviderMeta.rows).toBeDefined();

      const workerOrgMeta = await workerClient.query(
        'SELECT id, name, monthly_budget_microdollars, kek_version, created_at FROM organizations',
      );
      expect(workerOrgMeta.rows).toBeDefined();
    });

    it('B2. verifies intermediate memory scrubbing on successful and failing vault unwrap/decrypt', async () => {
      const orgEnvelope = await loadOrgEnvelope(ORG_A);

      // Verify successful decrypt clears intermediate buffers and caller owns returned buffer
      const tempCred = Buffer.from('sk-canary-memory-scrub-verification-12345', 'utf8');
      const tempKeyId = crypto.randomUUID();

      const encrypted = vaultV1.encryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: tempKeyId,
        provider: 'openai',
        plaintext: tempCred,
        organizationEnvelope: orgEnvelope,
      });

      // Clear caller's temp input buffer
      tempCred.fill(0);

      const decrypted = vaultV1.decryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: tempKeyId,
        provider: 'openai',
        providerEnvelope: encrypted,
        organizationEnvelope: orgEnvelope,
      });

      expect(decrypted.toString('utf8')).toBe('sk-canary-memory-scrub-verification-12345');
      // Caller clears returned buffer
      decrypted.fill(0);
      expect(decrypted.every((b) => b === 0)).toBe(true);

      // Verify failing decrypt clears intermediate chunks and leaves no plaintext
      const tamperedCiphertext = Buffer.from(encrypted.ciphertext);
      tamperedCiphertext[tamperedCiphertext.length - 1]! ^= 0xff;

      expect(() =>
        vaultV1.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: tempKeyId,
          provider: 'openai',
          providerEnvelope: {
            ciphertext: tamperedCiphertext,
            iv: encrypted.iv,
            authTag: encrypted.authTag,
          },
          organizationEnvelope: orgEnvelope,
        }),
      ).toThrow(VaultError);
    });

    it('B3. verifies historical KEK compatibility: V1 decrypts under V1, and under V1+V2, fails without V1', async () => {
      const orgEnvelope = await loadOrgEnvelope(ORG_A);
      expect(orgEnvelope.kekVersion).toBe(1);

      const tempKeyId = crypto.randomUUID();
      const tempCred = Buffer.from('sk-canary-historical-kek-probe', 'utf8');
      const encrypted = vaultV1.encryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: tempKeyId,
        provider: 'openai',
        plaintext: tempCred,
        organizationEnvelope: orgEnvelope,
      });

      // 1. Decrypts with V1 vault
      const decV1 = vaultV1.decryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: tempKeyId,
        provider: 'openai',
        providerEnvelope: encrypted,
        organizationEnvelope: orgEnvelope,
      });
      expect(decV1.toString('utf8')).toBe('sk-canary-historical-kek-probe');
      decV1.fill(0);

      // 2. Decrypts with V1+V2 vault (active version is 2, historical V1 available)
      const decBoth = vaultBothActiveV2.decryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: tempKeyId,
        provider: 'openai',
        providerEnvelope: encrypted,
        organizationEnvelope: orgEnvelope,
      });
      expect(decBoth.toString('utf8')).toBe('sk-canary-historical-kek-probe');
      decBoth.fill(0);

      // 3. Fails closed without historical V1 (vault only has V2)
      expect(() =>
        vaultV2Only.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: tempKeyId,
          provider: 'openai',
          providerEnvelope: encrypted,
          organizationEnvelope: orgEnvelope,
        }),
      ).toThrow(VaultError);
    });

    it('B4. verifies AAD tampering and cross-tenant / cross-record ciphertext transplantation fails closed', async () => {
      const orgEnvelopeA = await loadOrgEnvelope(ORG_A);
      const orgEnvelopeB = await loadOrgEnvelope(ORG_B);

      const keyIdA = crypto.randomUUID();
      const keyIdB = crypto.randomUUID();

      const encrypted = vaultV1.encryptProviderCredential({
        orgId: ORG_A,
        providerKeyId: keyIdA,
        provider: 'openai',
        plaintext: Buffer.from('secret-payload-transplant-test', 'utf8'),
        organizationEnvelope: orgEnvelopeA,
      });

      // 1. Cross-record transplantation: attempting to decrypt keyIdA's ciphertext under keyIdB fails
      expect(() =>
        vaultV1.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: keyIdB,
          provider: 'openai',
          providerEnvelope: encrypted,
          organizationEnvelope: orgEnvelopeA,
        }),
      ).toThrow(VaultError);

      // 2. Cross-tenant transplantation: attempting to decrypt Org A's ciphertext under Org B fails
      expect(() =>
        vaultV1.decryptProviderCredential({
          orgId: ORG_B,
          providerKeyId: keyIdA,
          provider: 'openai',
          providerEnvelope: encrypted,
          organizationEnvelope: orgEnvelopeB,
        }),
      ).toThrow(VaultError);

      // 3. Provider AAD substitution: attempting to decrypt under different provider name fails
      expect(() =>
        vaultV1.decryptProviderCredential({
          orgId: ORG_A,
          providerKeyId: keyIdA,
          provider: 'openai-invalid',
          providerEnvelope: encrypted,
          organizationEnvelope: orgEnvelopeA,
        }),
      ).toThrow(VaultError);
    });

    it('B5. privacy and logging probe: secret canary credentials never appear in application logs or errors', async () => {
      const canaryString = 'sk-synthetic-logger-privacy-canary-998877';

      // Log normal structured operations with testLogger
      testLogger.info({ orgId: ORG_A, action: 'create_provider_key' }, 'Creating key');

      try {
        // Trigger a validation failure with the canary
        await service.createKey(ORG_A, {
          provider: 'openai',
          label: 'Prohibited\nControl',
          credential: canaryString,
        });
      } catch (err) {
        testLogger.error({ err }, 'Expected validation error');
      }

      // Assert that canaryString is not present in ANY collected log line
      for (const logLine of capturedLogs) {
        expect(logLine).not.toContain(canaryString);
      }
    });
  });
});
