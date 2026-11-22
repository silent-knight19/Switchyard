import crypto from 'node:crypto';
import pg from 'pg';
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
import { KekKeyring } from '../vault/kek.js';
import {
  ProviderKeyManagementError,
  ProviderKeyManagementService,
} from './provider-key-management.js';

const ORG_A = '11111111-1111-4111-8111-111111111111';
const ORG_B = '22222222-2222-4222-8222-222222222222';
const ADMIN_PASSWORD = 'Synthetic-Admin-Password-2026!';

const KEK_V1 = crypto.randomBytes(32);

const CANARY_A = 'sk-synthetic-canary-openai-key-org-a-123456';
const CANARY_REPLACEMENT = 'sk-synthetic-replacement-key-org-a-999999';

function fakeRateLimiter(): LoginRateLimiter {
  return {
    assertNotRateLimited: async () => undefined,
  } as unknown as LoginRateLimiter;
}

describe('SW-1.7-B: Provider Credential Vault Completion (Real PostgreSQL 16 Suite)', () => {
  let cluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();

  let adminClient: pg.Client;
  let appPool: pg.Pool;

  let vaultV1: EnvelopeVault;
  let authService: AuthenticationService;
  let service: ProviderKeyManagementService;

  let orgAEnvelope: OrganizationDekEnvelope;
  let orgBEnvelope: OrganizationDekEnvelope;

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

    vaultV1 = new EnvelopeVault(new KekKeyring({ activeVersion: 1, keys: { 1: KEK_V1 } }));

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
});
