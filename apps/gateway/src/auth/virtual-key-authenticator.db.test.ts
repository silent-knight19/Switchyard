import crypto from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { runMigrations } from '../db/migrate.js';
import {
  bootstrapDatabase,
  createDisposableDatabase,
  createRolePasswords,
  roleConnectionString,
  startDisposableCluster,
  type DisposableCluster,
  type DisposableDatabase,
} from '../db/test/disposable-pg.js';
import { generateKeyMaterial, VirtualKeyService } from './virtual-key.js';
import {
  type IVirtualKeyRateLimiter,
  VirtualKeyAuthError,
  VirtualKeyAuthenticatorService,
} from './virtual-key-authenticator.js';

describe('SW-1.6.2: Real PostgreSQL 16 Virtual Key Authentication & Security Suite', () => {
  let cluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();
  let adminClient: pg.Client;
  let appPool: pg.Pool;
  let workerPool: pg.Pool;
  let issuanceService: VirtualKeyService;
  let authenticator: VirtualKeyAuthenticatorService;
  let mockRateLimiter: IVirtualKeyRateLimiter;

  const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
  const ORG_B_ID = '22222222-2222-4222-8222-222222222222';
  const CLIENT_IP = '198.51.100.55';

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    db = await createDisposableDatabase(cluster, 'vk_auth_db_test');
    await bootstrapDatabase(db, passwords);

    // Apply migrations 0001 through 0011
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

    // Connect admin client for fixture setup
    adminClient = new pg.Client({ connectionString: db.url });
    await adminClient.connect();

    // Seed test organizations
    await adminClient.query(`
      INSERT INTO public.organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
      VALUES
        ('${ORG_A_ID}', 'Org Alpha', 1000000, 1, '\\x01', '\\x02', '\\x03'),
        ('${ORG_B_ID}', 'Org Beta', 2000000, 1, '\\x04', '\\x05', '\\x06');
    `);

    // Connect runtime gateway_app pool
    appPool = new pg.Pool({
      connectionString: roleConnectionString(db.url, 'gateway_app', passwords.gateway_app),
    });
    appPool.on('error', () => undefined);

    // Connect runtime gateway_worker pool for negative privilege checks
    workerPool = new pg.Pool({
      connectionString: roleConnectionString(db.url, 'gateway_worker', passwords.gateway_worker),
    });
    workerPool.on('error', () => undefined);

    issuanceService = new VirtualKeyService(appPool);

    mockRateLimiter = {
      assertNotRateLimited: vi.fn().mockResolvedValue(undefined),
      reset: vi.fn().mockResolvedValue(undefined),
    };

    authenticator = new VirtualKeyAuthenticatorService({
      pool: appPool,
      rateLimiter: mockRateLimiter,
    });
  }, 60000);

  afterAll(async () => {
    await appPool?.end().catch(() => undefined);
    await workerPool?.end().catch(() => undefined);
    await adminClient?.end().catch(() => undefined);
    await db?.drop().catch(() => undefined);
  });

  describe('1. Tenant Identity Resolution & Key Authentication', () => {
    it('authenticates Org A key and resolves strictly to Org A principal', async () => {
      const keyA = await issuanceService.createKey({
        orgId: ORG_A_ID,
        name: 'Alpha Production Key',
      });

      const resA = await authenticator.authenticateKey(keyA.rawKey, CLIENT_IP);

      expect(resA.valid).toBe(true);
      expect(resA.principal).toBeDefined();
      expect(resA.principal?.type).toBe('virtual_key');
      expect(resA.principal?.keyId).toBe(keyA.id);
      expect(resA.principal?.orgId).toBe(ORG_A_ID);
      expect(resA.principal?.keyPolicy?.allowedModels).toEqual([]);
      expect(resA.principal?.keyPolicy?.rpmLimit).toBe(1);
      expect(resA.principal?.keyPolicy?.tpmLimit).toBe(1);
      expect(resA.principal?.keyPolicy?.concurrentStreamLimit).toBe(1);
      expect(resA.principal?.keyPolicy?.piiRedactionEnabled).toBe(true);
      expect(resA.principal?.keyPolicy?.storePayloads).toBe(false);
    });

    it('authenticates Org B key and resolves strictly to Org B principal', async () => {
      const keyB = await issuanceService.createKey({
        orgId: ORG_B_ID,
        name: 'Beta Production Key',
      });

      const resB = await authenticator.authenticateKey(keyB.rawKey, CLIENT_IP);

      expect(resB.valid).toBe(true);
      expect(resB.principal).toBeDefined();
      expect(resB.principal?.type).toBe('virtual_key');
      expect(resB.principal?.keyId).toBe(keyB.id);
      expect(resB.principal?.orgId).toBe(ORG_B_ID);
      expect(resB.principal?.keyPolicy?.allowedModels).toEqual([]);
    });

    it('denies well-formed random key that does not exist in database', async () => {
      // Build valid-format key with random secret
      const prefix = crypto.randomBytes(8).toString('base64url');
      const secret = crypto.randomBytes(32).toString('base64url');
      const randomKey = `gw_live_${prefix}_${secret}`;

      const res = await authenticator.authenticateKey(randomKey, CLIENT_IP);
      expect(res.valid).toBe(false);
      expect(res.reason).toBe('KEY_NOT_FOUND');
      expect(res.principal).toBeUndefined();
    });

    it('denies revoked key and prevents its verifier from being used', async () => {
      const keyToRevoke = await issuanceService.createKey({
        orgId: ORG_A_ID,
        name: 'Key To Revoke',
      });

      // Initially valid
      const beforeRevoke = await authenticator.authenticateKey(keyToRevoke.rawKey, CLIENT_IP);
      expect(beforeRevoke.valid).toBe(true);

      // Revoke the key in the database
      await adminClient.query('UPDATE public.virtual_keys SET revoked_at = NOW() WHERE id = $1', [
        keyToRevoke.id,
      ]);

      // Now must be denied with KEY_REVOKED
      const afterRevoke = await authenticator.authenticateKey(keyToRevoke.rawKey, CLIENT_IP);
      expect(afterRevoke.valid).toBe(false);
      expect(afterRevoke.reason).toBe('KEY_REVOKED');
      expect(afterRevoke.principal).toBeUndefined();
    });

    it('preserves empty allowed_models array without activating model access', async () => {
      const key = await issuanceService.createKey({
        orgId: ORG_A_ID,
        name: 'Deny All Models Key',
      });

      const res = await authenticator.authenticateKey(key.rawKey, CLIENT_IP);
      expect(res.valid).toBe(true);
      expect(res.principal?.keyPolicy?.allowedModels).toEqual([]);
      expect(Object.isFrozen(res.principal?.keyPolicy?.allowedModels)).toBe(true);
    });

    it('returns custom limits and privacy flags when configured in database', async () => {
      const customKey = await issuanceService.createKey({
        orgId: ORG_B_ID,
        name: 'Custom Policy Key',
      });

      // Update policy columns
      await adminClient.query(
        `UPDATE public.virtual_keys
         SET allowed_models = ARRAY['claude-3-haiku', 'gpt-4o-mini'],
             rpm_limit = 500,
             tpm_limit = 50000,
             concurrent_stream_limit = 25,
             exact_cache_enabled = true,
             semantic_cache_enabled = true,
             pii_redaction_enabled = false,
             store_payloads = true
         WHERE id = $1`,
        [customKey.id],
      );

      const res = await authenticator.authenticateKey(customKey.rawKey, CLIENT_IP);
      expect(res.valid).toBe(true);
      const policy = res.principal!.keyPolicy!;
      expect(policy.allowedModels).toEqual(['claude-3-haiku', 'gpt-4o-mini']);
      expect(policy.rpmLimit).toBe(500);
      expect(policy.tpmLimit).toBe(50000);
      expect(policy.concurrentStreamLimit).toBe(25);
      expect(policy.exactCacheEnabled).toBe(true);
      expect(policy.semanticCacheEnabled).toBe(true);
      expect(policy.piiRedactionEnabled).toBe(false);
      expect(policy.storePayloads).toBe(true);
    });
  });

  describe('2. Security Boundary & Privilege Verification', () => {
    it('proves gateway_app can execute lookup_virtual_key_by_hash', async () => {
      const res = await appPool.query(
        "SELECT * FROM app_private.lookup_virtual_key_by_hash('\\x01'::bytea)",
      );
      expect(res.rows).toEqual([]);
    });

    it('proves gateway_worker is denied execute on lookup_virtual_key_by_hash (42501)', async () => {
      await expect(
        workerPool.query("SELECT * FROM app_private.lookup_virtual_key_by_hash('\\x01'::bytea)"),
      ).rejects.toThrow(/permission denied/);
    });

    it('proves function returns zero rows for NULL or non-32-byte hashes', async () => {
      // NULL
      const resNull = await appPool.query(
        'SELECT * FROM app_private.lookup_virtual_key_by_hash(NULL)',
      );
      expect(resNull.rows).toHaveLength(0);

      // Empty bytea (\x)
      const resEmpty = await appPool.query(
        "SELECT * FROM app_private.lookup_virtual_key_by_hash('\\x'::bytea)",
      );
      expect(resEmpty.rows).toHaveLength(0);

      // 31 bytes
      const res31 = await appPool.query(
        'SELECT * FROM app_private.lookup_virtual_key_by_hash($1)',
        [Buffer.alloc(31, 0xaa)],
      );
      expect(res31.rows).toHaveLength(0);

      // 33 bytes
      const res33 = await appPool.query(
        'SELECT * FROM app_private.lookup_virtual_key_by_hash($1)',
        [Buffer.alloc(33, 0xbb)],
      );
      expect(res33.rows).toHaveLength(0);
    });

    it('proves principal contains zero secret or credential material', async () => {
      const key = await issuanceService.createKey({
        orgId: ORG_A_ID,
        name: 'Leakage Inspection Key',
      });

      const res = await authenticator.authenticateKey(key.rawKey, CLIENT_IP);
      const principalJson = JSON.stringify(res.principal);

      expect(principalJson).not.toContain(key.rawKey);
      expect(principalJson).not.toContain(key.keyPrefix);
      expect(principalJson).not.toContain('key_hash');
      expect(principalJson).not.toContain('secret');
      expect(principalJson).not.toContain(passwords.gateway_app);
      expect(principalJson).not.toContain(passwords.gateway_migrator);
    });
  });

  describe('3. Concurrency & Outage Handling', () => {
    it('concurrent independent authentications preserve strict tenant identity', async () => {
      const keyA = await issuanceService.createKey({ orgId: ORG_A_ID, name: 'Conc A' });
      const keyB = await issuanceService.createKey({ orgId: ORG_B_ID, name: 'Conc B' });

      const promises = Array.from({ length: 20 }, (_, idx) => {
        const isA = idx % 2 === 0;
        const key = isA ? keyA.rawKey : keyB.rawKey;
        const expectedOrg = isA ? ORG_A_ID : ORG_B_ID;
        const expectedKeyId = isA ? keyA.id : keyB.id;

        return authenticator.authenticateKey(key, `198.51.100.${idx + 1}`).then((res) => {
          expect(res.valid).toBe(true);
          expect(res.principal?.orgId).toBe(expectedOrg);
          expect(res.principal?.keyId).toBe(expectedKeyId);
        });
      });

      await Promise.all(promises);
    });

    it('fails closed with SERVICE_UNAVAILABLE when database pool is closed', async () => {
      const deadPool = new pg.Pool({
        connectionString: 'postgresql://gateway_app:pw@127.0.0.1:65534/dead_db',
        connectionTimeoutMillis: 200,
      });
      deadPool.on('error', () => undefined);

      const deadAuth = new VirtualKeyAuthenticatorService({
        pool: deadPool,
        rateLimiter: mockRateLimiter,
      });

      const material = generateKeyMaterial();
      await expect(deadAuth.authenticateKey(material.rawKey, CLIENT_IP)).rejects.toThrow(
        VirtualKeyAuthError,
      );

      try {
        await deadAuth.authenticateKey(material.rawKey, CLIENT_IP);
      } catch (err) {
        expect((err as VirtualKeyAuthError).reason).toBe('SERVICE_UNAVAILABLE');
      } finally {
        await deadPool.end().catch(() => undefined);
      }
    });
  });
});
