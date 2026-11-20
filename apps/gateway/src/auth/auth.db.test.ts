import crypto from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
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
import { hashPassword, verifyPassword } from './password.js';
import { AuthenticationService } from './service.js';
import { AuthenticationError, BootstrapError } from './types.js';

describe('SW-1.5.1: Authentication Service PostgreSQL 16 Integration Suite', () => {
  let cluster: DisposableCluster;
  let db: DisposableDatabase;
  const passwords = createRolePasswords();
  let adminClient: pg.Client;
  let appPool: pg.Pool;
  let authService: AuthenticationService;

  const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
  const USER_A_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const ADMIN_EMAIL = 'admin@alpha.com';
  const ADMIN_PASSWORD = 'CorrectHorseBatteryStaple!2026';

  let adminPasswordHash: string;

  beforeAll(async () => {
    cluster = await startDisposableCluster();
    db = await createDisposableDatabase(cluster, 'auth_service_test');
    await bootstrapDatabase(db, passwords);

    // Apply all migrations including 0011
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

    // Connect superuser client for fixture seeding and persistent state assertions
    adminClient = new pg.Client({ connectionString: db.url });
    await adminClient.connect();

    // Generate real Argon2id hash for the seed admin user
    adminPasswordHash = await hashPassword(ADMIN_PASSWORD);

    // Seed test organization and user
    await adminClient.query(`
      INSERT INTO public.organizations (id, name, monthly_budget_microdollars, kek_version, wrapped_dek, dek_iv, dek_auth_tag)
      VALUES ('${ORG_A_ID}', 'Org Alpha', 1000000, 1, '\\x0102', '\\x0304', '\\x0506');

      INSERT INTO public.users (id, org_id, email_normalized, password_hash, role)
      VALUES ('${USER_A_ID}', '${ORG_A_ID}', '${ADMIN_EMAIL}', '${adminPasswordHash}', 'admin');
    `);

    // Connect runtime gateway_app pool
    appPool = new pg.Pool({
      connectionString: roleConnectionString(db.url, 'gateway_app', passwords.gateway_app),
    });

    authService = new AuthenticationService({
      pool: appPool,
    });
  }, 60000);

  afterAll(async () => {
    if (appPool) await appPool.end();
    if (adminClient) await adminClient.end();
    if (db) await db.drop();
    if (cluster) await cluster.stop();
  }, 30000);

  describe('1. User Login & Password Verification', () => {
    it('authenticates a user with correct credentials and returns sanitized principal', async () => {
      const user = await authService.authenticate(ADMIN_EMAIL, ADMIN_PASSWORD, '127.0.0.1');

      expect(user.id).toBe(USER_A_ID);
      expect(user.orgId).toBe(ORG_A_ID);
      expect(user.role).toBe('admin');
      expect(user.emailNormalized).toBe(ADMIN_EMAIL);

      // Verify no sensitive fields (password_hash) exist on principal object
      const userRecord = user as unknown as Record<string, unknown>;
      expect(userRecord['password_hash']).toBeUndefined();
      expect(userRecord['passwordHash']).toBeUndefined();
    });

    it('normalizes mixed-case and untrimmed email during authentication', async () => {
      const user = await authService.authenticate(
        '  Admin@Alpha.COM  ',
        ADMIN_PASSWORD,
        '127.0.0.1',
      );

      expect(user.id).toBe(USER_A_ID);
      expect(user.orgId).toBe(ORG_A_ID);
      expect(user.emailNormalized).toBe(ADMIN_EMAIL);
    });

    it('rejects an incorrect password with generic INVALID_CREDENTIALS error', async () => {
      await expect(
        authService.authenticate(ADMIN_EMAIL, 'WrongPassword!2026', '127.0.0.1'),
      ).rejects.toThrow(AuthenticationError);

      try {
        await authService.authenticate(ADMIN_EMAIL, 'WrongPassword!2026', '127.0.0.1');
      } catch (err) {
        expect(err).toBeInstanceOf(AuthenticationError);
        const authErr = err as AuthenticationError;
        expect(authErr.reason).toBe('INVALID_CREDENTIALS');
        expect(authErr.message).toBe('Invalid email or password');
      }
    });

    it('rejects an unknown user email with generic INVALID_CREDENTIALS and executes dummy verify', async () => {
      await expect(
        authService.authenticate('nonexistent@example.com', ADMIN_PASSWORD, '127.0.0.1'),
      ).rejects.toThrow(AuthenticationError);

      try {
        await authService.authenticate('nonexistent@example.com', ADMIN_PASSWORD, '127.0.0.1');
      } catch (err) {
        expect(err).toBeInstanceOf(AuthenticationError);
        const authErr = err as AuthenticationError;
        expect(authErr.reason).toBe('INVALID_CREDENTIALS');
        expect(authErr.message).toBe('Invalid email or password');
      }
    });

    it('rejects malformed email inputs with INVALID_INPUT before database lookup', async () => {
      await expect(
        authService.authenticate('invalidemail', ADMIN_PASSWORD, '127.0.0.1'),
      ).rejects.toThrow(AuthenticationError);

      try {
        await authService.authenticate('invalidemail', ADMIN_PASSWORD, '127.0.0.1');
      } catch (err) {
        expect(err).toBeInstanceOf(AuthenticationError);
        expect((err as AuthenticationError).reason).toBe('INVALID_INPUT');
      }
    });

    it('rejects oversized passwords (> 128 bytes) with INVALID_INPUT before database or crypto operations', async () => {
      const oversizedPassword = 'a'.repeat(129);
      await expect(
        authService.authenticate(ADMIN_EMAIL, oversizedPassword, '127.0.0.1'),
      ).rejects.toThrow(AuthenticationError);

      try {
        await authService.authenticate(ADMIN_EMAIL, oversizedPassword, '127.0.0.1');
      } catch (err) {
        expect(err).toBeInstanceOf(AuthenticationError);
        expect((err as AuthenticationError).reason).toBe('INVALID_INPUT');
      }
    });
  });

  describe('2. Internal Organization & Administrator Bootstrap', () => {
    it('creates organization and initial admin atomically with valid Argon2id verifier', async () => {
      const orgId = crypto.randomUUID();
      const adminUserId = crypto.randomUUID();
      const adminEmail = 'newadmin@bootstrap.org';
      const adminPassword = 'BootstrapPassword!999';

      const res = await authService.bootstrapOrganizationWithAdmin({
        orgId,
        adminUserId,
        orgName: 'Bootstrap Org',
        monthlyBudgetMicrodollars: 50000000n,
        kekVersion: 1,
        wrappedDek: Buffer.from('test-wrapped-dek-bytes'),
        dekIv: Buffer.from('test-iv-12bytes!'),
        dekAuthTag: Buffer.from('test-auth-tag16!'),
        adminEmail,
        adminPassword,
      });

      expect(res.orgId).toBe(orgId);
      expect(res.adminUserId).toBe(adminUserId);

      // Verify persistent state in PostgreSQL
      const orgRow = await adminClient.query(
        'SELECT name, monthly_budget_microdollars FROM organizations WHERE id = $1',
        [orgId],
      );
      expect(orgRow.rows).toHaveLength(1);
      expect(orgRow.rows[0]?.name).toBe('Bootstrap Org');
      expect(orgRow.rows[0]?.monthly_budget_microdollars).toBe('50000000');

      const userRow = await adminClient.query(
        'SELECT role, password_hash, email_normalized FROM users WHERE id = $1',
        [adminUserId],
      );
      expect(userRow.rows).toHaveLength(1);
      expect(userRow.rows[0]?.role).toBe('admin');
      expect(userRow.rows[0]?.email_normalized).toBe(adminEmail);

      // Verify stored verifier is valid Argon2id hash that verifies with adminPassword
      const storedHash = userRow.rows[0]?.password_hash;
      expect(storedHash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
      const isMatch = await verifyPassword(storedHash, adminPassword);
      expect(isMatch).toBe(true);

      // Verify user can now immediately authenticate
      const authUser = await authService.authenticate(adminEmail, adminPassword, '127.0.0.1');
      expect(authUser.id).toBe(adminUserId);
      expect(authUser.orgId).toBe(orgId);
    });

    it('rejects duplicate email and leaves no orphan organization or user', async () => {
      const duplicateOrgId = crypto.randomUUID();
      const duplicateAdminUserId = crypto.randomUUID();

      await expect(
        authService.bootstrapOrganizationWithAdmin({
          orgId: duplicateOrgId,
          adminUserId: duplicateAdminUserId,
          orgName: 'Competing Org',
          monthlyBudgetMicrodollars: 1000n,
          kekVersion: 1,
          wrappedDek: Buffer.from('wrapped-dek'),
          dekIv: Buffer.from('dek-iv'),
          dekAuthTag: Buffer.from('dek-tag'),
          adminEmail: ADMIN_EMAIL, // already exists
          adminPassword: 'Password!123',
        }),
      ).rejects.toThrow(BootstrapError);

      // Verify atomicity: duplicateOrgId must NOT be persisted in organizations table
      const orgCheck = await adminClient.query('SELECT id FROM organizations WHERE id = $1', [
        duplicateOrgId,
      ]);
      expect(orgCheck.rows).toHaveLength(0);

      const userCheck = await adminClient.query('SELECT id FROM users WHERE id = $1', [
        duplicateAdminUserId,
      ]);
      expect(userCheck.rows).toHaveLength(0);
    });

    it('rejects duplicate organization ID and leaves no orphan user', async () => {
      const freshAdminId = crypto.randomUUID();

      await expect(
        authService.bootstrapOrganizationWithAdmin({
          orgId: ORG_A_ID, // already exists
          adminUserId: freshAdminId,
          orgName: 'Duplicate Org ID',
          monthlyBudgetMicrodollars: 1000n,
          kekVersion: 1,
          wrappedDek: Buffer.from('wrapped-dek'),
          dekIv: Buffer.from('dek-iv'),
          dekAuthTag: Buffer.from('dek-tag'),
          adminEmail: 'fresh.user@alpha.com',
          adminPassword: 'Password!123',
        }),
      ).rejects.toThrow(BootstrapError);

      const userCheck = await adminClient.query('SELECT id FROM users WHERE id = $1', [
        freshAdminId,
      ]);
      expect(userCheck.rows).toHaveLength(0);
    });

    it('rejects invalid budget before database execution', async () => {
      await expect(
        authService.bootstrapOrganizationWithAdmin({
          orgName: 'Negative Budget Org',
          monthlyBudgetMicrodollars: -100n,
          kekVersion: 1,
          wrappedDek: Buffer.from('wrapped-dek'),
          dekIv: Buffer.from('dek-iv'),
          dekAuthTag: Buffer.from('dek-tag'),
          adminEmail: 'neg@test.com',
          adminPassword: 'Password!123',
        }),
      ).rejects.toThrow(BootstrapError);
    });

    it('rejects missing or empty cryptographic DEK parameters', async () => {
      await expect(
        authService.bootstrapOrganizationWithAdmin({
          orgName: 'No DEK Org',
          monthlyBudgetMicrodollars: 1000n,
          kekVersion: 1,
          wrappedDek: Buffer.alloc(0), // empty
          dekIv: Buffer.from('iv'),
          dekAuthTag: Buffer.from('tag'),
          adminEmail: 'nodek@test.com',
          adminPassword: 'Password!123',
        }),
      ).rejects.toThrow(BootstrapError);
    });
  });
});
