import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';
import {
  MIGRATION_ADVISORY_LOCK_KEY,
  MIGRATION_LEDGER_TABLE,
  MigrationError,
  loadMigrationFiles,
  runMigrations,
  type MigrationErrorCode,
} from './migrate.js';
import {
  bootstrapDatabase,
  copyMigrationsToTempDir,
  createDisposableDatabase,
  createRolePasswords,
  isPgErrorWithCode,
  removeTempDir,
  schemaAclEntryForPublic,
  roleConnectionString,
  startDisposableCluster,
  writeMigrationsToTempDir,
  type DisposableCluster,
  type DisposableDatabase,
} from './test/disposable-pg.js';

const MIGRATION_FILES = [
  '0001-roles.sql',
  '0002-org-tables.sql',
  '0003-rls-default-deny.sql',
  '0004-gateway-control-privileges.sql',
  '0005-virtual-key-integrity.sql',
  '0006-schema-privilege-hardening.sql',
];
const ALL_VERSIONS = MIGRATION_FILES.map((fileName) => fileName.slice(0, 4));

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function captureError(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => null,
    (error: unknown) => error,
  );
}

async function expectMigrationError(
  promise: Promise<unknown>,
  code: MigrationErrorCode,
): Promise<MigrationError> {
  const error = await captureError(promise);
  expect(error).toBeInstanceOf(MigrationError);
  const migrationError = error as MigrationError;
  expect(migrationError.code).toBe(code);
  return migrationError;
}

describe('SW-1.3.1 migration runner: locking, integrity, bootstrap (real PostgreSQL 16)', () => {
  let cluster: DisposableCluster;
  const databases: DisposableDatabase[] = [];
  const passwords = createRolePasswords();

  async function createDatabase(label: string): Promise<DisposableDatabase> {
    const database = await createDisposableDatabase(cluster, label);
    await bootstrapDatabase(database, passwords);
    databases.push(database);
    return database;
  }

  function migratorPool(database: DisposableDatabase): pg.Pool {
    const pool = new pg.Pool({
      connectionString: roleConnectionString(
        database.url,
        'gateway_migrator',
        passwords.gateway_migrator,
      ),
      max: 2,
    });
    // A terminated migration backend is an expected failure path in the interruption test.
    pool.on('error', () => undefined);
    return pool;
  }

  async function migrate(database: DisposableDatabase, migrationsDir?: string): Promise<string[]> {
    const pool = migratorPool(database);
    try {
      return await runMigrations(pool, migrationsDir === undefined ? {} : { migrationsDir });
    } finally {
      await pool.end();
    }
  }

  beforeAll(async () => {
    cluster = await startDisposableCluster();
  });

  afterAll(async () => {
    for (const database of databases) {
      await database.drop().catch(() => undefined);
    }
    if (cluster) await cluster.stop();
  });

  it('bootstrap provisions the exact least-privilege role matrix from a clean cluster', async () => {
    const database = await createDatabase('bootstrap');
    const client = new pg.Client({ connectionString: database.url });
    await client.connect();
    try {
      const { rows } = await client.query<{
        rolname: string;
        rolcanlogin: boolean;
        rolsuper: boolean;
        rolbypassrls: boolean;
        rolcreatedb: boolean;
        rolcreaterole: boolean;
      }>(
        `SELECT rolname, rolcanlogin, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole
         FROM pg_roles
         WHERE rolname LIKE 'gateway\\_%'
         ORDER BY rolname`,
      );
      const byName = new Map(rows.map((row) => [row.rolname, row]));
      const expected: Array<{ role: string; login: boolean; bypassRls: boolean }> = [
        { role: 'gateway_app', login: true, bypassRls: false },
        { role: 'gateway_auth_executor', login: false, bypassRls: true },
        { role: 'gateway_migrator', login: true, bypassRls: false },
        { role: 'gateway_ops_executor', login: false, bypassRls: true },
        { role: 'gateway_owner', login: false, bypassRls: false },
        { role: 'gateway_startup', login: true, bypassRls: false },
        { role: 'gateway_worker', login: true, bypassRls: false },
      ];
      expect(rows).toHaveLength(expected.length);
      for (const entry of expected) {
        const role = byName.get(entry.role);
        expect(role, `role ${entry.role} exists`).toBeDefined();
        expect(role?.rolcanlogin).toBe(entry.login);
        expect(role?.rolbypassrls).toBe(entry.bypassRls);
        expect(role?.rolsuper).toBe(false);
        expect(role?.rolcreatedb).toBe(false);
        expect(role?.rolcreaterole).toBe(false);
      }
    } finally {
      await client.end();
    }
  });

  it('bootstrap grants the migration role the owner assumption and protects the public schema', async () => {
    const database = await createDatabase('bootstrap-grants');
    const client = new pg.Client({ connectionString: database.url });
    await client.connect();
    try {
      const { rows: membership } = await client.query<{ member: string }>(
        `SELECT am.member::regrole::text AS member
         FROM pg_auth_members am
         WHERE am.roleid = 'gateway_owner'::regrole
           AND am.member = 'gateway_migrator'::regrole`,
      );
      expect(membership).toHaveLength(1);

      const { rows: executorMembership } = await client.query<{ roleid: string }>(
        `SELECT am.roleid::regrole::text AS roleid
         FROM pg_auth_members am
         WHERE am.roleid IN ('gateway_auth_executor'::regrole, 'gateway_ops_executor'::regrole)`,
      );
      expect(executorMembership).toHaveLength(0);

      const { rows: schemaAcl } = await client.query<{ nspname: string; acl: string | null }>(
        `SELECT nspname, nspacl::text AS acl
         FROM pg_namespace
         WHERE nspname IN ('public', 'app_private')
         ORDER BY nspname`,
      );
      expect(schemaAcl).toHaveLength(2);
      const publicAcl = schemaAcl.find((row) => row.nspname === 'public')?.acl ?? null;
      expect(schemaAclEntryForPublic(publicAcl)).not.toContain('C');
      const appPrivateAcl = schemaAcl.find((row) => row.nspname === 'app_private')?.acl ?? null;
      expect(schemaAclEntryForPublic(appPrivateAcl)).toBe('');

      const { rows: appPrivateOwner } = await client.query<{ owner: string }>(
        `SELECT pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname = 'app_private'`,
      );
      expect(appPrivateOwner[0]?.owner).toBe('gateway_owner');
    } finally {
      await client.end();
    }
  });

  it('applies the full migration set from an empty database as gateway_migrator', async () => {
    const database = await createDatabase('fresh');
    const applied = await migrate(database);
    expect(applied).toEqual(ALL_VERSIONS);

    const client = new pg.Client({ connectionString: database.url });
    await client.connect();
    try {
      const { rows } = await client.query<{ version: string; checksum: string | null }>(
        `SELECT version, checksum FROM ${MIGRATION_LEDGER_TABLE} ORDER BY version`,
      );
      expect(rows.map((row) => row.version)).toEqual(ALL_VERSIONS);
      for (const row of rows) {
        expect(row.checksum).toMatch(/^[a-f0-9]{64}$/);
      }
    } finally {
      await client.end();
    }
  });

  it('is repeatable: a second run applies nothing and keeps checksums stable', async () => {
    const database = await createDatabase('repeat');
    await migrate(database);
    expect(await migrate(database)).toEqual([]);
  });

  it('rejects a modified previously applied migration (SHA-256 mismatch)', async () => {
    const database = await createDatabase('tamper');
    await migrate(database);

    const dir = copyMigrationsToTempDir(MIGRATION_FILES);
    const target = path.join(dir, '0002-org-tables.sql');
    fs.appendFileSync(target, '\n-- modified after application\n');
    try {
      const error = await expectMigrationError(
        migrate(database, dir),
        'MIGRATION_CHECKSUM_MISMATCH',
      );
      expect(error.message).toMatch(/0002/);
    } finally {
      removeTempDir(dir);
    }
  });

  it('rejects a missing applied migration file', async () => {
    const database = await createDatabase('missing-file');
    await migrate(database);

    const dir = copyMigrationsToTempDir(MIGRATION_FILES.filter((name) => !name.startsWith('0006')));
    try {
      const error = await expectMigrationError(migrate(database, dir), 'MIGRATION_FILE_MISSING');
      expect(error.message).toMatch(/0006/);
    } finally {
      removeTempDir(dir);
    }
  });

  it('rejects duplicate migration versions before touching the database', () => {
    const dir = writeMigrationsToTempDir({
      '0001-first.sql': 'SELECT 1;',
      '0001-second.sql': 'SELECT 2;',
    });
    try {
      expect(() => loadMigrationFiles(dir)).toThrowError(MigrationError);
      try {
        loadMigrationFiles(dir);
      } catch (error) {
        expect((error as MigrationError).code).toBe('MIGRATION_DUPLICATE_VERSION');
      }
    } finally {
      removeTempDir(dir);
    }
  });

  it('rejects unsupported migration ordering gaps before touching the database', () => {
    const dir = writeMigrationsToTempDir({
      '0001-first.sql': 'SELECT 1;',
      '0003-third.sql': 'SELECT 3;',
    });
    try {
      try {
        loadMigrationFiles(dir);
        throw new Error('expected loadMigrationFiles to reject a version gap');
      } catch (error) {
        expect(error).toBeInstanceOf(MigrationError);
        expect((error as MigrationError).code).toBe('MIGRATION_ORDER_INVALID');
      }
    } finally {
      removeTempDir(dir);
    }
  });

  it('rejects a pending migration that is older than an applied migration', async () => {
    const database = await createDatabase('out-of-order');
    const files = loadMigrationFiles();
    // Own the ledger as the migration role, exactly as a real deployment would.
    const client = new pg.Client({
      connectionString: roleConnectionString(
        database.url,
        'gateway_migrator',
        passwords.gateway_migrator,
      ),
    });
    await client.connect();
    try {
      await client.query(
        `CREATE TABLE ${MIGRATION_LEDGER_TABLE} (
           version TEXT PRIMARY KEY,
           name TEXT NOT NULL,
           checksum TEXT,
           applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
         )`,
      );
      for (const version of ['0001', '0003']) {
        const file = files.find((candidate) => candidate.version === version);
        expect(file).toBeDefined();
        if (file === undefined) continue;
        await client.query(
          `INSERT INTO ${MIGRATION_LEDGER_TABLE} (version, name, checksum) VALUES ($1, $2, $3)`,
          [file.version, file.name, file.checksum],
        );
      }
    } finally {
      await client.end();
    }
    await expectMigrationError(migrate(database), 'MIGRATION_ORDER_INVALID');
  });

  it('rolls back a failed migration and never records it', async () => {
    const database = await createDatabase('rollback');
    const dir = writeMigrationsToTempDir({
      '0001-probe.sql': 'CREATE TABLE migration_probe (id INT);',
      '0002-broken.sql':
        'CREATE TABLE migration_broken (id INT);\nSELECT * FROM table_that_does_not_exist;',
    });
    const client = new pg.Client({ connectionString: database.url });
    await client.connect();
    try {
      const error = await expectMigrationError(migrate(database, dir), 'MIGRATION_APPLY_FAILED');
      expect(isPgErrorWithCode(error.cause, '42P01')).toBe(true);

      const { rows: tables } = await client.query<{ name: string | null }>(
        `SELECT to_regclass('public.migration_probe')::text AS name
         UNION ALL
         SELECT to_regclass('public.migration_broken')::text AS name`,
      );
      expect(tables.map((row) => row.name)).toEqual(['migration_probe', null]);

      const { rows: ledger } = await client.query<{ version: string }>(
        `SELECT version FROM ${MIGRATION_LEDGER_TABLE} ORDER BY version`,
      );
      expect(ledger.map((row) => row.version)).toEqual(['0001']);

      fs.writeFileSync(
        path.join(dir, '0002-broken.sql'),
        'CREATE TABLE migration_broken (id INT);',
        'utf8',
      );
      await expect(migrate(database, dir)).resolves.toEqual(['0002']);
    } finally {
      await client.end();
      removeTempDir(dir);
    }
  });

  it('rolls back and releases the lock when a migration backend is interrupted', async () => {
    const database = await createDatabase('interrupt');
    const dir = writeMigrationsToTempDir({
      '0001-interrupt.sql': 'CREATE TABLE interrupt_probe (id INT);\nSELECT pg_sleep(30);',
    });
    const pool = migratorPool(database);
    const supervisor = new pg.Client({ connectionString: database.url });
    await supervisor.connect();
    try {
      const run = runMigrations(pool, { migrationsDir: dir, lockTimeoutMs: 5000 });
      const deadline = Date.now() + 20_000;
      let backendPid: number | undefined;
      while (Date.now() < deadline && backendPid === undefined) {
        const { rows } = await supervisor.query<{ pid: number }>(
          `SELECT pid
           FROM pg_stat_activity
           WHERE datname = current_database()
             AND pid <> pg_backend_pid()
             AND query LIKE '%pg_sleep(30)%'
           LIMIT 1`,
        );
        backendPid = rows[0]?.pid;
        if (backendPid === undefined) await delay(100);
      }
      expect(backendPid, 'migration backend should be executing the slow statement').toBeDefined();
      if (backendPid === undefined) throw new Error('migration backend not found');
      await supervisor.query('SELECT pg_terminate_backend($1)', [backendPid]);

      const error = await captureError(run);
      expect(error).not.toBeNull();

      const { rows: tables } = await supervisor.query<{ name: string | null }>(
        `SELECT to_regclass('public.interrupt_probe')::text AS name`,
      );
      expect(tables[0]?.name).toBeNull();
      const { rows: ledger } = await supervisor.query<{ version: string }>(
        `SELECT version FROM ${MIGRATION_LEDGER_TABLE}`,
      );
      expect(ledger).toHaveLength(0);

      removeTempDir(dir);
      const validDir = writeMigrationsToTempDir({
        '0001-probe.sql': 'CREATE TABLE interrupt_probe (id INT);',
      });
      try {
        await expect(migrate(database, validDir)).resolves.toEqual(['0001']);
      } finally {
        removeTempDir(validDir);
      }
    } finally {
      await supervisor.end();
      await pool.end();
    }
  });

  it('bounds the advisory-lock wait and reports MIGRATION_LOCK_TIMEOUT', async () => {
    const database = await createDatabase('lock-timeout');
    const holder = new pg.Client({ connectionString: database.url });
    await holder.connect();
    try {
      await holder.query('SELECT pg_advisory_lock($1::bigint)', [MIGRATION_ADVISORY_LOCK_KEY]);
      const error = await expectMigrationError(
        (async () => {
          const pool = migratorPool(database);
          try {
            return await runMigrations(pool, { lockTimeoutMs: 400 });
          } finally {
            await pool.end();
          }
        })(),
        'MIGRATION_LOCK_TIMEOUT',
      );
      expect(isPgErrorWithCode(error.cause, '55P03')).toBe(true);
    } finally {
      await holder.query('SELECT pg_advisory_unlock($1::bigint)', [MIGRATION_ADVISORY_LOCK_KEY]);
      await holder.end();
    }

    expect(await migrate(database)).toEqual(ALL_VERSIONS);
  });

  it('applies each migration exactly once when concurrent runners race', async () => {
    const database = await createDatabase('concurrent');
    const pools = [0, 1, 2].map(() => migratorPool(database));
    try {
      const results = await Promise.all(pools.map((pool) => runMigrations(pool)));
      const applied = results.flat().sort();
      expect(applied).toEqual(ALL_VERSIONS);
    } finally {
      await Promise.all(pools.map((pool) => pool.end()));
    }

    const client = new pg.Client({ connectionString: database.url });
    await client.connect();
    try {
      const { rows } = await client.query<{ version: string; count: number }>(
        `SELECT version, count(*)::int AS count FROM ${MIGRATION_LEDGER_TABLE} GROUP BY version`,
      );
      expect(rows).toHaveLength(ALL_VERSIONS.length);
      for (const row of rows) expect(row.count).toBe(1);
    } finally {
      await client.end();
    }
  });

  it('adopts legacy checksums only when explicitly requested', async () => {
    const database = await createDatabase('legacy');
    const legacyDir = copyMigrationsToTempDir(['0001-roles.sql', '0002-org-tables.sql']);
    try {
      expect(await migrate(database, legacyDir)).toEqual(['0001', '0002']);
    } finally {
      removeTempDir(legacyDir);
    }

    const client = new pg.Client({ connectionString: database.url });
    await client.connect();
    try {
      await client.query(`UPDATE ${MIGRATION_LEDGER_TABLE} SET checksum = NULL`);
    } finally {
      await client.end();
    }

    await expectMigrationError(migrate(database), 'MIGRATION_LEGACY_CHECKSUM_MISSING');

    const events: string[] = [];
    const pool = migratorPool(database);
    let applied: string[];
    try {
      applied = await runMigrations(pool, {
        adoptLegacyChecksums: true,
        onEvent: (event) => events.push(`${event.type}:${'version' in event ? event.version : ''}`),
      });
    } finally {
      await pool.end();
    }
    expect(applied).toEqual(['0003', '0004', '0005', '0006']);
    expect(events).toContain('adopted:0001');
    expect(events).toContain('adopted:0002');

    const verifier = new pg.Client({ connectionString: database.url });
    await verifier.connect();
    try {
      const files = loadMigrationFiles();
      const { rows } = await verifier.query<{ version: string; checksum: string | null }>(
        `SELECT version, checksum FROM ${MIGRATION_LEDGER_TABLE} ORDER BY version`,
      );
      for (const row of rows) {
        const file = files.find((candidate) => candidate.version === row.version);
        expect(file?.checksum).toBe(row.checksum);
      }
    } finally {
      await verifier.end();
    }

    // Repeated adoption on an already-adopted ledger is idempotent and stable
    const secondEvents: string[] = [];
    const secondPool = migratorPool(database);
    let secondApplied: string[];
    try {
      secondApplied = await runMigrations(secondPool, {
        adoptLegacyChecksums: true,
        onEvent: (event) =>
          secondEvents.push(`${event.type}:${'version' in event ? event.version : ''}`),
      });
    } finally {
      await secondPool.end();
    }
    expect(secondApplied).toEqual([]);
    expect(secondEvents).toEqual(['up-to-date:']);
  });

  it('rejects checksum adoption when legacy migration file on disk is modified (DB-14)', async () => {
    const database = await createDatabase('legacy_modified');
    const legacyDir = copyMigrationsToTempDir(['0001-roles.sql', '0002-org-tables.sql']);
    try {
      expect(await migrate(database, legacyDir)).toEqual(['0001', '0002']);
    } finally {
      removeTempDir(legacyDir);
    }

    const client = new pg.Client({ connectionString: database.url });
    await client.connect();
    try {
      await client.query(`UPDATE ${MIGRATION_LEDGER_TABLE} SET checksum = NULL`);
    } finally {
      await client.end();
    }

    // Temp dir with modified 0001-roles.sql
    const tempDir = writeMigrationsToTempDir({
      '0001-roles.sql': '-- modified content that does not match historical baseline\nSELECT 1;\n',
      '0002-org-tables.sql': fs.readFileSync(
        path.join(process.cwd(), 'src', 'db', 'migrations', '0002-org-tables.sql'),
        'utf8',
      ),
    });
    try {
      const pool = migratorPool(database);
      try {
        await expectMigrationError(
          runMigrations(pool, { migrationsDir: tempDir, adoptLegacyChecksums: true }),
          'MIGRATION_LEGACY_CHECKSUM_UNVERIFIED',
        );
      } finally {
        await pool.end();
      }
    } finally {
      removeTempDir(tempDir);
    }
  });

  it('rejects checksum adoption for an unknown legacy migration without verified baseline (DB-14)', async () => {
    const database = await createDatabase('legacy_unknown');
    const legacyDir = copyMigrationsToTempDir([
      '0001-roles.sql',
      '0002-org-tables.sql',
      '0003-rls-default-deny.sql',
    ]);
    try {
      expect(await migrate(database, legacyDir)).toEqual(['0001', '0002', '0003']);
    } finally {
      removeTempDir(legacyDir);
    }

    const client = new pg.Client({ connectionString: database.url });
    await client.connect();
    try {
      // Migration 0003 is NOT in VERIFIED_LEGACY_MIGRATIONS; having NULL checksum is rejected
      await client.query(
        `UPDATE ${MIGRATION_LEDGER_TABLE} SET checksum = NULL WHERE version = '0003'`,
      );
    } finally {
      await client.end();
    }

    const pool = migratorPool(database);
    try {
      await expectMigrationError(
        runMigrations(pool, { adoptLegacyChecksums: true }),
        'MIGRATION_LEGACY_CHECKSUM_UNVERIFIED',
      );
    } finally {
      await pool.end();
    }
  });
});
