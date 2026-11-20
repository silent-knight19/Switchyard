import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  assertClusterIdentity,
  assertSafeDisposableDatabaseName,
  startDisposableCluster,
  CLUSTER_ID_ENV,
  CLUSTER_LABEL_KEY,
  CLUSTER_LABEL_VALUE,
  UNSUPPORTED_ADMIN_URL_ENV,
  type ClusterIdentityEvidence,
} from './disposable-pg.js';

describe('SW-1.3.1 disposable-pg test-cluster guard (review finding DB-13)', () => {
  it('refuses unsupported TEST_POSTGRES_ADMIN_URL environment variable', async () => {
    const prior = process.env[UNSUPPORTED_ADMIN_URL_ENV];
    try {
      // Simulate developer environment with loopback admin URL pointing at development cluster
      process.env[UNSUPPORTED_ADMIN_URL_ENV] =
        'postgres://switchyard:switchyard_dev_password@127.0.0.1:5432/postgres';
      await expect(startDisposableCluster()).rejects.toThrow(
        /TEST_POSTGRES_ADMIN_URL is no longer supported/,
      );
    } finally {
      if (prior === undefined) {
        delete process.env[UNSUPPORTED_ADMIN_URL_ENV];
      } else {
        process.env[UNSUPPORTED_ADMIN_URL_ENV] = prior;
      }
    }
  });

  describe('assertClusterIdentity evidence verification', () => {
    const validCluster = {
      containerName: 'switchyard-test-pg-1234-abcd',
      token: crypto.randomBytes(32).toString('hex'),
    };

    const validEvidence: ClusterIdentityEvidence = {
      containerName: 'switchyard-test-pg-1234-abcd',
      running: true,
      labels: {
        [CLUSTER_LABEL_KEY]: CLUSTER_LABEL_VALUE,
      },
      environment: [`${CLUSTER_ID_ENV}=${validCluster.token}`],
    };

    it('accepts authentic disposable cluster evidence', () => {
      expect(() => assertClusterIdentity(validCluster, validEvidence)).not.toThrow();
    });

    it('refuses mismatched container name (refusing external/development container)', () => {
      expect(() =>
        assertClusterIdentity(validCluster, {
          ...validEvidence,
          containerName: 'switchyard-postgres',
        }),
      ).toThrow(/expected the disposable test container/);
    });

    it('refuses container that is not running', () => {
      expect(() =>
        assertClusterIdentity(validCluster, {
          ...validEvidence,
          running: false,
        }),
      ).toThrow(/the container is not running/);
    });

    it('refuses container missing the switchyard.test=db identity label', () => {
      expect(() =>
        assertClusterIdentity(validCluster, {
          ...validEvidence,
          labels: {},
        }),
      ).toThrow(/missing disposable-cluster identity label/);

      expect(() =>
        assertClusterIdentity(validCluster, {
          ...validEvidence,
          labels: { [CLUSTER_LABEL_KEY]: 'unrelated' },
        }),
      ).toThrow(/missing disposable-cluster identity label/);
    });

    it('refuses container missing the cluster identity token environment variable', () => {
      expect(() =>
        assertClusterIdentity(validCluster, {
          ...validEvidence,
          environment: ['POSTGRES_PASSWORD=secret'],
        }),
      ).toThrow(/missing disposable-cluster identity token/);
    });

    it('refuses container with mismatched cluster identity token', () => {
      expect(() =>
        assertClusterIdentity(validCluster, {
          ...validEvidence,
          environment: [`${CLUSTER_ID_ENV}=wrong_token_value`],
        }),
      ).toThrow(/disposable-cluster identity token mismatch/);
    });
  });

  describe('assertSafeDisposableDatabaseName guard', () => {
    it('strictly refuses the persistent development database "switchyard"', () => {
      expect(() => assertSafeDisposableDatabaseName('switchyard')).toThrow(
        /Refusing to operate on database "switchyard"/,
      );
    });

    it('refuses postgres maintenance and system databases', () => {
      expect(() => assertSafeDisposableDatabaseName('postgres')).toThrow(/Refusing to operate/);
      expect(() => assertSafeDisposableDatabaseName('template1')).toThrow(/Refusing to operate/);
    });

    it('refuses names not matching the switchyard_test_* pattern', () => {
      expect(() => assertSafeDisposableDatabaseName('test_db')).toThrow(/Refusing to operate/);
      expect(() => assertSafeDisposableDatabaseName('production')).toThrow(/Refusing to operate/);
      expect(() =>
        assertSafeDisposableDatabaseName('switchyard_test_drop; DROP TABLE users; --'),
      ).toThrow(/Refusing to operate/);
    });

    it('accepts valid disposable test database names', () => {
      expect(() =>
        assertSafeDisposableDatabaseName('switchyard_test_db_abcdef123456'),
      ).not.toThrow();
      expect(() => assertSafeDisposableDatabaseName('switchyard_test_migration_001')).not.toThrow();
    });
  });
});
