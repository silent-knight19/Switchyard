import pg from 'pg';
import type { GatewayConfig } from '../config/index.js';

const { Pool } = pg;

export interface PostgresClient {
  pool: pg.Pool;
  checkReadiness(timeoutMs?: number): Promise<{ ok: boolean; code?: string; error?: string }>;
  close(): Promise<void>;
}

export function createPostgresClient(config: GatewayConfig): PostgresClient {
  const pool = new Pool({
    host: config.POSTGRES_HOST,
    port: config.POSTGRES_PORT,
    database: config.POSTGRES_DB,
    user: config.POSTGRES_USER,
    password: config.POSTGRES_PASSWORD,
    max: 10,
    idleTimeoutMillis: 10000,
    connectionTimeoutMillis: 2000,
    statement_timeout: 2000,
  });

  return {
    pool,
    async checkReadiness(timeoutMs = 2000) {
      let timer: NodeJS.Timeout | null = null;
      let isTimedOut = false;

      const timeoutPromise = new Promise<{ ok: false; code: string; error: string }>((resolve) => {
        timer = setTimeout(() => {
          isTimedOut = true;
          resolve({ ok: false, code: 'TIMEOUT', error: 'PostgreSQL readiness check timed out' });
        }, timeoutMs);
      });

      const checkPromise = (async (): Promise<{ ok: boolean; code?: string; error?: string }> => {
        let client: pg.PoolClient | null = null;
        try {
          // Bounded connection acquisition
          client = await pool.connect();
          if (isTimedOut) {
            client.release(true);
            client = null;
            return {
              ok: false,
              code: 'TIMEOUT',
              error: 'PostgreSQL connection acquired after timeout',
            };
          }

          // Enforce statement timeout at database level
          await client.query('SELECT 1');

          if (isTimedOut) {
            client.release(true);
            client = null;
            return { ok: false, code: 'TIMEOUT', error: 'PostgreSQL query finished after timeout' };
          }

          return { ok: true };
        } catch (err: unknown) {
          if (client) {
            // Invalidate/destroy errored or canceled connection to prevent retention/pool exhaustion
            client.release(true);
            client = null;
          }
          const code =
            err && typeof err === 'object' && 'code' in err && typeof err.code === 'string'
              ? err.code
              : 'DATABASE_ERROR';
          return { ok: false, code, error: 'PostgreSQL readiness check query failed' };
        } finally {
          if (client) {
            client.release();
          }
        }
      })();

      try {
        return await Promise.race([checkPromise, timeoutPromise]);
      } finally {
        if (timer) clearTimeout(timer);
      }
    },
    async close() {
      await pool.end();
    },
  };
}
