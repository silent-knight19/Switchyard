import pg from 'pg';
import type { GatewayConfig } from '../config/index.js';

const { Pool } = pg;

export interface PostgresClient {
  pool: pg.Pool;
  checkReadiness(): Promise<{ ok: boolean; error?: string }>;
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
    connectionTimeoutMillis: 3000,
  });

  return {
    pool,
    async checkReadiness() {
      try {
        const client = await pool.connect();
        try {
          await client.query('SELECT 1');
          return { ok: true };
        } finally {
          client.release();
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown database error';
        return { ok: false, error: message };
      }
    },
    async close() {
      await pool.end();
    },
  };
}
