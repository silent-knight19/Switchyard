import type pino from 'pino';
import type { AppInstance } from '../app.js';
import type { PostgresClient } from '../infrastructure/postgres.js';
import type { RedisClient } from '../infrastructure/redis.js';
import type { LifecycleCoordinator } from './state.js';

export interface ShutdownDependencies {
  server: AppInstance;
  postgres: PostgresClient;
  redis: RedisClient;
  lifecycle: LifecycleCoordinator;
  logger: pino.Logger;
  timeoutMs?: number;
}

export class GracefulShutdownManager {
  private shutdownPromise: Promise<void> | null = null;

  constructor(private readonly deps: ShutdownDependencies) {}

  public async shutdown(signal?: string): Promise<void> {
    if (this.shutdownPromise) {
      return this.shutdownPromise;
    }

    this.deps.logger.info({ signal }, 'Graceful shutdown initiated');
    this.deps.lifecycle.setDraining();

    this.shutdownPromise = this.executeShutdown();
    return this.shutdownPromise;
  }

  private async executeShutdown(): Promise<void> {
    const timeoutMs = this.deps.timeoutMs ?? 5000;

    const shutdownTimer = setTimeout(() => {
      this.deps.logger.error({ timeoutMs }, 'Shutdown deadline exceeded; forcing process exit');
      process.exit(1);
    }, timeoutMs);

    shutdownTimer.unref();

    try {
      // 1. Close HTTP server and drain in-flight connections
      this.deps.logger.debug('Closing Fastify HTTP server');
      await this.deps.server.close();

      // 2. Close PostgreSQL connection pool
      this.deps.logger.debug('Closing PostgreSQL connection pool');
      await this.deps.postgres.close();

      // 3. Close Redis connection
      this.deps.logger.debug('Closing Redis client connection');
      await this.deps.redis.close();

      this.deps.lifecycle.setStopped();
      this.deps.logger.info('Graceful shutdown completed successfully');
    } catch (err) {
      this.deps.logger.error({ err }, 'Error occurred during graceful shutdown');
      throw err;
    } finally {
      clearTimeout(shutdownTimer);
    }
  }
}
