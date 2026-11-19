import fastify from 'fastify';
import type pino from 'pino';
import type { PostgresClient } from './infrastructure/postgres.js';
import type { RedisClient } from './infrastructure/redis.js';
import type { LifecycleCoordinator } from './lifecycle/state.js';
import { registerHealthRoutes } from './routes/health.js';

export type AppInstance = ReturnType<typeof fastify>;

export interface BuildAppOptions {
  postgres: PostgresClient;
  redis: RedisClient;
  lifecycle: LifecycleCoordinator;
  logger: pino.Logger;
}

export async function buildApp(options: BuildAppOptions): Promise<AppInstance> {
  const { postgres, redis, lifecycle, logger } = options;

  const app = fastify({
    loggerInstance: logger,
    disableRequestLogging: true,
  });

  // Safe Request Lifecycle Logging (D4)
  app.addHook('onRequest', async (req) => {
    logger.info(
      {
        requestId: req.id,
        method: req.method,
        url: req.url,
      },
      'Incoming request',
    );
  });

  app.addHook('onResponse', async (req, reply) => {
    logger.info(
      {
        requestId: req.id,
        method: req.method,
        url: req.url,
        statusCode: reply.statusCode,
        responseTimeMs: reply.elapsedTime,
      },
      'Request completed',
    );
  });

  await registerHealthRoutes(app, { postgres, redis, lifecycle });

  return app;
}
