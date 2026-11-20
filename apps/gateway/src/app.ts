import fastify from 'fastify';
import type pino from 'pino';
import type { PostgresClient } from './infrastructure/postgres.js';
import type { RedisClient } from './infrastructure/redis.js';
import type { LifecycleCoordinator } from './lifecycle/state.js';
import { registerHealthRoutes } from './routes/health.js';
import { getSafeRouteIdentifier } from './logging/serializers.js';

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

  // Safe Request Lifecycle Logging (Finding 4): Log route templates or allowlisted identifiers only; never raw paths or query strings
  app.addHook('onRequest', async (req) => {
    const safeRoute = getSafeRouteIdentifier(req.url, req.routeOptions?.url);
    logger.info(
      {
        requestId: req.id,
        method: req.method,
        route: safeRoute,
      },
      'Incoming request',
    );
  });

  app.addHook('onResponse', async (req, reply) => {
    const safeRoute = getSafeRouteIdentifier(req.url, req.routeOptions?.url);
    logger.info(
      {
        requestId: req.id,
        method: req.method,
        route: safeRoute,
        statusCode: reply.statusCode,
        responseTimeMs: reply.elapsedTime,
      },
      'Request completed',
    );
  });

  await registerHealthRoutes(app, { postgres, redis, lifecycle });

  return app;
}
