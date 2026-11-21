import fastify from 'fastify';
import type pino from 'pino';
import type { GatewayConfig } from './config/index.js';
import type { PostgresClient } from './infrastructure/postgres.js';
import type { RedisClient } from './infrastructure/redis.js';
import type { LifecycleCoordinator } from './lifecycle/state.js';
import { registerHealthRoutes } from './routes/health.js';
import { registerVirtualKeyRoutes } from './routes/virtual-keys.js';
import { getSafeRouteIdentifier } from './logging/serializers.js';
import { SessionService } from './auth/session.js';
import { installAuthorizationBoundary } from './auth/authorization.js';

export type AppInstance = ReturnType<typeof fastify>;

export interface BuildAppOptions {
  postgres: PostgresClient;
  redis: RedisClient;
  lifecycle: LifecycleCoordinator;
  logger: pino.Logger;
  config: GatewayConfig;
}

export async function buildApp(options: BuildAppOptions): Promise<AppInstance> {
  const { postgres, redis, lifecycle, logger, config } = options;

  const app = fastify({
    loggerInstance: logger,
    disableRequestLogging: true,
  });

  // Construct application-scoped session service reusing Postgres pool
  const sessionService = new SessionService({
    pool: postgres.pool,
    config,
    environment: config.NODE_ENV,
    cookieOptions: {
      secure: config.COOKIE_SECURE,
      isProduction: config.NODE_ENV === 'production',
    },
  });

  // Install default-deny authorization boundary before any routes are registered (SW-1.5.4)
  installAuthorizationBoundary(app, {
    sessionService,
    trustedOrigin: config.BROWSER_ORIGIN,
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
  await registerVirtualKeyRoutes(app, { pool: postgres.pool });

  return app;
}
