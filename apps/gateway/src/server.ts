import { loadConfig, type GatewayConfig } from './config/index.js';
import { createLogger } from './logging/index.js';
import { createPostgresClient, type PostgresClient } from './infrastructure/postgres.js';
import { createRedisClient, type RedisClient } from './infrastructure/redis.js';
import { LifecycleCoordinator } from './lifecycle/state.js';
import { GracefulShutdownManager } from './lifecycle/shutdown.js';
import { buildApp, type AppInstance } from './app.js';

export interface GatewayServerContext {
  config: GatewayConfig;
  app: AppInstance;
  postgres: PostgresClient;
  redis: RedisClient;
  lifecycle: LifecycleCoordinator;
  shutdownManager: GracefulShutdownManager;
  stop(): Promise<void>;
}

export async function createServer(
  envOverride?: Record<string, string | undefined>,
): Promise<GatewayServerContext> {
  // Step 1: Validate configuration
  const config = loadConfig(envOverride);

  // Step 2: Initialize logger
  const logger = createLogger({
    level: config.NODE_ENV === 'production' ? 'info' : 'debug',
    environment: config.NODE_ENV,
  });

  logger.info({ env: config.NODE_ENV, port: config.PORT }, 'Initializing Gateway server');

  const lifecycle = new LifecycleCoordinator();

  // Step 3: Initialize database connectivity
  logger.info('Connecting to PostgreSQL');
  const postgres = createPostgresClient(config);
  const pgReady = await postgres.checkReadiness();
  if (!pgReady.ok) {
    const errorMsg = `PostgreSQL readiness check failed during startup: ${pgReady.error}`;
    logger.error(errorMsg);
    await postgres.close();
    throw new Error(errorMsg);
  }

  // Step 4: Initialize Redis connectivity
  logger.info('Connecting to Redis');
  const redis = createRedisClient(config);
  const redisReady = await redis.checkReadiness();
  if (!redisReady.ok) {
    const errorMsg = `Redis readiness check failed during startup: ${redisReady.error}`;
    logger.error(errorMsg);
    await redis.close();
    await postgres.close();
    throw new Error(errorMsg);
  }

  // Step 5: Verify mandatory Redis security policy (noeviction)
  if (redisReady.policy !== 'noeviction') {
    const errorMsg = `Unsafe Redis policy "${redisReady.policy}": expected "noeviction"`;
    logger.error(errorMsg);
    await redis.close();
    await postgres.close();
    throw new Error(errorMsg);
  }

  // Step 6: Initialize Fastify and health routes
  const app = await buildApp({
    postgres,
    redis,
    lifecycle,
    logger,
  });

  const shutdownManager = new GracefulShutdownManager({
    server: app,
    postgres,
    redis,
    lifecycle,
    logger,
  });

  return {
    config,
    app,
    postgres,
    redis,
    lifecycle,
    shutdownManager,
    stop: () => shutdownManager.shutdown('MANUAL'),
  };
}

export async function startServer(
  envOverride?: Record<string, string | undefined>,
): Promise<GatewayServerContext> {
  const context = await createServer(envOverride);
  const { app, config, lifecycle, shutdownManager } = context;

  // Step 7: Begin listening only after required initialization succeeds
  await app.listen({ port: config.PORT, host: config.HOST });

  lifecycle.setReady();
  app.log.info({ port: config.PORT, host: config.HOST }, 'Gateway server is listening and ready');

  // Step 8: Register process shutdown hooks
  const handleSignal = (signal: string) => {
    app.log.info({ signal }, 'Process signal received; shutting down');
    shutdownManager.shutdown(signal).then(
      () => {
        process.exit(0);
      },
      (err) => {
        app.log.error({ err }, 'Fatal error during graceful shutdown');
        process.exit(1);
      },
    );
  };

  process.once('SIGTERM', () => handleSignal('SIGTERM'));
  process.once('SIGINT', () => handleSignal('SIGINT'));

  return context;
}
