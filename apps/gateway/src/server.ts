import { loadConfig, type GatewayConfig } from './config/index.js';
import { createLogger } from './logging/index.js';
import { createPostgresClient, type PostgresClient } from './infrastructure/postgres.js';
import { createRedisClient, type RedisClient } from './infrastructure/redis.js';
import { LifecycleCoordinator } from './lifecycle/state.js';
import { GracefulShutdownManager } from './lifecycle/shutdown.js';
import { buildApp, type AppInstance } from './app.js';

export class StartupError extends Error {
  public readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'StartupError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export interface GatewayServerContext {
  config: GatewayConfig;
  app: AppInstance;
  postgres: PostgresClient;
  redis: RedisClient;
  lifecycle: LifecycleCoordinator;
  shutdownManager: GracefulShutdownManager;
  stop(): Promise<void>;
}

export interface ServerDependencies {
  postgres?: PostgresClient;
  redis?: RedisClient;
}

export async function createServer(
  envOverride?: Record<string, string | undefined>,
  dependencies?: ServerDependencies,
): Promise<GatewayServerContext> {
  // Step 1: Validate configuration (Fails closed on missing/invalid settings)
  const config = loadConfig(envOverride);

  // Step 2: Initialize structured logger
  const logger = createLogger({
    level: config.NODE_ENV === 'production' ? 'info' : 'debug',
    environment: config.NODE_ENV,
  });

  logger.info({ env: config.NODE_ENV, port: config.PORT }, 'Initializing Gateway server');

  let postgres: PostgresClient | null = null;
  let redis: RedisClient | null = null;
  let app: AppInstance | null = null;

  // Cleanup boundary (R4): Guarantee resource cleanup on any initialization failure
  const cleanup = async () => {
    if (app) {
      try {
        await app.close();
      } catch {
        /* ignore cleanup error to preserve root cause */
      }
    }
    if (redis) {
      try {
        await redis.close();
      } catch {
        /* ignore cleanup error to preserve root cause */
      }
    }
    if (postgres) {
      try {
        await postgres.close();
      } catch {
        /* ignore cleanup error to preserve root cause */
      }
    }
  };

  try {
    const lifecycle = new LifecycleCoordinator();

    // Step 3: Initialize database connectivity (R1, R5: bounded & secret-safe)
    logger.info('Connecting to PostgreSQL');
    postgres = dependencies?.postgres ?? createPostgresClient(config);
    const pgReady = await postgres.checkReadiness(2000);
    if (!pgReady.ok) {
      const code = pgReady.code ?? 'DATABASE_CONNECT_FAILED';
      logger.error({ code }, 'PostgreSQL readiness check failed during startup');
      throw new StartupError(code, 'PostgreSQL readiness check failed during startup');
    }

    // Step 4: Initialize Redis connectivity (R1, R5: bounded & secret-safe)
    logger.info('Connecting to Redis');
    redis = dependencies?.redis ?? createRedisClient(config);
    const redisReady = await redis.checkReadiness(2000);
    if (!redisReady.ok) {
      const code = redisReady.code ?? 'REDIS_CONNECT_FAILED';
      logger.error({ code }, 'Redis readiness check failed during startup');
      throw new StartupError(code, 'Redis readiness check failed during startup');
    }

    // Step 5: Verify mandatory Redis security policy (noeviction)
    if (redisReady.policy !== 'noeviction') {
      logger.error({ policy: redisReady.policy }, 'Unsafe Redis policy: expected "noeviction"');
      throw new StartupError(
        'UNSAFE_REDIS_POLICY',
        `Unsafe Redis policy "${redisReady.policy}": expected "noeviction"`,
      );
    }

    // Step 6: Verify mandatory Redis runtime ACL restrictions (R3)
    const aclVerification = await redis.verifyAclRestrictions(2000);
    if (!aclVerification.ok) {
      const code = aclVerification.code ?? 'UNSAFE_REDIS_ACL';
      logger.error({ code }, 'Redis ACL restriction verification failed');
      throw new StartupError(
        code,
        'Redis ACL verification failed: runtime identity is not properly restricted',
      );
    }

    // Step 7: Initialize Fastify and health routes
    app = await buildApp({
      postgres,
      redis,
      lifecycle,
      logger,
      config,
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
  } catch (err) {
    await cleanup();
    throw err;
  }
}

export async function startServer(
  envOverride?: Record<string, string | undefined>,
  dependencies?: ServerDependencies,
): Promise<GatewayServerContext> {
  const context = await createServer(envOverride, dependencies);
  const { app, config, lifecycle, shutdownManager } = context;

  // Step 8: Begin listening only after required initialization succeeds (R4 cleanup on listen error)
  try {
    await app.listen({ port: config.PORT, host: config.HOST });
    lifecycle.setReady();
    app.log.info({ port: config.PORT, host: config.HOST }, 'Gateway server is listening and ready');
  } catch (err) {
    await shutdownManager.shutdown('LISTEN_FAILED').catch(() => {});
    throw err;
  }

  // Step 9: Register process shutdown hooks
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
