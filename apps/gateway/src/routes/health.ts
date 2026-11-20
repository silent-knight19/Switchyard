import type { FastifyReply, FastifyRequest } from 'fastify';
import type { AppInstance } from '../app.js';
import type { PostgresClient } from '../infrastructure/postgres.js';
import type { RedisClient } from '../infrastructure/redis.js';
import type { LifecycleCoordinator } from '../lifecycle/state.js';

export interface HealthRouteOptions {
  postgres: PostgresClient;
  redis: RedisClient;
  lifecycle: LifecycleCoordinator;
}

const READINESS_TIMEOUT_MS = 2500;

export async function registerHealthRoutes(
  app: AppInstance,
  options: HealthRouteOptions,
): Promise<void> {
  const { postgres, redis, lifecycle } = options;

  app.get('/health/live', async (_req: FastifyRequest, reply: FastifyReply) => {
    if (lifecycle.getState() === 'stopped') {
      return reply.status(503).send({ status: 'stopped' });
    }
    return reply.status(200).send({ status: 'ok' });
  });

  app.get('/health/ready', async (_req: FastifyRequest, reply: FastifyReply) => {
    if (!lifecycle.isReady()) {
      return reply.status(503).send({
        status: 'unavailable',
        reason: lifecycle.getState(),
      });
    }

    let timer: NodeJS.Timeout | null = null;
    const timeoutPromise = new Promise<{ timeout: true }>((resolve) => {
      timer = setTimeout(() => resolve({ timeout: true }), READINESS_TIMEOUT_MS);
    });

    const checkPromise = Promise.all([
      postgres.checkReadiness(2000),
      redis.checkReadiness(2000),
    ]).then(([pgResult, redisResult]) => ({ timeout: false as const, pgResult, redisResult }));

    let result:
      | { timeout: true }
      | { timeout: false; pgResult: { ok: boolean }; redisResult: { ok: boolean } };
    try {
      result = await Promise.race([checkPromise, timeoutPromise]);
    } finally {
      if (timer) clearTimeout(timer);
    }

    if (result.timeout) {
      return reply.status(503).send({
        status: 'unavailable',
        reason: 'timeout',
      });
    }

    const { pgResult, redisResult } = result;
    const isReady = pgResult.ok && redisResult.ok;

    if (!isReady) {
      return reply.status(503).send({
        status: 'unavailable',
        dependencies: {
          database: pgResult.ok ? 'healthy' : 'unhealthy',
          redis: redisResult.ok ? 'healthy' : 'unhealthy',
        },
      });
    }

    return reply.status(200).send({
      status: 'ready',
      dependencies: {
        database: 'healthy',
        redis: 'healthy',
      },
    });
  });
}
