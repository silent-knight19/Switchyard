import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type pg from 'pg';
import type { AppInstance } from '../app.js';
import type { BrowserPrincipal } from '../auth/authorization.js';
import {
  isValidUuid,
  ProviderKeyManagementError,
  ProviderKeyManagementService,
} from '../auth/provider-key-management.js';
import { InvalidTenantIdError } from '../db/tenant.js';
import type { EnvelopeVault } from '../vault/envelope.js';
import { VaultError } from '../vault/errors.js';

export interface ProviderKeyRoutesOptions {
  pool: pg.Pool;
  vault?: EnvelopeVault | undefined;
  service?: ProviderKeyManagementService | undefined;
}

function sendProviderKeyErrorReply(reply: FastifyReply, err: unknown): void {
  reply.header('Cache-Control', 'no-store');
  reply.header('Pragma', 'no-cache');

  if (err instanceof ProviderKeyManagementError) {
    switch (err.reason) {
      case 'INVALID_INPUT':
        reply.status(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message: err.message,
        });
        return;
      case 'KEY_NOT_FOUND':
        reply.status(404).send({
          statusCode: 404,
          error: 'Not Found',
          message: 'Provider key not found',
        });
        return;
      case 'KEY_DISABLED':
        reply.status(409).send({
          statusCode: 409,
          error: 'Conflict',
          message: err.message,
        });
        return;
      case 'VAULT_UNAVAILABLE':
        reply.status(503).send({
          statusCode: 503,
          error: 'Service Unavailable',
          message: 'Provider credential vault is unavailable',
        });
        return;
      case 'AUTHENTICATION_FAILED':
        reply.status(503).send({
          statusCode: 503,
          error: 'Service Unavailable',
          message: 'Provider credential vault authentication failed',
        });
        return;
      case 'DATABASE_ERROR':
      default:
        reply.status(503).send({
          statusCode: 503,
          error: 'Service Unavailable',
          message: 'Database service unavailable',
        });
        return;
    }
  }

  if (err instanceof InvalidTenantIdError) {
    reply.status(400).send({
      statusCode: 400,
      error: 'Bad Request',
      message: err.message,
    });
    return;
  }

  if (err instanceof VaultError) {
    if (err.reason === 'INVALID_INPUT') {
      reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: err.message,
      });
      return;
    }
    reply.status(503).send({
      statusCode: 503,
      error: 'Service Unavailable',
      message: 'Provider credential vault service error',
    });
    return;
  }

  reply.status(503).send({
    statusCode: 503,
    error: 'Service Unavailable',
    message: 'Service unavailable',
  });
}

export async function registerProviderKeyRoutes(
  app: AppInstance,
  options: ProviderKeyRoutesOptions,
): Promise<void> {
  const service =
    options.service ??
    new ProviderKeyManagementService({
      pool: options.pool,
      vault: options.vault,
    });

  await app.register(async (providerApp: FastifyInstance) => {
    providerApp.addHook('onSend', async (_req: FastifyRequest, reply: FastifyReply) => {
      reply.header('Cache-Control', 'no-store');
      reply.header('Pragma', 'no-cache');
    });

    // 1. POST /api/provider-keys — Create an encrypted provider credential
    providerApp.post(
      '/api/provider-keys',
      {
        config: {
          authz: {
            principal: 'browser',
            minRole: 'admin',
          },
        },
      },
      async (req: FastifyRequest, reply: FastifyReply) => {
        try {
          const principal = req.principal as BrowserPrincipal;
          const orgId = principal.orgId;

          // Disallow query parameters
          const query = req.query as Record<string, unknown> | undefined;
          if (query && Object.keys(query).length > 0) {
            reply.header('Cache-Control', 'no-store');
            return reply.status(400).send({
              statusCode: 400,
              error: 'Bad Request',
              message: 'Query parameters are not permitted on this endpoint',
            });
          }

          // Strict request body validation: must be JSON object with exactly provider, label, credential
          const body = req.body;
          if (!body || typeof body !== 'object' || Array.isArray(body)) {
            reply.header('Cache-Control', 'no-store');
            return reply.status(400).send({
              statusCode: 400,
              error: 'Bad Request',
              message: 'Invalid request body: expected a non-null JSON object',
            });
          }

          const bodyRecord = body as Record<string, unknown>;
          const keys = Object.keys(bodyRecord);
          const expectedKeys = new Set(['provider', 'label', 'credential']);
          if (keys.length !== 3 || !keys.every((k) => expectedKeys.has(k))) {
            reply.header('Cache-Control', 'no-store');
            return reply.status(400).send({
              statusCode: 400,
              error: 'Bad Request',
              message:
                'Invalid request body: only "provider", "label", and "credential" are permitted with no additional fields',
            });
          }

          if (typeof bodyRecord.provider !== 'string') {
            reply.header('Cache-Control', 'no-store');
            return reply.status(400).send({
              statusCode: 400,
              error: 'Bad Request',
              message: 'Invalid provider: expected string',
            });
          }

          if (typeof bodyRecord.label !== 'string') {
            reply.header('Cache-Control', 'no-store');
            return reply.status(400).send({
              statusCode: 400,
              error: 'Bad Request',
              message: 'Invalid label: expected string',
            });
          }

          if (typeof bodyRecord.credential !== 'string') {
            reply.header('Cache-Control', 'no-store');
            return reply.status(400).send({
              statusCode: 400,
              error: 'Bad Request',
              message: 'Invalid credential: expected string',
            });
          }

          const result = await service.createKey(orgId, {
            provider: bodyRecord.provider,
            label: bodyRecord.label,
            credential: bodyRecord.credential,
          });

          reply.header('Cache-Control', 'no-store');
          reply.header('Pragma', 'no-cache');
          return reply.status(201).send(result);
        } catch (err) {
          sendProviderKeyErrorReply(reply, err);
        }
      },
    );

    // 2. GET /api/provider-keys — List safe provider credential metadata
    providerApp.get(
      '/api/provider-keys',
      {
        config: {
          authz: {
            principal: 'browser',
            minRole: 'admin',
          },
        },
      },
      async (req: FastifyRequest, reply: FastifyReply) => {
        try {
          const principal = req.principal as BrowserPrincipal;
          const orgId = principal.orgId;

          const query = req.query as Record<string, unknown> | undefined;
          if (query) {
            const allowedQueryParams = new Set(['limit', 'cursor']);
            for (const qKey of Object.keys(query)) {
              if (!allowedQueryParams.has(qKey)) {
                reply.header('Cache-Control', 'no-store');
                return reply.status(400).send({
                  statusCode: 400,
                  error: 'Bad Request',
                  message: `Unexpected query parameter "${qKey}" is not permitted`,
                });
              }
            }
          }

          let limit: number | undefined;
          let cursor: string | undefined;

          if (query?.limit !== undefined) {
            const rawLimit = query.limit;
            const parsed = typeof rawLimit === 'number' ? rawLimit : Number(rawLimit);
            if (typeof rawLimit === 'string' && (!/^\d+$/.test(rawLimit.trim()) || isNaN(parsed))) {
              reply.header('Cache-Control', 'no-store');
              return reply.status(400).send({
                statusCode: 400,
                error: 'Bad Request',
                message: 'Invalid limit: must be a positive integer between 1 and 100',
              });
            }
            if (
              !Number.isFinite(parsed) ||
              !Number.isSafeInteger(parsed) ||
              parsed < 1 ||
              parsed > 100
            ) {
              reply.header('Cache-Control', 'no-store');
              return reply.status(400).send({
                statusCode: 400,
                error: 'Bad Request',
                message: 'Invalid limit: must be a positive integer between 1 and 100',
              });
            }
            limit = parsed;
          }

          if (query?.cursor !== undefined) {
            if (typeof query.cursor !== 'string' || query.cursor.trim().length === 0) {
              reply.header('Cache-Control', 'no-store');
              return reply.status(400).send({
                statusCode: 400,
                error: 'Bad Request',
                message: 'Invalid cursor: malformed cursor',
              });
            }
            cursor = query.cursor.trim();
          }

          const listOptions: { limit?: number; cursor?: string } = {};
          if (limit !== undefined) {
            listOptions.limit = limit;
          }
          if (cursor !== undefined) {
            listOptions.cursor = cursor;
          }

          const result = await service.listKeys(orgId, listOptions);
          reply.header('Cache-Control', 'no-store');
          reply.header('Pragma', 'no-cache');
          return reply.status(200).send(result);
        } catch (err) {
          sendProviderKeyErrorReply(reply, err);
        }
      },
    );

    // 3. PUT /api/provider-keys/:id — Atomically replace a provider credential
    providerApp.put(
      '/api/provider-keys/:id',
      {
        config: {
          authz: {
            principal: 'browser',
            minRole: 'admin',
          },
        },
      },
      async (req: FastifyRequest, reply: FastifyReply) => {
        try {
          const principal = req.principal as BrowserPrincipal;
          const orgId = principal.orgId;

          // Disallow query parameters
          const query = req.query as Record<string, unknown> | undefined;
          if (query && Object.keys(query).length > 0) {
            reply.header('Cache-Control', 'no-store');
            return reply.status(400).send({
              statusCode: 400,
              error: 'Bad Request',
              message: 'Query parameters are not permitted on this endpoint',
            });
          }

          const params = req.params as { id?: unknown };
          if (!isValidUuid(params.id)) {
            reply.header('Cache-Control', 'no-store');
            return reply.status(400).send({
              statusCode: 400,
              error: 'Bad Request',
              message: 'Invalid key ID: malformed UUID',
            });
          }
          const keyId = (params.id as string).trim();

          // Strict request body validation: exactly label and credential
          const body = req.body;
          if (!body || typeof body !== 'object' || Array.isArray(body)) {
            reply.header('Cache-Control', 'no-store');
            return reply.status(400).send({
              statusCode: 400,
              error: 'Bad Request',
              message: 'Invalid request body: expected a non-null JSON object',
            });
          }

          const bodyRecord = body as Record<string, unknown>;
          const keys = Object.keys(bodyRecord);
          const expectedKeys = new Set(['label', 'credential']);
          if (keys.length !== 2 || !keys.every((k) => expectedKeys.has(k))) {
            reply.header('Cache-Control', 'no-store');
            return reply.status(400).send({
              statusCode: 400,
              error: 'Bad Request',
              message:
                'Invalid request body: only "label" and "credential" are permitted with no additional fields',
            });
          }

          if (typeof bodyRecord.label !== 'string') {
            reply.header('Cache-Control', 'no-store');
            return reply.status(400).send({
              statusCode: 400,
              error: 'Bad Request',
              message: 'Invalid label: expected string',
            });
          }

          if (typeof bodyRecord.credential !== 'string') {
            reply.header('Cache-Control', 'no-store');
            return reply.status(400).send({
              statusCode: 400,
              error: 'Bad Request',
              message: 'Invalid credential: expected string',
            });
          }

          const result = await service.replaceKey(orgId, keyId, {
            label: bodyRecord.label,
            credential: bodyRecord.credential,
          });

          reply.header('Cache-Control', 'no-store');
          reply.header('Pragma', 'no-cache');
          return reply.status(200).send(result);
        } catch (err) {
          sendProviderKeyErrorReply(reply, err);
        }
      },
    );

    // 4. DELETE /api/provider-keys/:id — Disable an existing provider credential
    providerApp.delete(
      '/api/provider-keys/:id',
      {
        config: {
          authz: {
            principal: 'browser',
            minRole: 'admin',
          },
        },
      },
      async (req: FastifyRequest, reply: FastifyReply) => {
        try {
          const principal = req.principal as BrowserPrincipal;
          const orgId = principal.orgId;

          // Disallow query parameters
          const query = req.query as Record<string, unknown> | undefined;
          if (query && Object.keys(query).length > 0) {
            reply.header('Cache-Control', 'no-store');
            return reply.status(400).send({
              statusCode: 400,
              error: 'Bad Request',
              message: 'Query parameters are not permitted on this endpoint',
            });
          }

          const params = req.params as { id?: unknown };
          if (!isValidUuid(params.id)) {
            reply.header('Cache-Control', 'no-store');
            return reply.status(400).send({
              statusCode: 400,
              error: 'Bad Request',
              message: 'Invalid key ID: malformed UUID',
            });
          }
          const keyId = (params.id as string).trim();

          await service.disableKey(orgId, keyId);

          reply.header('Cache-Control', 'no-store');
          reply.header('Pragma', 'no-cache');
          return reply.status(204).send();
        } catch (err) {
          sendProviderKeyErrorReply(reply, err);
        }
      },
    );
  });
}
