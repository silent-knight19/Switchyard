import type { FastifyReply, FastifyRequest } from 'fastify';
import type pg from 'pg';
import type { AppInstance } from '../app.js';
import type { BrowserPrincipal } from '../auth/authorization.js';
import {
  isValidUuid,
  VirtualKeyManagementError,
  VirtualKeyManagementService,
} from '../auth/virtual-key-management.js';
import { VirtualKeyError } from '../auth/virtual-key.js';
import { InvalidTenantIdError } from '../db/tenant.js';

export interface VirtualKeyRoutesOptions {
  pool: pg.Pool;
  service?: VirtualKeyManagementService;
}

const CONTROL_CHARS_REGEX = /[\u0000-\u001F\u007F-\u009F]/;

function sendErrorReply(reply: FastifyReply, err: unknown): void {
  if (err instanceof VirtualKeyManagementError) {
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
          message: 'Virtual key not found',
        });
        return;
      case 'KEY_REVOKED':
        reply.status(409).send({
          statusCode: 409,
          error: 'Conflict',
          message: 'Cannot update policy of a revoked virtual key',
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

  if (err instanceof VirtualKeyError) {
    if (err.reason === 'INVALID_INPUT') {
      reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: err.message,
      });
      return;
    }
    if (err.reason === 'DATABASE_CONFLICT') {
      reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        message: err.message,
      });
      return;
    }
    reply.status(503).send({
      statusCode: 503,
      error: 'Service Unavailable',
      message: 'Database service unavailable',
    });
    return;
  }

  if (err instanceof InvalidTenantIdError) {
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
    message: 'Database service unavailable',
  });
}

export async function registerVirtualKeyRoutes(
  app: AppInstance,
  options: VirtualKeyRoutesOptions,
): Promise<void> {
  const service = options.service ?? new VirtualKeyManagementService({ pool: options.pool });

  // 1. POST /api/keys — Create virtual API key and disclose plaintext once
  app.post(
    '/api/keys',
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

        // Strict request body validation: must be object with exactly 'name'
        const body = req.body;
        if (!body || typeof body !== 'object' || Array.isArray(body)) {
          return reply.status(400).send({
            statusCode: 400,
            error: 'Bad Request',
            message: 'Invalid request body: expected a non-null JSON object',
          });
        }

        const keys = Object.keys(body as Record<string, unknown>);
        if (keys.length !== 1 || keys[0] !== 'name') {
          return reply.status(400).send({
            statusCode: 400,
            error: 'Bad Request',
            message: 'Invalid request body: only "name" is permitted with no additional fields',
          });
        }

        const rawName = (body as { name?: unknown }).name;
        if (typeof rawName !== 'string') {
          return reply.status(400).send({
            statusCode: 400,
            error: 'Bad Request',
            message: 'Invalid key name: expected string',
          });
        }

        const trimmedName = rawName.trim();
        if (trimmedName.length === 0) {
          return reply.status(400).send({
            statusCode: 400,
            error: 'Bad Request',
            message: 'Invalid key name: name cannot be empty',
          });
        }

        if (Buffer.byteLength(trimmedName, 'utf8') > 255) {
          return reply.status(400).send({
            statusCode: 400,
            error: 'Bad Request',
            message: 'Invalid key name: exceeds maximum 255 UTF-8 bytes',
          });
        }

        if (CONTROL_CHARS_REGEX.test(trimmedName)) {
          return reply.status(400).send({
            statusCode: 400,
            error: 'Bad Request',
            message: 'Invalid key name: control characters are prohibited',
          });
        }

        const result = await service.createKey(orgId, trimmedName);

        reply.header('Cache-Control', 'no-store');
        reply.header('Pragma', 'no-cache');
        return reply.status(201).send(result);
      } catch (err) {
        sendErrorReply(reply, err);
      }
    },
  );

  // 2. GET /api/keys — List organization-owned key metadata
  app.get(
    '/api/keys',
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
        let limit: number | undefined;
        let cursor: string | undefined;

        if (query?.limit !== undefined) {
          const rawLimit = query.limit;
          const parsed = typeof rawLimit === 'number' ? rawLimit : Number(rawLimit);
          if (typeof rawLimit === 'string' && (!/^\d+$/.test(rawLimit.trim()) || isNaN(parsed))) {
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
        return reply.status(200).send(result);
      } catch (err) {
        sendErrorReply(reply, err);
      }
    },
  );

  // 3. PUT /api/keys/:id/policy — Atomically replace complete policy
  app.put(
    '/api/keys/:id/policy',
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

        const params = req.params as { id?: unknown };
        if (!isValidUuid(params.id)) {
          return reply.status(400).send({
            statusCode: 400,
            error: 'Bad Request',
            message: 'Invalid key ID: malformed UUID',
          });
        }
        const keyId = (params.id as string).trim();

        const result = await service.replacePolicy(orgId, keyId, req.body);
        return reply.status(200).send(result);
      } catch (err) {
        sendErrorReply(reply, err);
      }
    },
  );

  // 4. DELETE /api/keys/:id — Revoke key
  app.delete(
    '/api/keys/:id',
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

        const params = req.params as { id?: unknown };
        if (!isValidUuid(params.id)) {
          return reply.status(400).send({
            statusCode: 400,
            error: 'Bad Request',
            message: 'Invalid key ID: malformed UUID',
          });
        }
        const keyId = (params.id as string).trim();

        await service.revokeKey(orgId, keyId);
        return reply.status(204).send();
      } catch (err) {
        sendErrorReply(reply, err);
      }
    },
  );
}
