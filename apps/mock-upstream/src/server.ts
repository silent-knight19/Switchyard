import crypto from 'node:crypto';
import events from 'node:events';
import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import type { Socket } from 'node:net';
import { parseMockConfig } from './config.js';
import { getFixture, hasFixture } from './fixtures/registry.js';
import type { AbortObservation, Fixture } from './fixtures/types.js';
import { sendJsonResponse } from './response/json.js';
import { sendSseResponse } from './response/sse.js';
import { sendHttpError, executeNetworkFault } from './response/faults.js';
import {
  executeEdgeCase,
  sendNonSseResponse,
  sendCapabilityResponse,
} from './response/edge-cases.js';

export interface MockServerOptions {
  port?: number;
  host?: string;
  defaultFixture?: string;
  allowHeaderSelection?: boolean;
  controlSecret?: string;
}

const MAX_OBSERVATIONS = 100;
const SUPPORTED_MODELS = new Set(['mock-chat-v1']);
const VALID_ROLES = new Set(['system', 'user', 'assistant']);

export class MockServer {
  private readonly server: http.Server;
  private readonly config = parseMockConfig();
  private readonly activeSockets = new Set<Socket>();
  private readonly observations: AbortObservation[] = [];
  private readonly shutdownController = new AbortController();
  private readonly controlSecret: string;
  private lastRequestAbortSignal?: AbortSignal;
  private activeFixtureOverride: string | null = null;
  private defaultFixture: string;
  private readonly allowHeaderSelection: boolean;
  private running = false;
  private port = 0;
  private host = '127.0.0.1';

  constructor(options: MockServerOptions = {}) {
    // Production fail-closed check
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        'Mock upstream server cannot run in production environment (NODE_ENV=production)',
      );
    }

    this.defaultFixture = options.defaultFixture ?? 'json.basic';
    this.allowHeaderSelection = options.allowHeaderSelection ?? true;
    this.host = options.host ?? this.config.host;
    this.port = options.port ?? this.config.port;

    const CONTROL_SECRET_HEX_REGEX = /^[0-9a-fA-F]{64}$/;
    if (options.controlSecret !== undefined) {
      const explicit = options.controlSecret.trim();
      if (explicit.length > 0) {
        if (!CONTROL_SECRET_HEX_REGEX.test(explicit)) {
          throw new Error(
            'Invalid controlSecret: must be exactly 32 bytes encoded as 64 hexadecimal characters',
          );
        }
        this.controlSecret = explicit.toLowerCase();
      } else {
        this.controlSecret = crypto.randomBytes(32).toString('hex');
      }
    } else if (this.config.controlSecret) {
      this.controlSecret = this.config.controlSecret;
    } else {
      this.controlSecret = crypto.randomBytes(32).toString('hex');
    }

    this.server = http.createServer((req, res) => {
      this.handleRequest(req, res).catch(() => {
        if (!res.headersSent && !res.destroyed) {
          res.statusCode = 500;
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              error: {
                message: 'Internal mock server error',
                type: 'server_error',
                param: null,
                code: 'internal_error',
              },
            }),
          );
        }
      });
    });

    this.server.on('connection', (socket) => {
      this.activeSockets.add(socket);
      socket.on('close', () => {
        this.activeSockets.delete(socket);
      });
    });
  }

  public async start(): Promise<{ port: number; host: string; url: string }> {
    return new Promise((resolve, reject) => {
      this.server.listen(this.port, this.host, () => {
        const addr = this.server.address();
        if (typeof addr === 'object' && addr !== null) {
          this.port = addr.port;
          this.host = addr.address;
        }
        this.running = true;
        resolve({
          port: this.port,
          host: this.host,
          url: `http://${this.host}:${this.port}`,
        });
      });
      this.server.on('error', reject);
    });
  }

  public async stop(): Promise<void> {
    if (!this.running) return;
    this.running = false;
    this.shutdownController.abort();

    // Destroy active sockets
    for (const socket of this.activeSockets) {
      socket.destroy();
    }
    this.activeSockets.clear();

    return new Promise((resolve, reject) => {
      this.server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  public getPort(): number {
    return this.port;
  }

  public getUrl(): string {
    return `http://${this.host}:${this.port}`;
  }

  public getControlSecret(): string {
    return this.controlSecret;
  }

  public getShutdownListenerCount(): number {
    return events.getEventListeners(this.shutdownController.signal, 'abort').length;
  }

  public getLastRequestSignalListenerCount(): number {
    return this.lastRequestAbortSignal
      ? events.getEventListeners(this.lastRequestAbortSignal, 'abort').length
      : 0;
  }

  public setActiveFixture(fixtureId: string | null): void {
    if (fixtureId !== null && !hasFixture(fixtureId)) {
      throw new Error(`Unknown fixture ID: ${fixtureId}`);
    }
    this.activeFixtureOverride = fixtureId;
  }

  public setDefaultFixture(fixtureId: string): void {
    if (!hasFixture(fixtureId)) {
      throw new Error(`Unknown fixture ID: ${fixtureId}`);
    }
    this.defaultFixture = fixtureId;
  }

  public getObservations(): AbortObservation[] {
    return [...this.observations];
  }

  public clearObservations(): void {
    this.observations.length = 0;
  }

  private isAuthorized(req: IncomingMessage): boolean {
    const authHeader = req.headers['authorization'];
    const controlKeyHeader = req.headers['x-test-control-key'];

    let providedKey = '';
    if (typeof controlKeyHeader === 'string') {
      providedKey = controlKeyHeader.trim();
    } else if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
      providedKey = authHeader.slice(7).trim();
    }

    if (!providedKey || !this.controlSecret) {
      return false;
    }

    const providedBuf = Buffer.from(providedKey, 'utf8');
    const expectedBuf = Buffer.from(this.controlSecret, 'utf8');
    if (providedBuf.length !== expectedBuf.length) {
      return false;
    }
    return crypto.timingSafeEqual(providedBuf, expectedBuf);
  }

  private recordObservation(observation: AbortObservation): void {
    if (this.observations.length >= MAX_OBSERVATIONS) {
      this.observations.shift();
    }
    this.observations.push(observation);
  }

  private async readRequestBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const contentLength = Number(req.headers['content-length'] ?? 0);
      if (contentLength > this.config.maxBodyBytes) {
        req.resume();
        reject(new Error('PAYLOAD_TOO_LARGE'));
        return;
      }

      const chunks: Buffer[] = [];
      let totalBytes = 0;
      let exceeded = false;

      req.on('data', (chunk: Buffer) => {
        if (exceeded) return;
        totalBytes += chunk.length;
        if (totalBytes > this.config.maxBodyBytes) {
          exceeded = true;
          req.resume();
          reject(new Error('PAYLOAD_TOO_LARGE'));
          return;
        }
        chunks.push(chunk);
      });

      req.on('end', () => {
        if (!exceeded) {
          resolve(Buffer.concat(chunks).toString('utf8'));
        }
      });

      req.on('error', reject);
    });
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = req.url ?? '/';
    const method = req.method ?? 'GET';

    // Health check
    if (url === '/health/ready' && method === 'GET') {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ status: 'ready' }));
      return;
    }

    // Private test control routes
    if (url.startsWith('/__test/')) {
      await this.handleTestControl(url, method, req, res);
      return;
    }

    // OpenAI Chat Completions API
    if (url === '/v1/chat/completions' && method === 'POST') {
      await this.handleChatCompletions(req, res);
      return;
    }

    res.statusCode = 404;
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        error: {
          message: `Unknown path: ${url}`,
          type: 'invalid_request_error',
          param: null,
          code: 'resource_not_found',
        },
      }),
    );
  }

  private async handleTestControl(
    url: string,
    method: string,
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    if (!this.isAuthorized(req)) {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          error: {
            message: 'Unauthorized test control request: valid test control key required.',
            type: 'authentication_error',
            param: null,
            code: 'unauthorized',
          },
        }),
      );
      return;
    }

    if (url === '/__test/abort-observations' && method === 'GET') {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ observations: this.getObservations() }));
      return;
    }

    if (url === '/__test/reset' && method === 'POST') {
      this.clearObservations();
      this.activeFixtureOverride = null;
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ reset: true }));
      return;
    }

    if (url === '/__test/active-fixture' && method === 'PUT') {
      const body = await this.readRequestBody(req);
      try {
        const parsed = JSON.parse(body);
        if (typeof parsed?.fixtureId === 'string' && hasFixture(parsed.fixtureId)) {
          this.setActiveFixture(parsed.fixtureId);
          res.statusCode = 200;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ activeFixture: parsed.fixtureId }));
          return;
        }
      } catch {
        // fall through
      }
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          error: {
            message: 'Invalid or unknown fixtureId',
            type: 'invalid_request_error',
            param: 'fixtureId',
            code: 'invalid_parameter',
          },
        }),
      );
      return;
    }

    if (url === '/__test/active-fixture' && method === 'DELETE') {
      this.setActiveFixture(null);
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ activeFixture: null }));
      return;
    }

    res.statusCode = 404;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: { message: 'Not found' } }));
  }

  private async handleChatCompletions(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const startTime = Date.now();
    const requestId = `obs-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
    const abortController = new AbortController();
    this.lastRequestAbortSignal = abortController.signal;

    const onShutdownAbort = (): void => {
      abortController.abort();
    };

    if (this.shutdownController.signal.aborted) {
      abortController.abort();
    } else {
      this.shutdownController.signal.addEventListener('abort', onShutdownAbort, {
        once: true,
      });
    }

    let clientAborted = false;
    let bytesWritten = 0;

    const onClientClose = (): void => {
      if (!res.writableEnded) {
        clientAborted = true;
        abortController.abort();
      }
    };

    try {
      let rawBody = '';
      try {
        rawBody = await this.readRequestBody(req);
      } catch (err: unknown) {
        if (err instanceof Error && err.message === 'PAYLOAD_TOO_LARGE') {
          res.statusCode = 413;
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              error: {
                message: 'Request body exceeds maximum allowed size.',
                type: 'invalid_request_error',
                param: null,
                code: 'payload_too_large',
              },
            }),
          );
          this.recordObservation({
            id: requestId,
            fixtureId: 'none',
            model: 'unknown',
            stream: false,
            outcome: 'rejected',
            headersSent: res.headersSent,
            bytesWritten: 0,
            durationMs: Date.now() - startTime,
            recordedAt: startTime,
            error: 'PAYLOAD_TOO_LARGE',
          });
          return;
        }
        throw err;
      }

      let parsedBody: unknown;
      try {
        parsedBody = JSON.parse(rawBody);
      } catch {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            error: {
              message: 'Invalid JSON in request body.',
              type: 'invalid_request_error',
              param: null,
              code: 'invalid_json',
            },
          }),
        );
        this.recordObservation({
          id: requestId,
          fixtureId: 'none',
          model: 'unknown',
          stream: false,
          outcome: 'rejected',
          headersSent: res.headersSent,
          bytesWritten: 0,
          durationMs: Date.now() - startTime,
          recordedAt: startTime,
          error: 'INVALID_JSON',
        });
        return;
      }

      // Validate request object structure (reject null, primitives, arrays)
      if (typeof parsedBody !== 'object' || parsedBody === null || Array.isArray(parsedBody)) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            error: {
              message: 'Invalid request body: expected a JSON object.',
              type: 'invalid_request_error',
              param: null,
              code: 'invalid_payload',
            },
          }),
        );
        this.recordObservation({
          id: requestId,
          fixtureId: 'none',
          model: 'unknown',
          stream: false,
          outcome: 'rejected',
          headersSent: res.headersSent,
          bytesWritten: 0,
          durationMs: Date.now() - startTime,
          recordedAt: startTime,
          error: 'INVALID_PAYLOAD',
        });
        return;
      }

      const bodyObj = parsedBody as Record<string, unknown>;

      // Validate model against approved allowlist (do not reflect untrusted inputs)
      const modelVal = bodyObj.model;
      if (typeof modelVal !== 'string' || !SUPPORTED_MODELS.has(modelVal)) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            error: {
              message: 'The requested model is not supported by mock upstream.',
              type: 'invalid_request_error',
              param: 'model',
              code: 'model_not_found',
            },
          }),
        );
        this.recordObservation({
          id: requestId,
          fixtureId: 'none',
          model: 'unknown',
          stream: false,
          outcome: 'rejected',
          headersSent: res.headersSent,
          bytesWritten: 0,
          durationMs: Date.now() - startTime,
          recordedAt: startTime,
          error: 'MODEL_NOT_FOUND',
        });
        return;
      }
      const model = modelVal;

      // Validate messages array and its items
      const messages = bodyObj.messages;
      if (!Array.isArray(messages) || messages.length === 0) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            error: {
              message: "Missing or empty required parameter: 'messages'.",
              type: 'invalid_request_error',
              param: 'messages',
              code: 'missing_parameter',
            },
          }),
        );
        this.recordObservation({
          id: requestId,
          fixtureId: 'none',
          model,
          stream: false,
          outcome: 'rejected',
          headersSent: res.headersSent,
          bytesWritten: 0,
          durationMs: Date.now() - startTime,
          recordedAt: startTime,
          error: 'MISSING_MESSAGES',
        });
        return;
      }

      for (const msg of messages) {
        if (
          typeof msg !== 'object' ||
          msg === null ||
          Array.isArray(msg) ||
          typeof msg.role !== 'string' ||
          !VALID_ROLES.has(msg.role) ||
          typeof msg.content !== 'string'
        ) {
          res.statusCode = 400;
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              error: {
                message:
                  "Invalid message in 'messages' list: expected object with valid role and content string.",
                type: 'invalid_request_error',
                param: 'messages',
                code: 'invalid_parameter',
              },
            }),
          );
          this.recordObservation({
            id: requestId,
            fixtureId: 'none',
            model,
            stream: false,
            outcome: 'rejected',
            headersSent: res.headersSent,
            bytesWritten: 0,
            durationMs: Date.now() - startTime,
            recordedAt: startTime,
            error: 'INVALID_MESSAGE_OBJECT',
          });
          return;
        }
      }

      const stream = bodyObj.stream === true;

      // Resolve fixture ID
      let fixtureId: string | undefined;

      // 1. Header selection (requires valid authorization)
      const headerFixture = req.headers['x-test-fixture-id'];
      if (typeof headerFixture === 'string' && headerFixture.length > 0) {
        if (!this.allowHeaderSelection || !this.isAuthorized(req)) {
          res.statusCode = 401;
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              error: {
                message: 'Unauthorized fixture selection: valid test control key required.',
                type: 'authentication_error',
                param: 'x-test-fixture-id',
                code: 'unauthorized',
              },
            }),
          );
          this.recordObservation({
            id: requestId,
            fixtureId: 'none',
            model,
            stream,
            outcome: 'rejected',
            headersSent: res.headersSent,
            bytesWritten: 0,
            durationMs: Date.now() - startTime,
            recordedAt: startTime,
            error: 'UNAUTHORIZED_FIXTURE_SELECTION',
          });
          return;
        }

        if (!hasFixture(headerFixture)) {
          res.statusCode = 400;
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              error: {
                message: `Unknown fixture ID: ${headerFixture}`,
                type: 'invalid_request_error',
                param: 'x-test-fixture-id',
                code: 'fixture_not_found',
              },
            }),
          );
          this.recordObservation({
            id: requestId,
            fixtureId: headerFixture,
            model,
            stream,
            outcome: 'rejected',
            headersSent: res.headersSent,
            bytesWritten: 0,
            durationMs: Date.now() - startTime,
            recordedAt: startTime,
            error: 'FIXTURE_NOT_FOUND',
          });
          return;
        }
        fixtureId = headerFixture;
      }

      // 2. Active fixture override (set by authorized test control)
      if (!fixtureId && this.activeFixtureOverride) {
        fixtureId = this.activeFixtureOverride;
      }

      // 3. Fallback to default fixture or stream/json default
      if (!fixtureId) {
        if (stream && !this.defaultFixture.startsWith('sse.')) {
          fixtureId = 'sse.basic';
        } else if (!stream && this.defaultFixture.startsWith('sse.')) {
          fixtureId = 'json.basic';
        } else {
          fixtureId = this.defaultFixture;
        }
      }

      const fixture = getFixture(fixtureId);
      if (!fixture) {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            error: {
              message: `Resolved fixture not found in registry: ${fixtureId}`,
              type: 'server_error',
              param: null,
              code: 'fixture_resolution_error',
            },
          }),
        );
        return;
      }

      res.on('close', onClientClose);

      try {
        await this.executeFixture(res, fixture, abortController.signal, (bytes) => {
          bytesWritten = bytes;
        });

        if (clientAborted || abortController.signal.aborted) {
          this.recordObservation({
            id: requestId,
            fixtureId,
            model,
            stream,
            outcome: 'client_abort',
            headersSent: res.headersSent,
            bytesWritten,
            durationMs: Date.now() - startTime,
            recordedAt: startTime,
          });
        } else {
          this.recordObservation({
            id: requestId,
            fixtureId,
            model,
            stream,
            outcome: 'completed',
            headersSent: res.headersSent,
            bytesWritten,
            durationMs: Date.now() - startTime,
            recordedAt: startTime,
          });
        }
      } catch (err: unknown) {
        const isAbort = clientAborted || abortController.signal.aborted;
        this.recordObservation({
          id: requestId,
          fixtureId,
          model,
          stream,
          outcome: isAbort ? 'client_abort' : 'server_fault',
          headersSent: res.headersSent,
          bytesWritten,
          durationMs: Date.now() - startTime,
          recordedAt: startTime,
          error: err instanceof Error ? err.message : String(err),
        });
      } finally {
        res.removeListener('close', onClientClose);
      }
    } finally {
      this.shutdownController.signal.removeEventListener('abort', onShutdownAbort);
    }
  }

  protected async executeFixture(
    res: ServerResponse,
    fixture: Fixture,
    abortSignal: AbortSignal,
    onBytesWritten: (bytes: number) => void,
  ): Promise<void> {
    if (fixture.type === 'json') {
      const bytes = sendJsonResponse(res, fixture);
      onBytesWritten(bytes);
      return;
    }

    if (fixture.type === 'sse') {
      const result = await sendSseResponse(res, fixture, abortSignal);
      onBytesWritten(result.bytesWritten);
      return;
    }

    if (fixture.type === 'http_error') {
      const bytes = sendHttpError(res, fixture);
      onBytesWritten(bytes);
      return;
    }

    if (fixture.type === 'network_fault') {
      await executeNetworkFault(res, fixture, abortSignal, onBytesWritten);
      return;
    }

    if (fixture.type === 'edge_case') {
      await executeEdgeCase(res, fixture, abortSignal, onBytesWritten);
      return;
    }

    if (fixture.type === 'non_sse') {
      const bytes = sendNonSseResponse(res, fixture);
      onBytesWritten(bytes);
      return;
    }

    if (fixture.type === 'capability') {
      const bytes = sendCapabilityResponse(res, fixture);
      onBytesWritten(bytes);
      return;
    }

    const exhaustiveCheck: never = fixture;
    throw new Error(`Unhandled fixture: ${JSON.stringify(exhaustiveCheck)}`);
  }
}

export async function createMockServer(options?: MockServerOptions): Promise<MockServer> {
  const server = new MockServer(options);
  await server.start();
  return server;
}
