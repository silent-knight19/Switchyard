import net from 'node:net';
import { MockServer, type MockServerOptions } from '../server.js';
import type { AbortObservation } from '../fixtures/types.js';

export interface RefusedTarget {
  host: string;
  port: number;
  url: string;
}

export class MockTestHarness {
  public readonly server: MockServer;
  public url = '';
  public port = 0;
  public host = '127.0.0.1';
  public controlSecret = '';

  constructor(options: MockServerOptions = {}) {
    this.server = new MockServer({
      port: 0, // ephemeral port for test isolation
      host: '127.0.0.1',
      ...options,
    });
    this.controlSecret = this.server.getControlSecret();
  }

  public async start(): Promise<void> {
    const info = await this.server.start();
    this.port = info.port;
    this.host = info.host;
    this.url = info.url;
  }

  public async stop(): Promise<void> {
    await this.server.stop();
  }

  public async postChatCompletions(
    body: unknown,
    headers: Record<string, string> = {},
    signal?: AbortSignal,
  ): Promise<Response> {
    const requestHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      ...headers,
    };

    // If test fixture is selected and caller hasn't explicitly supplied or omitted auth, attach control key
    if (
      requestHeaders['x-test-fixture-id'] !== undefined &&
      requestHeaders['X-Test-Control-Key'] === undefined &&
      requestHeaders['x-test-control-key'] === undefined &&
      requestHeaders['Authorization'] === undefined &&
      requestHeaders['authorization'] === undefined
    ) {
      requestHeaders['X-Test-Control-Key'] = this.controlSecret;
    }

    const init: RequestInit = {
      method: 'POST',
      headers: requestHeaders,
      body: typeof body === 'string' ? body : JSON.stringify(body),
      ...(signal !== undefined ? { signal } : {}),
    };
    return fetch(`${this.url}/v1/chat/completions`, init);
  }

  public async getObservations(controlKey = this.controlSecret): Promise<AbortObservation[]> {
    const headers: Record<string, string> = {};
    if (controlKey) {
      headers['X-Test-Control-Key'] = controlKey;
    }
    const res = await fetch(`${this.url}/__test/abort-observations`, { headers });
    if (!res.ok) throw new Error(`Failed to fetch observations: ${res.status}`);
    const data = (await res.json()) as { observations: AbortObservation[] };
    return data.observations;
  }

  public async reset(controlKey = this.controlSecret): Promise<void> {
    const headers: Record<string, string> = {};
    if (controlKey) {
      headers['X-Test-Control-Key'] = controlKey;
    }
    const res = await fetch(`${this.url}/__test/reset`, { method: 'POST', headers });
    if (!res.ok) throw new Error(`Failed to reset mock harness: ${res.status}`);
  }

  public async setActiveFixture(fixtureId: string, controlKey = this.controlSecret): Promise<void> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (controlKey) {
      headers['X-Test-Control-Key'] = controlKey;
    }
    const res = await fetch(`${this.url}/__test/active-fixture`, {
      method: 'PUT',
      headers,
      body: JSON.stringify({ fixtureId }),
    });
    if (!res.ok) throw new Error(`Failed to set active fixture: ${res.status}`);
  }

  public async waitForObservations(
    predicate: (obs: AbortObservation[]) => boolean,
    timeoutMs = 1500,
  ): Promise<AbortObservation[]> {
    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      const observations = await this.getObservations();
      if (predicate(observations)) {
        return observations;
      }
      await new Promise((r) => setTimeout(r, 5));
    }
    const finalObservations = await this.getObservations();
    if (predicate(finalObservations)) {
      return finalObservations;
    }
    throw new Error(`Timeout waiting for observations condition after ${timeoutMs}ms`);
  }

  /**
   * Reserves a port on 127.0.0.1 by binding a temporary net.Server and immediately closing it,
   * guaranteeing no server is listening on that port when connected to.
   */
  public static async reserveRefusedTarget(): Promise<RefusedTarget> {
    return new Promise((resolve, reject) => {
      const server = net.createServer();
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as net.AddressInfo;
        const port = addr.port;
        server.close((err) => {
          if (err) return reject(err);
          resolve({
            host: '127.0.0.1',
            port,
            url: `http://127.0.0.1:${port}`,
          });
        });
      });
      server.on('error', reject);
    });
  }
}

export async function createMockHarness(options?: MockServerOptions): Promise<MockTestHarness> {
  const harness = new MockTestHarness(options);
  await harness.start();
  return harness;
}
