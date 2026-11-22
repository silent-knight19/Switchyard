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

  constructor(options: MockServerOptions = {}) {
    this.server = new MockServer({
      port: 0, // ephemeral port for test isolation
      host: '127.0.0.1',
      ...options,
    });
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
    const init: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
      body: typeof body === 'string' ? body : JSON.stringify(body),
      ...(signal !== undefined ? { signal } : {}),
    };
    return fetch(`${this.url}/v1/chat/completions`, init);
  }

  public async getObservations(): Promise<AbortObservation[]> {
    const res = await fetch(`${this.url}/__test/abort-observations`);
    if (!res.ok) throw new Error(`Failed to fetch observations: ${res.status}`);
    const data = (await res.json()) as { observations: AbortObservation[] };
    return data.observations;
  }

  public async reset(): Promise<void> {
    const res = await fetch(`${this.url}/__test/reset`, { method: 'POST' });
    if (!res.ok) throw new Error(`Failed to reset mock harness: ${res.status}`);
  }

  public async setActiveFixture(fixtureId: string): Promise<void> {
    const res = await fetch(`${this.url}/__test/active-fixture`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fixtureId }),
    });
    if (!res.ok) throw new Error(`Failed to set active fixture: ${res.status}`);
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
