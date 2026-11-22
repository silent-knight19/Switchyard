import { execFileSync, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseMockConfig } from '../config.js';
import { MockServer } from '../server.js';
import { createMockHarness, type MockTestHarness } from './harness.js';

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address() as net.AddressInfo | null;
      if (!addr) {
        srv.close(() => reject(new Error('Failed to obtain free port')));
        return;
      }
      const port = addr.port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

function resolveDistIndex(): string {
  const rootDir = fs.existsSync(path.resolve(process.cwd(), 'apps'))
    ? process.cwd()
    : path.resolve(process.cwd(), '../..');
  const distFile = path.resolve(rootDir, 'apps/mock-upstream/dist/index.js');

  if (!fs.existsSync(distFile)) {
    // If running in a clean checkout before `pnpm build`, compile mock-upstream on demand
    const tsconfigPath = path.resolve(rootDir, 'apps/mock-upstream/tsconfig.build.json');
    const tscBin = path.resolve(rootDir, 'node_modules/.bin/tsc');
    execFileSync(tscBin, ['-p', tsconfigPath], {
      cwd: rootDir,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  }

  if (!fs.existsSync(distFile)) {
    throw new Error(`Failed to locate or compile entrypoint: ${distFile}`);
  }
  return distFile;
}

function runSubprocess(
  entrypoint: string,
  env: Record<string, string>,
  timeoutMs = 7000,
): Promise<{ code: number | null; stdout: string; stderr: string; signal: string | null }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [entrypoint], {
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (d) => {
      stdout += d.toString('utf8');
    });
    child.stderr.on('data', (d) => {
      stderr += d.toString('utf8');
    });

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
    }, timeoutMs);

    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, signal });
    });
  });
}

describe('SW-1.8.4 Stage D: Production Isolation and Acceptance Suite', () => {
  let harness: MockTestHarness;
  const testSecret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; // gitleaks:allow

  beforeAll(async () => {
    harness = await createMockHarness({ controlSecret: testSecret });
  });

  afterAll(async () => {
    await harness.stop();
  });

  // Group A1: Production Startup Rejection
  describe('8.1 Production Startup Rejection (A1)', () => {
    it('8.1.1 parseMockConfig rejects NODE_ENV=production fail-closed', () => {
      expect(() => parseMockConfig({ NODE_ENV: 'production' })).toThrowError(
        'Mock upstream server cannot run in production environment (NODE_ENV=production)',
      );
    });

    it('8.1.2 MockServer constructor rejects process.env.NODE_ENV=production', () => {
      const origEnv = process.env.NODE_ENV;
      try {
        process.env.NODE_ENV = 'production';
        expect(() => new MockServer()).toThrowError(
          'Mock upstream server cannot run in production environment (NODE_ENV=production)',
        );
      } finally {
        process.env.NODE_ENV = origEnv;
      }
    });

    it('8.1.3 compiled entrypoint rejects NODE_ENV=production in separate process without opening port or exposing secrets', async () => {
      const entrypoint = resolveDistIndex();
      const testPort = await getFreePort();
      const canarySecret =
        'canary_secret_should_never_leak_' + crypto.randomBytes(8).toString('hex');

      const result = await runSubprocess(entrypoint, {
        NODE_ENV: 'production',
        PORT: String(testPort),
        MOCK_CONTROL_SECRET: canarySecret,
      });

      // Must exit with non-zero exit code
      expect(result.code).toBe(1);

      // Must contain expected error message
      expect(result.stderr).toContain(
        'Mock upstream server cannot run in production environment (NODE_ENV=production)',
      );

      // Must NOT leak control secret or canary in stdout or stderr
      expect(result.stdout).not.toContain(canarySecret);
      expect(result.stderr).not.toContain(canarySecret);

      // Must verify that HTTP listener was NEVER opened on testPort (connection refused)
      let connectionFailed = false;
      try {
        await fetch(`http://127.0.0.1:${testPort}/v1/chat/completions`);
      } catch (err: unknown) {
        connectionFailed = true;
        expect((err as Error).message).toMatch(/fetch failed|ECONNREFUSED/i);
      }
      expect(connectionFailed).toBe(true);

      // Must verify that test control route was NEVER accessible
      let controlFailed = false;
      try {
        await fetch(`http://127.0.0.1:${testPort}/__test/abort-observations`);
      } catch (err: unknown) {
        controlFailed = true;
        expect((err as Error).message).toMatch(/fetch failed|ECONNREFUSED/i);
      }
      expect(controlFailed).toBe(true);
    });

    it('8.1.4 compiled entrypoint rejects malformed MOCK_CONTROL_SECRET without echoing secret in error', async () => {
      const entrypoint = resolveDistIndex();
      const testPort = await getFreePort();
      const invalidSecret = 'short_and_invalid_secret_value_123';

      const result = await runSubprocess(entrypoint, {
        NODE_ENV: 'development',
        PORT: String(testPort),
        MOCK_CONTROL_SECRET: invalidSecret,
      });

      expect(result.code).toBe(1);
      expect(result.stderr).toContain(
        'Invalid MOCK_CONTROL_SECRET: must be exactly 32 bytes encoded as 64 hexadecimal characters',
      );
      // Secret must not be echoed in error message
      expect(result.stderr).not.toContain(invalidSecret);
      expect(result.stdout).not.toContain(invalidSecret);
    });

    it('8.1.5 compiled entrypoint starts successfully in development and shuts down cleanly on SIGTERM', async () => {
      const entrypoint = resolveDistIndex();
      const testPort = await getFreePort();
      const validSecret = 'a'.repeat(64);

      const child = spawn(process.execPath, [entrypoint], {
        env: {
          ...process.env,
          NODE_ENV: 'development',
          PORT: String(testPort),
          HOST: '127.0.0.1',
          MOCK_CONTROL_SECRET: validSecret,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      child.stdout.on('data', (d) => {
        stdout += d.toString('utf8');
      });

      // Wait for server to listen
      const startTime = Date.now();
      let listening = false;
      while (Date.now() - startTime < 4000) {
        if (stdout.includes(`Mock upstream server listening on http://127.0.0.1:${testPort}`)) {
          listening = true;
          break;
        }
        await new Promise((r) => setTimeout(r, 50));
      }
      expect(listening).toBe(true);

      // Verify health check succeeds
      const healthRes = await fetch(`http://127.0.0.1:${testPort}/health/ready`);
      expect(healthRes.status).toBe(200);
      const healthData = (await healthRes.json()) as { status: string };
      expect(healthData.status).toBe('ready');

      // Verify control route enforces configured secret
      const unauthControl = await fetch(`http://127.0.0.1:${testPort}/__test/abort-observations`);
      expect(unauthControl.status).toBe(401);

      const authControl = await fetch(`http://127.0.0.1:${testPort}/__test/abort-observations`, {
        headers: { Authorization: `Bearer ${validSecret}` },
      });
      expect(authControl.status).toBe(200);

      // Send SIGTERM and verify graceful shutdown with exit code 0
      const exitPromise = new Promise<{ code: number | null; signal: string | null }>((resolve) => {
        child.on('close', (code, signal) => resolve({ code, signal }));
      });

      child.kill('SIGTERM');
      const exitResult = await exitPromise;
      expect(exitResult.code).toBe(0);

      // Verify port is freed
      let closed = false;
      try {
        await fetch(`http://127.0.0.1:${testPort}/health/ready`);
      } catch {
        closed = true;
      }
      expect(closed).toBe(true);
    });
  });

  // Group A3: Test-Control Route Isolation and Authorization
  describe('8.2 Test-Control Route Isolation and Authorization (A3)', () => {
    it('8.2.1 unauthenticated test-control endpoints return 401 Unauthorized', async () => {
      const endpoints: Array<{ method: string; path: string }> = [
        { method: 'GET', path: '/__test/abort-observations' },
        { method: 'POST', path: '/__test/reset' },
        { method: 'PUT', path: '/__test/active-fixture' },
        { method: 'DELETE', path: '/__test/active-fixture' },
      ];

      for (const ep of endpoints) {
        const init: RequestInit = {
          method: ep.method,
          ...(ep.method === 'PUT'
            ? {
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ fixtureId: 'json.basic' }),
              }
            : {}),
        };
        const res = await fetch(`${harness.url}${ep.path}`, init);
        expect(res.status).toBe(401);
        const data = (await res.json()) as { error: { code: string; message: string } };
        expect(data.error.code).toBe('unauthorized');
        expect(data.error.message).toContain('Unauthorized');
      }
    });

    it('8.2.2 incorrect control credentials return 401 Unauthorized', async () => {
      const wrongSecret = 'b'.repeat(64);
      const res = await fetch(`${harness.url}/__test/abort-observations`, {
        headers: { Authorization: `Bearer ${wrongSecret}` },
      });
      expect(res.status).toBe(401);
      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('unauthorized');
    });

    it('8.2.3 authorized requests succeed with Authorization: Bearer or x-test-control-key', async () => {
      // Via Bearer header
      const resBearer = await fetch(`${harness.url}/__test/abort-observations`, {
        headers: { Authorization: `Bearer ${testSecret}` },
      });
      expect(resBearer.status).toBe(200);

      // Via x-test-control-key header
      const resHeader = await fetch(`${harness.url}/__test/abort-observations`, {
        headers: { 'x-test-control-key': testSecret },
      });
      expect(resHeader.status).toBe(200);
    });

    it('8.2.4 x-test-fixture-id header requires valid control credentials', async () => {
      // Missing control key
      const unauthRes = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'test' }],
        },
        {
          'x-test-fixture-id': 'error.500',
          // Omitting X-Test-Control-Key explicitly
          'X-Test-Control-Key': '',
        },
      );
      expect(unauthRes.status).toBe(401);

      // Correct control key executes requested fault fixture
      const authRes = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'test' }],
        },
        {
          'x-test-fixture-id': 'error.500',
          'X-Test-Control-Key': testSecret,
        },
      );
      expect(authRes.status).toBe(500);
    });

    it('8.2.5 standard completions without control headers succeed with default fixture without secrets', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'hello' }],
        },
        {
          // Explicitly clear test control headers
          'X-Test-Control-Key': '',
          'x-test-control-key': '',
          Authorization: '',
        },
      );
      expect(res.status).toBe(200);
      const data = (await res.json()) as { id: string; object: string };
      expect(data.object).toBe('chat.completion');
      expect(data.id).toMatch(/^chatcmpl-mock-/);
    });

    it('8.2.6 invalid fixture ID returns predictable 400 rejection', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'hello' }],
        },
        {
          'x-test-fixture-id': 'nonexistent.fixture.id',
          'X-Test-Control-Key': testSecret,
        },
      );
      expect(res.status).toBe(400);
      const data = (await res.json()) as { error: { code: string; message: string } };
      expect(data.error.code).toBe('fixture_not_found');
      expect(data.error.message).toContain('Unknown fixture ID');
    });

    it('8.2.7 control secret is never reflected in error messages or responses', async () => {
      const canarySecret = 'a1b2c3d4e5f6'.repeat(5) + '1234'; // gitleaks:allow
      const res = await fetch(`${harness.url}/__test/abort-observations`, {
        headers: { Authorization: `Bearer ${canarySecret}` },
      });
      expect(res.status).toBe(401);
      const text = await res.text();
      expect(text).not.toContain(canarySecret);
      expect(res.headers.get('authorization')).toBeNull();
    });
  });

  // Group B1 & B3: Private Docker Networking and Configuration
  describe('8.3 Docker Compose Private Networking and Configuration (B1, B3)', () => {
    let composeContent: string;

    beforeAll(() => {
      const candidates = [
        path.resolve(process.cwd(), 'docker-compose.yml'),
        path.resolve(process.cwd(), '../../docker-compose.yml'),
      ];
      const composePath = candidates.find((p) => fs.existsSync(p));
      expect(composePath).toBeDefined();
      composeContent = fs.readFileSync(composePath!, 'utf8');
    });

    it('8.3.1 mock-upstream service exists and is attached to switchyard-network', () => {
      expect(composeContent).toContain('mock-upstream:');
      const mockBlock = composeContent.match(/mock-upstream:[\s\S]*?(?=\n\s\s\w|$)/)?.[0] ?? '';
      expect(mockBlock).toContain('switchyard-network');
      expect(mockBlock).toContain('NODE_ENV: development');
    });

    it('8.3.2 mock-upstream has NO published host port (private network boundary)', () => {
      const mockBlock = composeContent.match(/mock-upstream:[\s\S]*?(?=\n\s\s\w|$)/)?.[0] ?? '';
      // Ensure ports block does NOT exist on mock-upstream
      expect(mockBlock).not.toMatch(/\bports:/);
    });

    it('8.3.3 docker-compose forwards MOCK_CONTROL_SECRET without hardcoded secret value', () => {
      const mockBlock = composeContent.match(/mock-upstream:[\s\S]*?(?=\n\s\s\w|$)/)?.[0] ?? '';
      expect(mockBlock).toContain('MOCK_CONTROL_SECRET: ${MOCK_CONTROL_SECRET:-}');
      // No raw 64-hex secret hardcoded
      expect(mockBlock).not.toMatch(/[0-9a-fA-F]{64}/);
    });

    it('8.3.4 gateway, postgres, and redis host ports are strictly loopback-bound (127.0.0.1)', () => {
      const portMappings = composeContent.match(/-\s*["']?127\.0\.0\.1:[^"'\n]+/g) ?? [];
      // At least postgres, redis, and gateway must be bound to 127.0.0.1
      expect(portMappings.length).toBeGreaterThanOrEqual(3);

      // Verify that no 0.0.0.0 port mapping exists
      expect(composeContent).not.toMatch(/-\s*["']?0\.0\.0\.0:/);
    });

    it('8.3.5 Compose service inventory analysis: confirms present vs missing services (P1-01 to P1-06)', () => {
      // Present services
      expect(composeContent).toMatch(/postgres:/);
      expect(composeContent).toMatch(/redis:/);
      expect(composeContent).toMatch(/migrate:/);
      expect(composeContent).toMatch(/gateway:/);
      expect(composeContent).toMatch(/mock-upstream:/);

      // Services absent from compose: worker and web
      expect(composeContent).not.toMatch(/worker:/);
      expect(composeContent).not.toMatch(/web:/);

      // Workspace directory analysis
      const rootDir = fs.existsSync(path.resolve(process.cwd(), 'apps'))
        ? process.cwd()
        : path.resolve(process.cwd(), '../..');

      // apps/web exists as scaffolding only (package.json and tsconfig.json, no executable web app)
      const webPkgPath = path.resolve(rootDir, 'apps/web/package.json');
      expect(fs.existsSync(webPkgPath)).toBe(true);
      const webFiles = fs.readdirSync(path.resolve(rootDir, 'apps/web'));
      expect(webFiles.sort()).toEqual(['package.json', 'tsconfig.json'].sort());

      // apps/worker does NOT exist in filesystem
      const workerDir = path.resolve(rootDir, 'apps/worker');
      expect(fs.existsSync(workerDir)).toBe(false);
    });
  });

  // Group B4 & C5: Container Shutdown and Resource Cleanup
  describe('8.4 Container Shutdown and Resource Cleanup (B4, C5)', () => {
    it('8.4.1 server.stop() destroys active sockets and aborts pending delayed SSE writes', async () => {
      const isolatedHarness = await createMockHarness();
      expect(isolatedHarness.port).toBeGreaterThan(0);

      // Initiate a delayed SSE request
      const controller = new AbortController();
      const sseFetchPromise = isolatedHarness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'test delayed' }],
          stream: true,
        },
        {
          'x-test-fixture-id': 'sse.delayed-chunks',
        },
        controller.signal,
      );

      // Await initial response headers
      const res = await sseFetchPromise;
      expect(res.status).toBe(200);

      // Stop server mid-stream
      await isolatedHarness.stop();

      // Body reader should terminate abruptly because socket was destroyed
      let readerError = false;
      try {
        await res.text();
      } catch {
        readerError = true;
      }
      expect(readerError).toBe(true);

      // Signal listener count must be 0
      expect(isolatedHarness.server.getLastRequestSignalListenerCount()).toBe(0);
      expect(isolatedHarness.server.getShutdownListenerCount()).toBe(0);
    });

    it('8.4.2 client-side abort cleans up listeners and records abort observation', async () => {
      await harness.reset();
      const controller = new AbortController();

      const fetchPromise = harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'test abort' }],
          stream: true,
        },
        {
          'x-test-fixture-id': 'sse.delayed-chunks',
        },
        controller.signal,
      );

      const res = await fetchPromise;
      expect(res.status).toBe(200);

      // Abort client-side while stream is open
      controller.abort();

      try {
        await res.text();
      } catch {
        // Expected abort error
      }

      // Verify abort was observed
      const observations = await harness.waitForObservations((obs) => obs.length > 0);
      expect(observations.length).toBeGreaterThan(0);
      expect(observations[0]?.fixtureId).toBe('sse.delayed-chunks');

      // Verify listeners cleaned up
      expect(harness.server.getLastRequestSignalListenerCount()).toBe(0);
    });
  });

  // Group C1-C4 & A4: Determinism and Seed Restrictions
  describe('8.5 Determinism, Reproducibility and Seed Restrictions (C1-C5, A4)', () => {
    it('8.5.1 JSON completions produce byte-identical responses across repeated calls', async () => {
      const payload = {
        model: 'mock-chat-v1',
        messages: [{ role: 'user', content: 'Hello deterministic mock' }],
      };

      const res1 = await harness.postChatCompletions(payload);
      expect(res1.status).toBe(200);
      const text1 = await res1.text();

      const res2 = await harness.postChatCompletions(payload);
      expect(res2.status).toBe(200);
      const text2 = await res2.text();

      // Byte-identical representation
      expect(text1).toBe(text2);

      const parsed = JSON.parse(text1) as {
        id: string;
        created: number;
        usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
      };
      expect(parsed.id).toBe('chatcmpl-mock-json-basic');
      expect(parsed.created).toBe(1700000000);
      expect(parsed.usage.prompt_tokens).toBe(12);
      expect(parsed.usage.completion_tokens).toBe(8);
      expect(parsed.usage.total_tokens).toBe(20);
    });

    it('8.5.2 SSE streaming produces byte-identical chunk sequence across repeated calls', async () => {
      const payload = {
        model: 'mock-chat-v1',
        messages: [{ role: 'user', content: 'Stream test' }],
        stream: true,
      };

      const res1 = await harness.postChatCompletions(payload);
      expect(res1.status).toBe(200);
      const sseText1 = await res1.text();

      const res2 = await harness.postChatCompletions(payload);
      expect(res2.status).toBe(200);
      const sseText2 = await res2.text();

      expect(sseText1).toBe(sseText2);
      expect(sseText1).toContain('data: [DONE]\n\n');
      expect(sseText1).toContain('chatcmpl-mock-sse-basic');
    });

    it('8.5.3 test fixtures and deterministic responses require no paid credentials or external providers', async () => {
      // Standard completion without any OpenAI API key
      const res = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: [{ role: 'user', content: 'no paid tokens' }],
      });
      expect(res.status).toBe(200);
      const data = (await res.json()) as { choices: Array<{ message: { content: string } }> };
      expect(data.choices[0]?.message.content).toBe('Deterministic mock response.');
    });

    it('8.5.4 confirms absence of demo account seeder or hard-coded production accounts', () => {
      const rootDir = fs.existsSync(path.resolve(process.cwd(), 'apps'))
        ? process.cwd()
        : path.resolve(process.cwd(), '../..');

      // Check PostgreSQL init scripts
      const initScript = path.resolve(rootDir, 'docker/postgres/init/02-init-development.sh');
      expect(fs.existsSync(initScript)).toBe(true);
      const initContent = fs.readFileSync(initScript, 'utf8');

      // The script only configures passwords for database roles (gateway_migrator, gateway_app, etc.)
      // It does NOT insert demo user accounts, orgs, or keys into the database
      expect(initContent).not.toMatch(/INSERT INTO/i);
      expect(initContent).not.toMatch(/demo@/i);
      expect(initContent).not.toMatch(/demo_user/i);
    });
  });
});
