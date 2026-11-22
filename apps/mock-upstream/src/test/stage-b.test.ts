import http from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createMockHarness, MockTestHarness, type RefusedTarget } from './harness.js';
import { HTTP_ERROR_FIXTURES } from '../fixtures/faults.js';

describe('SW-1.8.2: Network and HTTP Fault-Injection Profiles (Stage B)', () => {
  let harness: MockTestHarness;

  beforeAll(async () => {
    harness = await createMockHarness();
  });

  afterAll(async () => {
    await harness.stop();
  });

  describe('1. HTTP error profiles (4xx and 5xx)', () => {
    const errorStatuses = [400, 401, 403, 422, 500, 502, 503, 504] as const;

    for (const status of errorStatuses) {
      it(`1.${status} returns exact status ${status} with safe bounded error payload`, async () => {
        const fixtureId = `error.${status}`;
        const res = await harness.postChatCompletions(
          {
            model: 'mock-chat-v1',
            messages: [{ role: 'user', content: `Testing ${fixtureId}` }],
          },
          { 'x-test-fixture-id': fixtureId },
        );

        expect(res.status).toBe(status);
        expect(res.headers.get('content-type')).toBe('application/json; charset=utf-8');

        const expectedFixture = HTTP_ERROR_FIXTURES[fixtureId];
        const body = (await res.json()) as {
          error: { message: string; code: string; type: string };
        };

        expect(body.error.code).toBe(expectedFixture?.errorBody.error.code);
        expect(body.error.message).toBe(expectedFixture?.errorBody.error.message);
        expect(body.error.type).toBe(expectedFixture?.errorBody.error.type);
      });
    }

    it('1.429 returns HTTP 429 with exact Retry-After header and rate-limit payload', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Testing rate limit' }],
        },
        { 'x-test-fixture-id': 'error.429' },
      );

      expect(res.status).toBe(429);
      expect(res.headers.get('retry-after')).toBe('5');

      const body = (await res.json()) as { error: { message: string; code: string; type: string } };
      expect(body.error.code).toBe('rate_limit_exceeded');
      expect(body.error.type).toBe('rate_limit_error');
    });
  });

  describe('2. Connection refusal (transport level)', () => {
    it('2.1 connection refusal is a real transport-level failure, not an HTTP 503', async () => {
      const refused: RefusedTarget = await MockTestHarness.reserveRefusedTarget();

      try {
        await fetch(refused.url);
        expect.unreachable('Connection to closed port should have failed at transport layer');
      } catch (err: unknown) {
        expect(err).toBeInstanceOf(TypeError);
        const errMsg = String(err);
        // Error from fetch on refused port
        expect(errMsg).toMatch(/fetch failed/i);
      }
    });
  });

  describe('3. Connection resets (before, after headers, and mid-body)', () => {
    it('3.1 connection reset before headers causes transport failure and records server_fault', async () => {
      await harness.reset();

      try {
        await harness.postChatCompletions(
          {
            model: 'mock-chat-v1',
            messages: [{ role: 'user', content: 'Reset before headers' }],
          },
          { 'x-test-fixture-id': 'fault.connection-reset-before-headers' },
        );
        expect.unreachable('Socket should have been destroyed before headers');
      } catch (err: unknown) {
        expect(String(err)).toMatch(/terminated|fetch failed/i);
      }

      await new Promise((r) => setTimeout(r, 20));
      const observations = await harness.getObservations();
      const lastObs = observations[observations.length - 1];
      expect(lastObs?.outcome).toBe('server_fault');
      expect(lastObs?.headersSent).toBe(false);
      expect(lastObs?.bytesWritten).toBe(0);
    });

    it('3.2 connection reset after headers is observed as premature close', async () => {
      await harness.reset();

      try {
        const res = await harness.postChatCompletions(
          {
            model: 'mock-chat-v1',
            messages: [{ role: 'user', content: 'Reset after headers' }],
          },
          { 'x-test-fixture-id': 'fault.connection-reset-after-headers' },
        );
        await res.text();
        expect.unreachable('Socket should have been destroyed after headers');
      } catch (err: unknown) {
        expect(String(err)).toMatch(/terminated|fetch failed/i);
      }

      await new Promise((r) => setTimeout(r, 20));
      const observations = await harness.getObservations();
      const lastObs = observations[observations.length - 1];
      expect(lastObs?.outcome).toBe('server_fault');
      expect(lastObs?.headersSent).toBe(true);
    });

    it('3.3 connection reset mid-body emits partial bytes before terminating socket', async () => {
      await harness.reset();

      try {
        const res = await harness.postChatCompletions(
          {
            model: 'mock-chat-v1',
            messages: [{ role: 'user', content: 'Reset mid body' }],
          },
          { 'x-test-fixture-id': 'fault.connection-reset-mid-body' },
        );
        await res.text();
        expect.unreachable('Socket should have been destroyed mid-body');
      } catch (err: unknown) {
        expect(String(err)).toMatch(/terminated|fetch failed/i);
      }

      await new Promise((r) => setTimeout(r, 20));
      const observations = await harness.getObservations();
      const lastObs = observations[observations.length - 1];
      expect(lastObs?.outcome).toBe('server_fault');
      expect(lastObs?.headersSent).toBe(true);
      expect(lastObs?.bytesWritten).toBeGreaterThan(0);
    });
  });

  describe('4. TTFT hang and mid-stream drop', () => {
    it('4.1 TTFT hang emits no tokens and can be aborted cleanly without leaking handlers', async () => {
      await harness.reset();
      const controller = new AbortController();

      const fetchPromise = harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'TTFT hang test' }],
        },
        { 'x-test-fixture-id': 'fault.ttft-hang' },
        controller.signal,
      );

      // Wait 30ms ensuring no headers or tokens have arrived
      await new Promise((r) => setTimeout(r, 30));
      controller.abort();

      await expect(fetchPromise).rejects.toThrow();

      await new Promise((r) => setTimeout(r, 20));
      const observations = await harness.getObservations();
      const lastObs = observations[observations.length - 1];
      expect(lastObs?.outcome).toBe('client_abort');
      expect(lastObs?.headersSent).toBe(false);
      expect(lastObs?.bytesWritten).toBe(0);
    });

    it('4.2 mid-stream drop emits content before abrupt disconnect and never emits [DONE]', async () => {
      await harness.reset();

      // Use raw http.request to inspect received chunks and socket termination
      const receivedChunks: Buffer[] = [];
      let closedPrematurely = false;

      await new Promise<void>((resolve) => {
        const req = http.request(
          {
            hostname: harness.host,
            port: harness.port,
            path: '/v1/chat/completions',
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-test-fixture-id': 'fault.mid-stream-drop',
            },
          },
          (res) => {
            expect(res.statusCode).toBe(200);
            expect(res.headers['content-type']).toContain('text/event-stream');

            res.on('data', (chunk: Buffer) => {
              receivedChunks.push(chunk);
            });

            res.on('close', () => {
              closedPrematurely = true;
              resolve();
            });

            res.on('error', () => {
              closedPrematurely = true;
              resolve();
            });
          },
        );

        req.on('error', () => {
          closedPrematurely = true;
          resolve();
        });

        req.write(
          JSON.stringify({
            model: 'mock-chat-v1',
            messages: [{ role: 'user', content: 'Mid stream drop' }],
            stream: true,
          }),
        );
        req.end();
      });

      expect(closedPrematurely).toBe(true);

      const combinedText = Buffer.concat(receivedChunks).toString('utf8');
      expect(combinedText).toContain('Stream truncated before completion');
      expect(combinedText).not.toContain('data: [DONE]');

      const observations = await harness.getObservations();
      const lastObs = observations[observations.length - 1];
      expect(lastObs?.outcome).toBe('server_fault');
      expect(lastObs?.bytesWritten).toBeGreaterThan(0);
    });
  });

  describe('5. Client-abort observation and lifecycle guarantees', () => {
    it('5.1 successful completion is classified as completed, not client_abort', async () => {
      await harness.reset();

      const res = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: [{ role: 'user', content: 'Normal complete' }],
        stream: false,
      });
      expect(res.status).toBe(200);
      await res.json();

      const observations = await harness.getObservations();
      const lastObs = observations[observations.length - 1];
      expect(lastObs?.outcome).toBe('completed');
    });

    it('5.2 concurrent requests do not corrupt fixture resolution or observation state', async () => {
      await harness.reset();

      const req1 = harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Req 1' }],
        },
        { 'x-test-fixture-id': 'error.401' },
      );

      const req2 = harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Req 2' }],
        },
        { 'x-test-fixture-id': 'error.403' },
      );

      const req3 = harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Req 3' }],
        },
        { 'x-test-fixture-id': 'error.429' },
      );

      const [res1, res2, res3] = await Promise.all([req1, req2, req3]);
      expect(res1?.status).toBe(401);
      expect(res2?.status).toBe(403);
      expect(res3?.status).toBe(429);

      const observations = await harness.getObservations();
      expect(observations.length).toBe(3);
    });

    it('5.3 server shutdown terminates hanging requests cleanly', async () => {
      const isolatedHarness = await createMockHarness();

      // Start a hanging request
      const hangingReq = isolatedHarness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Hang until stop' }],
        },
        { 'x-test-fixture-id': 'fault.ttft-hang' },
      );

      // Give it time to connect
      await new Promise((r) => setTimeout(r, 20));

      // Stop server while hanging request is active
      await isolatedHarness.stop();

      // Request must terminate/reject
      await expect(hangingReq).rejects.toThrow();
    });
  });
});
