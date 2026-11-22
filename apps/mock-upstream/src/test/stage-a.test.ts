import fs from 'node:fs';
import path from 'node:path';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createMockHarness, MockTestHarness } from './harness.js';
import { MockServer } from '../server.js';
import { parseMockConfig } from '../config.js';
import { SUCCESS_JSON_FIXTURES } from '../fixtures/success.js';

describe('SW-1.8.1: Deterministic Chat-Completions JSON and SSE Fixtures (Stage A)', () => {
  let harness: MockTestHarness;

  beforeAll(async () => {
    harness = await createMockHarness();
  });

  afterAll(async () => {
    await harness.stop();
  });

  describe('1. Non-streaming JSON fixtures', () => {
    it('1.1 valid non-streaming request returns 200 and OpenAI-compatible JSON', async () => {
      const res = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: [{ role: 'user', content: 'Hello' }],
        stream: false,
      });

      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toBe('application/json; charset=utf-8');

      const data = (await res.json()) as Record<string, unknown>;
      expect(data.id).toBe('chatcmpl-mock-json-basic');
      expect(data.object).toBe('chat.completion');
      expect(data.created).toBe(1700000000);
      expect(data.model).toBe('mock-chat-v1');

      const choices = data.choices as Array<{
        index: number;
        message: { role: string; content: string };
        finish_reason: string;
      }>;
      expect(choices).toHaveLength(1);
      expect(choices[0]?.message.role).toBe('assistant');
      expect(choices[0]?.message.content).toBe('Deterministic mock response.');
      expect(choices[0]?.finish_reason).toBe('stop');

      const usage = data.usage as {
        prompt_tokens: number;
        completion_tokens: number;
        total_tokens: number;
      };
      expect(usage).toEqual({
        prompt_tokens: 12,
        completion_tokens: 8,
        total_tokens: 20,
      });
    });

    it('1.2 repeated requests produce byte-identical bodies across multiple invocations', async () => {
      const res1 = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: [{ role: 'user', content: 'Run 1' }],
        stream: false,
      });
      const text1 = await res1.text();

      const res2 = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: [{ role: 'user', content: 'Run 2' }],
        stream: false,
      });
      const text2 = await res2.text();

      expect(text1).toBe(text2);
      expect(Buffer.from(text1)).toEqual(Buffer.from(text2));
    });

    it('1.3 fixed usage fixture returns exact configured usage tokens', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Testing usage' }],
          stream: false,
        },
        { 'x-test-fixture-id': 'json.fixed-usage' },
      );

      expect(res.status).toBe(200);
      const data = (await res.json()) as Record<string, unknown>;
      expect(data.id).toBe('chatcmpl-mock-json-fixed-usage');
      expect(data.usage).toEqual({
        prompt_tokens: 50,
        completion_tokens: 25,
        total_tokens: 75,
      });
    });

    it('1.4 long-bounded fixture produces deterministic bounded output', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Long request' }],
          stream: false,
        },
        { 'x-test-fixture-id': 'json.long-bounded' },
      );

      expect(res.status).toBe(200);
      const data = (await res.json()) as Record<string, unknown>;
      const choices = data.choices as Array<{
        message: { content: string };
      }>;
      const content = choices[0]?.message.content ?? '';
      expect(content.length).toBeGreaterThan(2000);
      expect(content).toBe(SUCCESS_JSON_FIXTURES['json.long-bounded']?.assistantContent);
    });

    it('1.5 Content-Length header exactly matches body byte length', async () => {
      const res = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: [{ role: 'user', content: 'Header check' }],
        stream: false,
      });

      const contentLengthHeader = res.headers.get('content-length');
      expect(contentLengthHeader).not.toBeNull();
      const rawBytes = await res.arrayBuffer();
      expect(Number(contentLengthHeader)).toBe(rawBytes.byteLength);
    });
  });

  describe('2. Streaming SSE fixtures and timing verification', () => {
    it('2.1 streaming request returns 200 with text/event-stream headers', async () => {
      const res = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: [{ role: 'user', content: 'Stream test' }],
        stream: true,
      });

      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toBe('text/event-stream; charset=utf-8');
      expect(res.headers.get('cache-control')).toBe('no-cache');
    });

    it('2.2 SSE framing is valid, chunks reconstruct text, and ends with [DONE]', async () => {
      const res = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: [{ role: 'user', content: 'Stream test' }],
        stream: true,
      });

      const text = await res.text();
      const events = text
        .split('\n\n')
        .map((e) => e.trim())
        .filter((e) => e.length > 0);

      expect(events.length).toBeGreaterThanOrEqual(4);

      // Verify each event starts with "data: "
      for (const ev of events) {
        expect(ev.startsWith('data: ')).toBe(true);
      }

      // Last event must be [DONE]
      expect(events[events.length - 1]).toBe('data: [DONE]');

      // Parse JSON events
      const jsonEvents = events.slice(0, -1).map((ev) => JSON.parse(ev.slice('data: '.length)));

      // Event 0: role assistant
      expect(jsonEvents[0].choices[0].delta.role).toBe('assistant');

      // Content events reconstruct 'Hello, world!'
      const reconstructed = jsonEvents.map((e) => e.choices[0]?.delta?.content ?? '').join('');
      expect(reconstructed).toBe('Hello, world!');

      // Terminal event has finish_reason = 'stop'
      const terminalEvent = jsonEvents[jsonEvents.length - 1];
      expect(terminalEvent.choices[0].finish_reason).toBe('stop');
    });

    it('2.3 repeated SSE runs produce byte-identical output', async () => {
      const res1 = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: [{ role: 'user', content: 'Run 1' }],
        stream: true,
      });
      const text1 = await res1.text();

      const res2 = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: [{ role: 'user', content: 'Run 2' }],
        stream: true,
      });
      const text2 = await res2.text();

      expect(text1).toBe(text2);
      expect(Buffer.from(text1)).toEqual(Buffer.from(text2));
    });

    it('2.4 sse.multi-chunk emits all chunks deterministically', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Multi chunk' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.multi-chunk' },
      );

      const text = await res.text();
      const events = text
        .split('\n\n')
        .map((e) => e.trim())
        .filter((e) => e.length > 0);

      const jsonEvents = events.slice(0, -1).map((ev) => JSON.parse(ev.slice('data: '.length)));

      const reconstructed = jsonEvents.map((e) => e.choices[0]?.delta?.content ?? '').join('');
      expect(reconstructed).toBe('Chunk 1 Chunk 2 Chunk 3 Chunk 4 Chunk 5');
    });

    it('2.5 TTFT delay is measured at first observable content token', async () => {
      const start = Date.now();
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'TTFT test' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.delayed-ttft' },
      );

      expect(res.status).toBe(200);
      const reader = res.body?.getReader();
      expect(reader).toBeDefined();

      const decoder = new TextDecoder();
      let buffer = '';
      let firstContentTokenTime = 0;

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          if (!firstContentTokenTime && buffer.includes('Delayed')) {
            firstContentTokenTime = Date.now();
          }
        }
      }

      // Assert TTFT was measured at first content token
      expect(firstContentTokenTime).toBeGreaterThan(0);
      const ttftElapsed = firstContentTokenTime - start;
      // Fixture has ttftMs = 30
      expect(ttftElapsed).toBeGreaterThanOrEqual(25);
      expect(buffer).toContain('data: [DONE]');
    });

    it('2.6 inter-chunk delay is exercised between content chunks', async () => {
      const start = Date.now();
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Inter chunk delay' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.delayed-chunks' },
      );

      const text = await res.text();
      const elapsed = Date.now() - start;

      // Fixture has 3 chunks with interChunkMs = 15 -> ~45ms total
      expect(elapsed).toBeGreaterThanOrEqual(30);
      expect(text).toContain('Three');
      expect(text).toContain('data: [DONE]');
    });
  });

  describe('3. Validation, security, and access control', () => {
    it('3.1 rejects malformed JSON with 400 invalid_json', async () => {
      const res = await harness.postChatCompletions('{ invalid json');
      expect(res.status).toBe(400);

      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('invalid_json');
    });

    it('3.2 rejects missing messages parameter with 400 missing_parameter', async () => {
      const res = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: [],
      });
      expect(res.status).toBe(400);

      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('missing_parameter');
    });

    it('3.3 rejects unsupported model with 400 model_not_found', async () => {
      const res = await harness.postChatCompletions({
        model: 'unsupported-model-x',
        messages: [{ role: 'user', content: 'Hello' }],
      });
      expect(res.status).toBe(400);

      const data = (await res.json()) as { error: { code: string; message: string } };
      expect(data.error.code).toBe('model_not_found');
      // Must not reflect untrusted input
      expect(data.error.message).not.toContain('unsupported-model-x');
    });

    it('3.4 rejects unknown fixture ID header with 400 fixture_not_found when authorized', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Hello' }],
        },
        { 'x-test-fixture-id': 'non.existent.fixture' },
      );
      expect(res.status).toBe(400);

      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('fixture_not_found');
    });

    it('3.5 rejects oversized payload > 64KB with 413 payload_too_large', async () => {
      const largeContent = 'x'.repeat(70 * 1024);
      const res = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: [{ role: 'user', content: largeContent }],
      });
      expect(res.status).toBe(413);

      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('payload_too_large');
    });

    it('3.6 client abort stops pending stream and records observation via event polling', async () => {
      await harness.reset();
      const controller = new AbortController();

      try {
        const fetchPromise = harness.postChatCompletions(
          {
            model: 'mock-chat-v1',
            messages: [{ role: 'user', content: 'Abort test' }],
            stream: true,
          },
          { 'x-test-fixture-id': 'sse.delayed-ttft' },
          controller.signal,
        );

        // Abort after 5ms (well before ttftMs = 30ms)
        setTimeout(() => {
          controller.abort();
        }, 5);

        await expect(fetchPromise).rejects.toThrow();

        // Deterministic observation polling (MOCK-05)
        const observations = await harness.waitForObservations(
          (obs) => obs.length >= 1 && obs[obs.length - 1]?.outcome === 'client_abort',
        );
        const lastObs = observations[observations.length - 1];
        expect(lastObs?.outcome).toBe('client_abort');
      } finally {
        controller.abort();
      }
    });

    it('3.7 production profile fails closed at initialization', () => {
      const origEnv = process.env.NODE_ENV;
      try {
        process.env.NODE_ENV = 'production';
        expect(() => new MockServer()).toThrow(
          'Mock upstream server cannot run in production environment (NODE_ENV=production)',
        );
      } finally {
        process.env.NODE_ENV = origEnv;
      }
    });

    it('3.8 server starts and stops cleanly with no dangling handles', async () => {
      const isolatedHarness = await createMockHarness();
      expect(isolatedHarness.port).toBeGreaterThan(0);
      await isolatedHarness.stop();
    });

    // MOCK-01 Access Control Tests
    it('3.9 unauthenticated test-control requests are rejected with 401', async () => {
      // Direct fetch without authorization header
      const res = await fetch(`${harness.url}/__test/abort-observations`);
      expect(res.status).toBe(401);
      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('unauthorized');
    });

    it('3.10 test-control requests with invalid credentials are rejected with 401', async () => {
      const res = await fetch(`${harness.url}/__test/abort-observations`, {
        headers: { 'X-Test-Control-Key': 'wrong-key-value' },
      });
      expect(res.status).toBe(401);
      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('unauthorized');
    });

    it('3.11 unauthorized fixture-selection header x-test-fixture-id is rejected with 401', async () => {
      // Explicitly pass empty control key to test unauthenticated header selection
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Unauthorized test' }],
        },
        {
          'x-test-fixture-id': 'error.500',
          'X-Test-Control-Key': '', // explicitly unauthenticated
        },
      );
      expect(res.status).toBe(401);
      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('unauthorized');
    });

    it('3.12 ordinary mock requests without x-test-fixture-id succeed without authorization', async () => {
      // Standard OpenAI request with no control key
      const res = await fetch(`${harness.url}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Standard caller' }],
        }),
      });
      expect(res.status).toBe(200);
      const data = (await res.json()) as { choices: Array<{ message: { content: string } }> };
      expect(data.choices[0]?.message.content).toBe('Deterministic mock response.');
    });

    // MOCK-02 Listener Accumulation Tests
    it('3.13 50 sequential successful requests do not accumulate shutdown listeners', async () => {
      for (let i = 0; i < 50; i++) {
        const res = await harness.postChatCompletions({
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: `Seq ${i}` }],
          stream: false,
        });
        expect(res.status).toBe(200);
        await res.json();
      }

      // Assert listener count on server shutdown signal is 0
      expect(harness.server.getShutdownListenerCount()).toBe(0);
    });

    it('3.14 50 sequential rejected requests do not accumulate shutdown listeners', async () => {
      for (let i = 0; i < 50; i++) {
        const res = await harness.postChatCompletions('{ invalid json');
        expect(res.status).toBe(400);
      }

      expect(harness.server.getShutdownListenerCount()).toBe(0);
    });

    // MOCK-04 JSON and Model Hardening Tests
    it('3.15 rejects JSON null body with 400 invalid_payload', async () => {
      const res = await harness.postChatCompletions('null');
      expect(res.status).toBe(400);
      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('invalid_payload');
    });

    it('3.16 rejects JSON array body with 400 invalid_payload', async () => {
      const res = await harness.postChatCompletions('[]');
      expect(res.status).toBe(400);
      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('invalid_payload');
    });

    it('3.17 rejects JSON primitive body with 400 invalid_payload', async () => {
      const res = await harness.postChatCompletions('"a primitive string"');
      expect(res.status).toBe(400);
      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('invalid_payload');
    });

    it('3.18 rejects unknown mock-* model with 400 model_not_found without reflection', async () => {
      const res = await harness.postChatCompletions({
        model: 'mock-chat-v2',
        messages: [{ role: 'user', content: 'Testing unknown mock model' }],
      });
      expect(res.status).toBe(400);
      const data = (await res.json()) as { error: { code: string; message: string } };
      expect(data.error.code).toBe('model_not_found');
      expect(data.error.message).not.toContain('mock-chat-v2');
    });

    it('3.19 rejects legacy gpt-4o and gpt-3.5-turbo models with 400 model_not_found', async () => {
      const res = await harness.postChatCompletions({
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'Testing gpt-4o' }],
      });
      expect(res.status).toBe(400);
      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('model_not_found');
    });

    it('3.20 rejects non-object item in messages list with 400 invalid_parameter', async () => {
      const res = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: ['not an object'],
      });
      expect(res.status).toBe(400);
      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('invalid_parameter');
    });

    it('3.21 rejects invalid role in messages list with 400 invalid_parameter', async () => {
      const res = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: [{ role: 'admin_injection', content: 'Hi' }],
      });
      expect(res.status).toBe(400);
      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('invalid_parameter');
    });

    it('3.22 rejects non-string content in messages list with 400 invalid_parameter', async () => {
      const res = await harness.postChatCompletions({
        model: 'mock-chat-v1',
        messages: [{ role: 'user', content: 12345 }],
      });
      expect(res.status).toBe(400);
      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('invalid_parameter');
    });

    // MOCK-06 Compose and Control Secret Configuration Tests
    it('3.23 default configuration generates 64-character hexadecimal control secret', async () => {
      const defaultServer = new MockServer();
      const secret = defaultServer.getControlSecret();
      expect(secret).toMatch(/^[0-9a-f]{64}$/);
    });

    it('3.24 explicit valid 64-hex control secret is accepted', async () => {
      const validSecret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; // gitleaks:allow
      const server = new MockServer({ controlSecret: validSecret });
      expect(server.getControlSecret()).toBe(validSecret);

      const parsed = parseMockConfig({ MOCK_CONTROL_SECRET: validSecret });
      expect(parsed.controlSecret).toBe(validSecret);
    });

    it('3.25 empty or whitespace-only configured secret generates random 64-hex token', async () => {
      const server = new MockServer({ controlSecret: '   ' });
      expect(server.getControlSecret()).toMatch(/^[0-9a-f]{64}$/);

      const parsed = parseMockConfig({ MOCK_CONTROL_SECRET: '   ' });
      expect(parsed.controlSecret).toBe('');
    });

    it('3.26 malformed control secret (short, non-hex, too long) is rejected at configuration time', () => {
      expect(() => parseMockConfig({ MOCK_CONTROL_SECRET: 'short' })).toThrow(
        /Invalid MOCK_CONTROL_SECRET/,
      );
      expect(() => parseMockConfig({ MOCK_CONTROL_SECRET: 'g'.repeat(64) })).toThrow(
        /Invalid MOCK_CONTROL_SECRET/,
      );
      expect(() => parseMockConfig({ MOCK_CONTROL_SECRET: 'a'.repeat(63) })).toThrow(
        /Invalid MOCK_CONTROL_SECRET/,
      );
      expect(() => parseMockConfig({ MOCK_CONTROL_SECRET: 'a'.repeat(65) })).toThrow(
        /Invalid MOCK_CONTROL_SECRET/,
      );
      expect(() => new MockServer({ controlSecret: 'not-valid-hex' })).toThrow(
        /Invalid controlSecret/,
      );
    });

    it('3.27 invalid secret error does not reflect the secret string', () => {
      const sensitiveLeakCandidate = 'my_super_secret_unauthorized_token_value_12345';
      try {
        parseMockConfig({ MOCK_CONTROL_SECRET: sensitiveLeakCandidate });
        expect.unreachable('Should have thrown configuration error');
      } catch (err: unknown) {
        expect(err).toBeInstanceOf(Error);
        expect((err as Error).message).not.toContain(sensitiveLeakCandidate);
      }
    });

    it('3.28 private test client with configured key can select fault fixture', async () => {
      const knownKey = 'a'.repeat(64);
      const customHarness = new MockTestHarness({ controlSecret: knownKey });
      await customHarness.start();

      try {
        const res = await customHarness.postChatCompletions(
          {
            model: 'mock-chat-v1',
            messages: [{ role: 'user', content: 'Fault test with key' }],
          },
          {
            'x-test-fixture-id': 'error.500',
            'X-Test-Control-Key': knownKey,
          },
        );
        expect(res.status).toBe(500);
      } finally {
        await customHarness.stop();
      }
    });

    it('3.29 private test client with configured key can query abort observations', async () => {
      const knownKey = 'b'.repeat(64);
      const customHarness = new MockTestHarness({ controlSecret: knownKey });
      await customHarness.start();

      try {
        const obs = await customHarness.getObservations(knownKey);
        expect(Array.isArray(obs)).toBe(true);
      } finally {
        await customHarness.stop();
      }
    });

    it('3.30 unauthorized client cannot query abort observations or select fixtures', async () => {
      const knownKey = 'c'.repeat(64);
      const customHarness = new MockTestHarness({ controlSecret: knownKey });
      await customHarness.start();

      try {
        // Missing key
        await expect(customHarness.getObservations('')).rejects.toThrow(/401/);

        // Incorrect key
        const wrongKey = 'd'.repeat(64);
        await expect(customHarness.getObservations(wrongKey)).rejects.toThrow(/401/);

        // Unauthorized fixture selection
        const res = await fetch(`${customHarness.url}/v1/chat/completions`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-test-fixture-id': 'error.500',
            'X-Test-Control-Key': wrongKey,
          },
          body: JSON.stringify({
            model: 'mock-chat-v1',
            messages: [{ role: 'user', content: 'Unauthorized fixture selection' }],
          }),
        });
        expect(res.status).toBe(401);
      } finally {
        await customHarness.stop();
      }
    });

    it('3.31 normal chat completions succeed without any control secret', async () => {
      const knownKey = 'e'.repeat(64);
      const customHarness = new MockTestHarness({ controlSecret: knownKey });
      await customHarness.start();

      try {
        // Direct fetch without X-Test-Control-Key or Authorization header
        const res = await fetch(`${customHarness.url}/v1/chat/completions`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: 'mock-chat-v1',
            messages: [{ role: 'user', content: 'Standard request' }],
          }),
        });
        expect(res.status).toBe(200);
        const data = (await res.json()) as { choices: Array<{ message: { content: string } }> };
        expect(data.choices[0]?.message.content).toBe('Deterministic mock response.');
      } finally {
        await customHarness.stop();
      }
    });

    it('3.32 docker-compose.yml forwards MOCK_CONTROL_SECRET and does not publish a host port', () => {
      const candidates = [
        path.resolve(process.cwd(), 'docker-compose.yml'),
        path.resolve(process.cwd(), '../../docker-compose.yml'),
      ];
      const composePath = candidates.find((p) => fs.existsSync(p));
      expect(composePath).toBeDefined();
      const composeContent = fs.readFileSync(composePath!, 'utf8');

      // Locate mock-upstream service block
      const mockServiceMatch = composeContent.match(/mock-upstream:[\s\S]*?(?=\n\s\s\w|$)/);
      expect(mockServiceMatch).toBeDefined();
      const mockServiceBlock = mockServiceMatch?.[0] ?? '';

      // Must forward MOCK_CONTROL_SECRET
      expect(mockServiceBlock).toContain('MOCK_CONTROL_SECRET: ${MOCK_CONTROL_SECRET:-}');

      // Must not publish ports
      expect(mockServiceBlock).not.toMatch(/\bports:/);
    });
  });
});
