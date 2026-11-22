import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createMockHarness, type MockTestHarness } from './harness.js';
import { MockServer } from '../server.js';
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

  describe('2. Streaming SSE fixtures', () => {
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

    it('2.5 TTFT delay is exercised before first token', async () => {
      const start = Date.now();
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'TTFT test' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.delayed-ttft' },
      );

      const text = await res.text();
      const elapsed = Date.now() - start;

      // Fixture has ttftMs = 30
      expect(elapsed).toBeGreaterThanOrEqual(25);
      expect(text).toContain('Delayed');
      expect(text).toContain('data: [DONE]');
    });

    it('2.6 inter-chunk delay is exercised between chunks', async () => {
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

  describe('3. Validation, limits and security', () => {
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

      const data = (await res.json()) as { error: { code: string } };
      expect(data.error.code).toBe('model_not_found');
    });

    it('3.4 rejects unknown fixture ID header with 400 fixture_not_found', async () => {
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

    it('3.6 client abort stops pending stream and records observation', async () => {
      await harness.reset();
      const controller = new AbortController();

      // Initiate request with delayed TTFT and abort before headers are sent
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

      // Small pause to allow server to record close
      await new Promise((r) => setTimeout(r, 40));

      const observations = await harness.getObservations();
      expect(observations.length).toBeGreaterThanOrEqual(1);
      const lastObs = observations[observations.length - 1];
      expect(lastObs?.outcome).toBe('client_abort');
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
  });
});
