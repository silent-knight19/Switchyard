import http from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createMockHarness, type MockTestHarness } from './harness.js';
import { getAllFixtureIds } from '../fixtures/registry.js';

describe('SW-1.8.3: Streaming Protocol Edge-Case Fixtures (Stage C)', () => {
  let harness: MockTestHarness;

  beforeAll(async () => {
    harness = await createMockHarness();
  });

  afterAll(async () => {
    await harness.stop();
  });

  describe('1. Fragmented UTF-8 and SSE framing', () => {
    it('1.1 fragmented UTF-8 cuts across multibyte boundary and reconstructs valid emoji', async () => {
      // Use raw http.request to capture individual socket write chunks
      const chunks: Buffer[] = [];

      await new Promise<void>((resolve, reject) => {
        const req = http.request(
          {
            hostname: harness.host,
            port: harness.port,
            path: '/v1/chat/completions',
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-test-fixture-id': 'sse.utf8-fragmented',
            },
          },
          (res) => {
            expect(res.statusCode).toBe(200);
            res.on('data', (chunk: Buffer) => {
              chunks.push(chunk);
            });
            res.on('end', () => resolve());
            res.on('error', reject);
          },
        );
        req.on('error', reject);
        req.write(
          JSON.stringify({
            model: 'mock-chat-v1',
            messages: [{ role: 'user', content: 'UTF8 frag' }],
            stream: true,
          }),
        );
        req.end();
      });

      // Verify at least two chunks were received (headers/first write, second write)
      expect(chunks.length).toBeGreaterThanOrEqual(2);

      // Verify first chunk ends with first two bytes of '🚀' (0xF0, 0x9F)
      const chunk1 = chunks[0];
      expect(chunk1).toBeDefined();
      const len1 = chunk1?.length ?? 0;
      expect(chunk1?.[len1 - 2]).toBe(0xf0);
      expect(chunk1?.[len1 - 1]).toBe(0x9f);

      // Verify second chunk starts with last two bytes of '🚀' (0x9A, 0x80)
      const chunk2 = chunks[1];
      expect(chunk2).toBeDefined();
      expect(chunk2?.[0]).toBe(0x9a);
      expect(chunk2?.[1]).toBe(0x80);

      // Combined decoded stream must reconstruct the complete emoji text
      const fullText = Buffer.concat(chunks).toString('utf8');
      expect(fullText).toContain('Rocket: 🚀 launch!');
      expect(fullText).toContain('data: [DONE]');
    });

    it('1.2 frame-fragmented splits single SSE event across transport writes', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Frame frag' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.frame-fragmented' },
      );

      const text = await res.text();
      expect(text).toContain('split content');
      expect(text).toContain('data: [DONE]');
    });

    it('1.3 frames-coalesced emits multiple SSE events in a single write', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Coalesced' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.frames-coalesced' },
      );

      const text = await res.text();
      expect(text).toContain('Frame 1');
      expect(text).toContain('Frame 2');
      expect(text).toContain('data: [DONE]');
    });
  });

  describe('2. Usage tail variations', () => {
    it('2.1 sse.usage-tail emits usage-only final chunk with empty choices', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Usage tail' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.usage-tail' },
      );

      const text = await res.text();
      const events = text
        .split('\n\n')
        .map((e) => e.trim())
        .filter((e) => e.length > 0);

      expect(events[events.length - 1]).toBe('data: [DONE]');

      // Penultimate event is usage chunk
      const usageEvent = JSON.parse(events[events.length - 2]?.slice(6) ?? '{}');
      expect(usageEvent.choices).toEqual([]);
      expect(usageEvent.usage).toEqual({
        prompt_tokens: 15,
        completion_tokens: 5,
        total_tokens: 20,
      });
    });

    it('2.2 sse.no-usage-tail omits usage-only chunk before [DONE]', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'No usage tail' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.no-usage-tail' },
      );

      const text = await res.text();
      const events = text
        .split('\n\n')
        .map((e) => e.trim())
        .filter((e) => e.length > 0);

      expect(events[events.length - 1]).toBe('data: [DONE]');

      // Penultimate event is terminal finish chunk, NOT usage chunk
      const terminalEvent = JSON.parse(events[events.length - 2]?.slice(6) ?? '{}');
      expect(terminalEvent.choices[0].finish_reason).toBe('stop');
      expect(terminalEvent.usage).toBeUndefined();
    });
  });

  describe('3. Malformed and edge-case SSE streams', () => {
    it('3.1 sse.invalid-json emits unquoted malformed JSON payload', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Invalid json' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.invalid-json' },
      );

      const text = await res.text();
      expect(text).toContain('invalid_json: unquoted');

      const dataLine = text.split('\n\n')[0]?.slice(6) ?? '';
      expect(() => JSON.parse(dataLine)).toThrow();
    });

    it('3.2 sse.missing-data emits SSE event without data field', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Missing data' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.missing-data' },
      );

      const text = await res.text();
      expect(text).toContain('event: ping');
      expect(text).toContain('id: 1');
      expect(text.split('\n\n')[0]).not.toContain('data:');
    });

    it('3.3 sse.truncated-json emits truncated incomplete JSON', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Truncated' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.truncated-json' },
      );

      const text = await res.text();
      expect(text).toContain('data: {"id":"trunc"');
      expect(() => JSON.parse('{"id":"trunc"')).toThrow();
    });

    it('3.4 sse.invalid-utf8 emits raw invalid UTF-8 bytes', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Bad utf8' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.invalid-utf8' },
      );

      const bytes = Buffer.from(await res.arrayBuffer());
      // Contains [0xC3, 0x28]
      let found = false;
      for (let i = 0; i < bytes.length - 1; i++) {
        if (bytes[i] === 0xc3 && bytes[i + 1] === 0x28) {
          found = true;
          break;
        }
      }
      expect(found).toBe(true);
    });

    it('3.5 sse.unterminated-event emits event without trailing double newline', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Unterminated' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.unterminated-event' },
      );

      const text = await res.text();
      expect(text).toContain('no newlines');
      expect(text.endsWith('\n\n')).toBe(false);
    });

    it('3.6 sse.duplicate-done emits duplicate [DONE] markers', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Duplicate done' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.duplicate-done' },
      );

      const text = await res.text();
      const matches = text.match(/data: \[DONE\]/g);
      expect(matches?.length).toBe(2);
    });

    it('3.7 usage.malformed emits intentionally invalid usage types', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Malformed usage' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'usage.malformed' },
      );

      const text = await res.text();
      expect(text).toContain('"prompt_tokens":-1');
      expect(text).toContain('"completion_tokens":"invalid"');
      expect(text).toContain('"total_tokens":null');
    });
  });

  describe('4. Oversized lines, events and large bodies', () => {
    it('4.1 sse.oversized-line emits line exceeding standard buffer bounds (64KB)', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Oversized line' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.oversized-line' },
      );

      const text = await res.text();
      expect(text.length).toBeGreaterThanOrEqual(65536);
      expect(text).toContain('data: [DONE]');
    });

    it('4.2 sse.oversized-event emits multi-line event spanning 128KB', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Oversized event' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'sse.oversized-event' },
      );

      const text = await res.text();
      expect(text.length).toBeGreaterThanOrEqual(131072);
      expect(text).toContain('data: [DONE]');
    });

    it('4.3 response.large-bounded-body returns 256KB bounded non-streaming body', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Large body' }],
          stream: false,
        },
        { 'x-test-fixture-id': 'response.large-bounded-body' },
      );

      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('application/json');

      const data = (await res.json()) as { choices: Array<{ message: { content: string } }> };
      const content = data.choices[0]?.message.content ?? '';
      expect(content.length).toBe(256 * 1024);
    });
  });

  describe('5. Non-SSE responses and provider capabilities', () => {
    it('5.1 response.non-sse-json returns application/json even for streaming request', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Non sse json' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'response.non-sse-json' },
      );

      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toBe('application/json; charset=utf-8');

      const data = (await res.json()) as { id: string };
      expect(data.id).toBe('chatcmpl-mock-non-sse-json');
    });

    it('5.2 response.non-sse-text returns text/plain error body', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Non sse text' }],
          stream: true,
        },
        { 'x-test-fixture-id': 'response.non-sse-text' },
      );

      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toBe('text/plain; charset=utf-8');

      const text = await res.text();
      expect(text).toBe('Plain text error: upstream protocol error');
    });

    it('5.3 capability.openai-mock returns model capability metadata', async () => {
      const res = await harness.postChatCompletions(
        {
          model: 'mock-chat-v1',
          messages: [{ role: 'user', content: 'Capabilities' }],
        },
        { 'x-test-fixture-id': 'capability.openai-mock' },
      );

      expect(res.status).toBe(200);
      const data = (await res.json()) as {
        model: string;
        context_window: number;
        supports_streaming: boolean;
      };
      expect(data.model).toBe('mock-chat-v1');
      expect(data.context_window).toBe(8192);
      expect(data.supports_streaming).toBe(true);
    });

    it('5.4 every fixture in the registry is selectable via private test controls', async () => {
      const fixtureIds = getAllFixtureIds();
      expect(fixtureIds.length).toBeGreaterThanOrEqual(25);

      // Verify each fixture can be set as active fixture via private control
      for (const id of fixtureIds) {
        await harness.setActiveFixture(id);
      }

      await harness.reset();
    });
  });
});
