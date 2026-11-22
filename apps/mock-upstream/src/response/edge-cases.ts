import type { ServerResponse } from 'node:http';
import type { CapabilityFixture, EdgeCaseFixture, NonSseFixture } from '../fixtures/types.js';

export function sendNonSseResponse(res: ServerResponse, fixture: NonSseFixture): number {
  const buffer =
    typeof fixture.body === 'string' ? Buffer.from(fixture.body, 'utf8') : fixture.body;

  res.statusCode = fixture.statusCode;
  res.setHeader('Content-Type', fixture.contentType);
  res.setHeader('Content-Length', buffer.length.toString());
  res.end(buffer);

  return buffer.length;
}

export function sendCapabilityResponse(res: ServerResponse, fixture: CapabilityFixture): number {
  const body = JSON.stringify({
    model: fixture.model,
    context_window: fixture.contextWindow,
    max_output_tokens: fixture.maxOutputTokens,
    supports_streaming: fixture.supportsStreaming,
  });
  const buffer = Buffer.from(body, 'utf8');

  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', buffer.length.toString());
  res.end(buffer);

  return buffer.length;
}

export async function executeEdgeCase(
  res: ServerResponse,
  fixture: EdgeCaseFixture,
  _abortSignal: AbortSignal,
  onBytesWritten: (bytes: number) => void,
): Promise<void> {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  let totalWritten = 0;
  const write = (data: Buffer | string): void => {
    if (res.writableEnded || res.destroyed) return;
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    totalWritten += buf.length;
    res.write(buf);
  };

  switch (fixture.subType) {
    case 'utf8_fragmented': {
      // "Rocket: 🚀 launch!"
      // '🚀' in UTF-8: 0xF0, 0x9F, 0x9A, 0x80
      const prefix = Buffer.from(
        'data: {"id":"chatcmpl-mock-utf8","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Rocket: ',
        'utf8',
      );
      const emojiPart1 = Buffer.from([0xf0, 0x9f]);
      const emojiPart2 = Buffer.from([0x9a, 0x80]);
      const suffix = Buffer.from(' launch!"}}]}\n\n', 'utf8');
      const done = Buffer.from('data: [DONE]\n\n', 'utf8');

      // Write 1: prefix + first half of emoji
      write(Buffer.concat([prefix, emojiPart1]));
      await new Promise<void>((r) => setTimeout(r, 5));
      // Write 2: second half of emoji + suffix
      write(Buffer.concat([emojiPart2, suffix]));
      await new Promise<void>((r) => setTimeout(r, 5));
      // Write 3: [DONE]
      write(done);
      break;
    }

    case 'frame_fragmented': {
      const part1 =
        'data: {"id":"chatcmpl-frag","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"cont';
      const part2 = 'ent":"split content"}}]}\n\n';
      const done = 'data: [DONE]\n\n';

      write(part1);
      await new Promise<void>((r) => setTimeout(r, 5));
      write(part2);
      await new Promise<void>((r) => setTimeout(r, 5));
      write(done);
      break;
    }

    case 'frames_coalesced': {
      const coalesced =
        'data: {"id":"chatcmpl-coal","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Frame 1"}}]}\n\n' +
        'data: {"id":"chatcmpl-coal","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Frame 2"}}]}\n\n';
      const done = 'data: [DONE]\n\n';

      write(coalesced);
      write(done);
      break;
    }

    case 'usage_tail': {
      const c1 =
        'data: {"id":"chatcmpl-mock-usage-tail","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"Tail content"},"finish_reason":null}]}\n\n';
      const c2 =
        'data: {"id":"chatcmpl-mock-usage-tail","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n';
      const c3 =
        'data: {"id":"chatcmpl-mock-usage-tail","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":15,"completion_tokens":5,"total_tokens":20}}\n\n';
      const done = 'data: [DONE]\n\n';

      write(c1);
      write(c2);
      write(c3);
      write(done);
      break;
    }

    case 'no_usage_tail': {
      const c1 =
        'data: {"id":"chatcmpl-mock-no-usage-tail","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"No tail content"},"finish_reason":null}]}\n\n';
      const c2 =
        'data: {"id":"chatcmpl-mock-no-usage-tail","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n';
      const done = 'data: [DONE]\n\n';

      write(c1);
      write(c2);
      write(done);
      break;
    }

    case 'invalid_json': {
      write('data: {"id":"bad","choices":[{"invalid_json: unquoted\n\n');
      write('data: [DONE]\n\n');
      break;
    }

    case 'missing_data': {
      write('event: ping\nid: 1\n\n');
      write('data: [DONE]\n\n');
      break;
    }

    case 'truncated_json': {
      write('data: {"id":"trunc"\n\n');
      break;
    }

    case 'invalid_utf8': {
      // Invalid UTF-8 sequence [0xC3, 0x28]
      const b1 = Buffer.from('data: {"choices":[{"delta":{"content":"', 'utf8');
      const bad = Buffer.from([0xc3, 0x28]);
      const b2 = Buffer.from('"}]}\n\n', 'utf8');
      write(Buffer.concat([b1, bad, b2]));
      break;
    }

    case 'unterminated_event': {
      // Intentionally missing trailing blank line delimiter \n\n
      write('data: {"id":"unterminated","choices":[{"delta":{"content":"no newlines"}}]}');
      break;
    }

    case 'duplicate_done': {
      write('data: {"choices":[{"delta":{"content":"done test"}}]}\n\n');
      write('data: [DONE]\n\n');
      write('data: [DONE]\n\n');
      break;
    }

    case 'oversized_line': {
      // Intentionally oversized single line exceeding line threshold (65,536 bytes > 32KB limit)
      const padding = 'a'.repeat(65536);
      write(`data: {"id":"oversized-line","choices":[{"delta":{"content":"${padding}"}}]}\n\n`);
      write('data: [DONE]\n\n');
      break;
    }

    case 'oversized_event': {
      // Intentionally oversized event composed of 32 individually bounded lines (each 4KB = 4,096 bytes).
      // Each line is well below the 32KB line threshold.
      // Aggregate event payload is 32 * 4,096 = 131,072 bytes (128KB), exceeding the 64KB event threshold.
      const lineCount = 32;
      const linePadding = 'b'.repeat(4096);
      for (let i = 0; i < lineCount; i++) {
        write(`data: {"line":${i},"chunk":"${linePadding}"}\n`);
      }
      write('\n'); // Single blank line terminates the multi-line event
      write('data: [DONE]\n\n');
      break;
    }

    case 'malformed_usage': {
      write(
        'data: {"choices":[],"usage":{"prompt_tokens":-1,"completion_tokens":"invalid","total_tokens":null}}\n\n',
      );
      write('data: [DONE]\n\n');
      break;
    }

    default: {
      const exhaustiveCheck: never = fixture.subType;
      throw new Error(`Unhandled edge case subType: ${String(exhaustiveCheck)}`);
    }
  }

  onBytesWritten(totalWritten);
  if (!res.writableEnded && !res.destroyed) {
    res.end();
  }
}
