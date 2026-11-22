import type { ServerResponse } from 'node:http';
import type {
  ChatCompletionChunk,
  ChatCompletionChunkChoice,
  SseFixture,
} from '../fixtures/types.js';

export function formatSseEvent(data: string | object): string {
  const payload = typeof data === 'string' ? data : JSON.stringify(data);
  return `data: ${payload}\n\n`;
}

export function buildRoleChunk(fixture: SseFixture): ChatCompletionChunk {
  return {
    id: fixture.responseId,
    object: 'chat.completion.chunk',
    created: fixture.created,
    model: fixture.model,
    choices: [
      {
        index: 0,
        delta: {
          role: 'assistant',
        },
        finish_reason: null,
      },
    ],
  };
}

export function buildContentChunk(fixture: SseFixture, content: string): ChatCompletionChunk {
  return {
    id: fixture.responseId,
    object: 'chat.completion.chunk',
    created: fixture.created,
    model: fixture.model,
    choices: [
      {
        index: 0,
        delta: {
          content,
        },
        finish_reason: null,
      },
    ],
  };
}

export function buildTerminalChunk(
  fixture: SseFixture,
  choices: ChatCompletionChunkChoice[] = [
    {
      index: 0,
      delta: {},
      finish_reason: fixture.finishReason,
    },
  ],
): ChatCompletionChunk {
  return {
    id: fixture.responseId,
    object: 'chat.completion.chunk',
    created: fixture.created,
    model: fixture.model,
    choices,
  };
}

export function buildUsageChunk(fixture: SseFixture): ChatCompletionChunk {
  return {
    id: fixture.responseId,
    object: 'chat.completion.chunk',
    created: fixture.created,
    model: fixture.model,
    choices: [],
    usage: {
      prompt_tokens: fixture.usage.prompt_tokens,
      completion_tokens: fixture.usage.completion_tokens,
      total_tokens: fixture.usage.total_tokens,
    },
  };
}

function delay(ms: number, signal?: AbortSignal): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      return reject(new Error('Aborted'));
    }
    const timer = setTimeout(() => {
      resolve();
    }, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        reject(new Error('Aborted'));
      },
      { once: true },
    );
  });
}

export async function sendSseResponse(
  res: ServerResponse,
  fixture: SseFixture,
  abortSignal?: AbortSignal,
): Promise<{ bytesWritten: number; completed: boolean }> {
  let bytesWritten = 0;

  const write = (str: string): boolean => {
    if (res.writableEnded || res.destroyed) return false;
    const buf = Buffer.from(str, 'utf8');
    bytesWritten += buf.length;
    res.write(buf);
    return true;
  };

  try {
    // 1. TTFT delay
    if (fixture.ttftMs > 0) {
      await delay(fixture.ttftMs, abortSignal);
    }

    if (abortSignal?.aborted || res.destroyed) {
      return { bytesWritten, completed: false };
    }

    // 2. Send SSE headers
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    // 3. Initial role chunk
    const roleChunk = formatSseEvent(buildRoleChunk(fixture));
    write(roleChunk);

    // 4. Content chunks with optional inter-chunk delay
    for (const chunk of fixture.chunks) {
      if (fixture.interChunkMs > 0) {
        await delay(fixture.interChunkMs, abortSignal);
      }
      if (abortSignal?.aborted || res.destroyed) {
        return { bytesWritten, completed: false };
      }
      const contentChunk = formatSseEvent(buildContentChunk(fixture, chunk));
      write(contentChunk);
    }

    // 5. Terminal chunk with finish reason
    const terminalChunk = formatSseEvent(buildTerminalChunk(fixture));
    write(terminalChunk);

    // 6. Optional usage-only chunk
    if (fixture.includeUsageTail) {
      const usageChunk = formatSseEvent(buildUsageChunk(fixture));
      write(usageChunk);
    }

    // 7. [DONE] marker
    write('data: [DONE]\n\n');

    if (!res.writableEnded && !res.destroyed) {
      res.end();
    }

    return { bytesWritten, completed: true };
  } catch {
    return { bytesWritten, completed: false };
  }
}
