import type { ServerResponse } from 'node:http';
import type { ChatCompletionResponse, JsonFixture } from '../fixtures/types.js';

export function buildChatCompletionResponse(fixture: JsonFixture): ChatCompletionResponse {
  return {
    id: fixture.responseId,
    object: 'chat.completion',
    created: fixture.created,
    model: fixture.model,
    choices: [
      {
        index: 0,
        message: {
          role: 'assistant',
          content: fixture.assistantContent,
        },
        finish_reason: fixture.finishReason,
      },
    ],
    usage: {
      prompt_tokens: fixture.usage.prompt_tokens,
      completion_tokens: fixture.usage.completion_tokens,
      total_tokens: fixture.usage.total_tokens,
    },
  };
}

export function serializeChatCompletionResponse(fixture: JsonFixture): string {
  const response = buildChatCompletionResponse(fixture);
  // Deterministic stable JSON serialization
  return JSON.stringify(response);
}

export function sendJsonResponse(res: ServerResponse, fixture: JsonFixture): number {
  const body = serializeChatCompletionResponse(fixture);
  const buffer = Buffer.from(body, 'utf8');

  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', buffer.length.toString());
  res.end(buffer);

  return buffer.length;
}
