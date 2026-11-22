import type { CapabilityFixture, EdgeCaseFixture, NonSseFixture } from './types.js';

export const EDGE_CASE_FIXTURES: Record<string, EdgeCaseFixture> = {
  'sse.utf8-fragmented': {
    type: 'edge_case',
    id: 'sse.utf8-fragmented',
    subType: 'utf8_fragmented',
    responseId: 'chatcmpl-mock-utf8-fragmented',
    created: 1700000000,
    model: 'mock-chat-v1',
  },
  'sse.frame-fragmented': {
    type: 'edge_case',
    id: 'sse.frame-fragmented',
    subType: 'frame_fragmented',
    responseId: 'chatcmpl-mock-frame-fragmented',
    created: 1700000000,
    model: 'mock-chat-v1',
  },
  'sse.frames-coalesced': {
    type: 'edge_case',
    id: 'sse.frames-coalesced',
    subType: 'frames_coalesced',
    responseId: 'chatcmpl-mock-frames-coalesced',
    created: 1700000000,
    model: 'mock-chat-v1',
  },
  'sse.usage-tail': {
    type: 'edge_case',
    id: 'sse.usage-tail',
    subType: 'usage_tail',
    responseId: 'chatcmpl-mock-usage-tail',
    created: 1700000000,
    model: 'mock-chat-v1',
    usage: {
      prompt_tokens: 15,
      completion_tokens: 5,
      total_tokens: 20,
    },
  },
  'sse.no-usage-tail': {
    type: 'edge_case',
    id: 'sse.no-usage-tail',
    subType: 'no_usage_tail',
    responseId: 'chatcmpl-mock-no-usage-tail',
    created: 1700000000,
    model: 'mock-chat-v1',
    usage: {
      prompt_tokens: 15,
      completion_tokens: 5,
      total_tokens: 20,
    },
  },
  'sse.invalid-json': {
    type: 'edge_case',
    id: 'sse.invalid-json',
    subType: 'invalid_json',
  },
  'sse.missing-data': {
    type: 'edge_case',
    id: 'sse.missing-data',
    subType: 'missing_data',
  },
  'sse.truncated-json': {
    type: 'edge_case',
    id: 'sse.truncated-json',
    subType: 'truncated_json',
  },
  'sse.invalid-utf8': {
    type: 'edge_case',
    id: 'sse.invalid-utf8',
    subType: 'invalid_utf8',
  },
  'sse.unterminated-event': {
    type: 'edge_case',
    id: 'sse.unterminated-event',
    subType: 'unterminated_event',
  },
  'sse.duplicate-done': {
    type: 'edge_case',
    id: 'sse.duplicate-done',
    subType: 'duplicate_done',
  },
  'sse.oversized-line': {
    type: 'edge_case',
    id: 'sse.oversized-line',
    subType: 'oversized_line',
  },
  'sse.oversized-event': {
    type: 'edge_case',
    id: 'sse.oversized-event',
    subType: 'oversized_event',
  },
  'usage.malformed': {
    type: 'edge_case',
    id: 'usage.malformed',
    subType: 'malformed_usage',
  },
};

const LARGE_BODY_PAYLOAD = JSON.stringify({
  id: 'chatcmpl-mock-large-bounded-body',
  object: 'chat.completion',
  created: 1700000000,
  model: 'mock-chat-v1',
  choices: [
    {
      index: 0,
      message: {
        role: 'assistant',
        content: 'x'.repeat(256 * 1024), // 256KB bounded
      },
      finish_reason: 'stop',
    },
  ],
  usage: {
    prompt_tokens: 20,
    completion_tokens: 65536,
    total_tokens: 65556,
  },
});

export const NON_SSE_FIXTURES: Record<string, NonSseFixture> = {
  'response.non-sse-json': {
    type: 'non_sse',
    id: 'response.non-sse-json',
    statusCode: 200,
    contentType: 'application/json; charset=utf-8',
    body: JSON.stringify({
      id: 'chatcmpl-mock-non-sse-json',
      object: 'chat.completion',
      created: 1700000000,
      model: 'mock-chat-v1',
      choices: [
        {
          index: 0,
          message: {
            role: 'assistant',
            content: 'Unexpected non-streaming JSON body returned for streaming request.',
          },
          finish_reason: 'stop',
        },
      ],
      usage: {
        prompt_tokens: 10,
        completion_tokens: 10,
        total_tokens: 20,
      },
    }),
  },
  'response.non-sse-text': {
    type: 'non_sse',
    id: 'response.non-sse-text',
    statusCode: 200,
    contentType: 'text/plain; charset=utf-8',
    body: 'Plain text error: upstream protocol error',
  },
  'response.large-bounded-body': {
    type: 'non_sse',
    id: 'response.large-bounded-body',
    statusCode: 200,
    contentType: 'application/json; charset=utf-8',
    body: LARGE_BODY_PAYLOAD,
  },
};

export const CAPABILITY_FIXTURES: Record<string, CapabilityFixture> = {
  'capability.openai-mock': {
    type: 'capability',
    id: 'capability.openai-mock',
    model: 'mock-chat-v1',
    contextWindow: 8192,
    maxOutputTokens: 4096,
    supportsStreaming: true,
  },
};
