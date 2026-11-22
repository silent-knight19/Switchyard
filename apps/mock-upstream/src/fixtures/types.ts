export interface ChatCompletionMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface ChatCompletionUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export interface ChatCompletionChoice {
  index: number;
  message: {
    role: 'assistant';
    content: string;
  };
  finish_reason: string;
}

export interface ChatCompletionResponse {
  id: string;
  object: 'chat.completion';
  created: number;
  model: string;
  choices: ChatCompletionChoice[];
  usage: ChatCompletionUsage;
}

export interface ChatCompletionChunkChoice {
  index: number;
  delta: {
    role?: 'assistant';
    content?: string;
  };
  finish_reason: string | null;
}

export interface ChatCompletionChunk {
  id: string;
  object: 'chat.completion.chunk';
  created: number;
  model: string;
  choices: ChatCompletionChunkChoice[];
  usage?: ChatCompletionUsage | null;
}

export interface JsonFixture {
  type: 'json';
  id: string;
  responseId: string;
  created: number;
  model: string;
  assistantContent: string;
  usage: ChatCompletionUsage;
  finishReason: string;
}

export interface SseFixture {
  type: 'sse';
  id: string;
  responseId: string;
  created: number;
  model: string;
  chunks: string[];
  usage: ChatCompletionUsage;
  finishReason: string;
  ttftMs: number;
  interChunkMs: number;
  includeUsageTail?: boolean;
}

export interface HttpErrorFixture {
  type: 'http_error';
  id: string;
  statusCode: number;
  headers?: Record<string, string>;
  errorBody: {
    error: {
      message: string;
      type: string;
      param: string | null;
      code: string;
    };
  };
}

export interface NetworkFaultFixture {
  type: 'network_fault';
  id: string;
  faultType:
    | 'connection_reset_before_headers'
    | 'connection_reset_after_headers'
    | 'connection_reset_mid_body'
    | 'ttft_hang'
    | 'mid_stream_drop';
}

export interface EdgeCaseFixture {
  type: 'edge_case';
  id: string;
  subType:
    | 'utf8_fragmented'
    | 'frame_fragmented'
    | 'frames_coalesced'
    | 'invalid_json'
    | 'missing_data'
    | 'truncated_json'
    | 'invalid_utf8'
    | 'unterminated_event'
    | 'duplicate_done'
    | 'oversized_line'
    | 'oversized_event'
    | 'malformed_usage';
}

export interface NonSseFixture {
  type: 'non_sse';
  id: string;
  statusCode: number;
  contentType: string;
  body: string | Buffer;
}

export interface CapabilityFixture {
  type: 'capability';
  id: string;
  model: string;
  contextWindow: number;
  maxOutputTokens: number;
  supportsStreaming: boolean;
}

export type Fixture =
  | JsonFixture
  | SseFixture
  | HttpErrorFixture
  | NetworkFaultFixture
  | EdgeCaseFixture
  | NonSseFixture
  | CapabilityFixture;

export interface AbortObservation {
  id: string;
  fixtureId: string;
  model: string;
  stream: boolean;
  outcome: 'completed' | 'client_abort' | 'server_fault' | 'rejected';
  headersSent: boolean;
  bytesWritten: number;
  durationMs: number;
  recordedAt: number;
  error?: string;
}
