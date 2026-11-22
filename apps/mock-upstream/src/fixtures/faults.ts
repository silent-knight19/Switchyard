import type { HttpErrorFixture, NetworkFaultFixture } from './types.js';

export const HTTP_ERROR_FIXTURES: Record<string, HttpErrorFixture> = {
  'error.400': {
    type: 'http_error',
    id: 'error.400',
    statusCode: 400,
    errorBody: {
      error: {
        message: 'Invalid request payload or parameters.',
        type: 'invalid_request_error',
        param: null,
        code: 'invalid_request',
      },
    },
  },
  'error.401': {
    type: 'http_error',
    id: 'error.401',
    statusCode: 401,
    errorBody: {
      error: {
        message: 'Incorrect or invalid API key provided.',
        type: 'authentication_error',
        param: null,
        code: 'invalid_api_key',
      },
    },
  },
  'error.403': {
    type: 'http_error',
    id: 'error.403',
    statusCode: 403,
    errorBody: {
      error: {
        message: 'You do not have permission to access the requested resource.',
        type: 'permission_denied_error',
        param: null,
        code: 'permission_denied',
      },
    },
  },
  'error.422': {
    type: 'http_error',
    id: 'error.422',
    statusCode: 422,
    errorBody: {
      error: {
        message: 'Unprocessable entity in chat completion request.',
        type: 'invalid_request_error',
        param: null,
        code: 'unprocessable_entity',
      },
    },
  },
  'error.429': {
    type: 'http_error',
    id: 'error.429',
    statusCode: 429,
    headers: {
      'Retry-After': '5',
    },
    errorBody: {
      error: {
        message: 'Rate limit exceeded. Please retry after 5 seconds.',
        type: 'rate_limit_error',
        param: null,
        code: 'rate_limit_exceeded',
      },
    },
  },
  'error.500': {
    type: 'http_error',
    id: 'error.500',
    statusCode: 500,
    errorBody: {
      error: {
        message: 'The server experienced an internal upstream error.',
        type: 'server_error',
        param: null,
        code: 'internal_error',
      },
    },
  },
  'error.502': {
    type: 'http_error',
    id: 'error.502',
    statusCode: 502,
    errorBody: {
      error: {
        message: 'Bad gateway encountered by upstream provider.',
        type: 'server_error',
        param: null,
        code: 'bad_gateway',
      },
    },
  },
  'error.503': {
    type: 'http_error',
    id: 'error.503',
    statusCode: 503,
    errorBody: {
      error: {
        message: 'Upstream model service is currently unavailable.',
        type: 'server_error',
        param: null,
        code: 'service_unavailable',
      },
    },
  },
  'error.504': {
    type: 'http_error',
    id: 'error.504',
    statusCode: 504,
    errorBody: {
      error: {
        message: 'Gateway timeout waiting for upstream response.',
        type: 'server_error',
        param: null,
        code: 'gateway_timeout',
      },
    },
  },
};

export const NETWORK_FAULT_FIXTURES: Record<string, NetworkFaultFixture> = {
  'fault.connection-reset-before-headers': {
    type: 'network_fault',
    id: 'fault.connection-reset-before-headers',
    faultType: 'connection_reset_before_headers',
  },
  'fault.connection-reset-after-headers': {
    type: 'network_fault',
    id: 'fault.connection-reset-after-headers',
    faultType: 'connection_reset_after_headers',
  },
  'fault.connection-reset-mid-body': {
    type: 'network_fault',
    id: 'fault.connection-reset-mid-body',
    faultType: 'connection_reset_mid_body',
  },
  'fault.ttft-hang': {
    type: 'network_fault',
    id: 'fault.ttft-hang',
    faultType: 'ttft_hang',
  },
  'fault.mid-stream-drop': {
    type: 'network_fault',
    id: 'fault.mid-stream-drop',
    faultType: 'mid_stream_drop',
  },
};
