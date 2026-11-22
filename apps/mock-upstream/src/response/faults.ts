import type { ServerResponse } from 'node:http';
import type { HttpErrorFixture, NetworkFaultFixture } from '../fixtures/types.js';

export function sendHttpError(res: ServerResponse, fixture: HttpErrorFixture): number {
  const body = JSON.stringify(fixture.errorBody);
  const buffer = Buffer.from(body, 'utf8');

  res.statusCode = fixture.statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', buffer.length.toString());

  if (fixture.headers) {
    for (const [key, value] of Object.entries(fixture.headers)) {
      res.setHeader(key, value);
    }
  }

  res.end(buffer);
  return buffer.length;
}

export async function executeNetworkFault(
  res: ServerResponse,
  fixture: NetworkFaultFixture,
  abortSignal: AbortSignal,
  onBytesWritten: (bytes: number) => void,
): Promise<void> {
  switch (fixture.faultType) {
    case 'connection_reset_before_headers': {
      res.socket?.destroy();
      throw new Error('CONNECTION_RESET_BEFORE_HEADERS');
    }

    case 'connection_reset_after_headers': {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Transfer-Encoding', 'chunked');
      res.flushHeaders?.();
      await new Promise((r) => setTimeout(r, 5));
      res.socket?.destroy();
      throw new Error('CONNECTION_RESET_AFTER_HEADERS');
    }

    case 'connection_reset_mid_body': {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Transfer-Encoding', 'chunked');
      res.flushHeaders?.();
      const partial = Buffer.from('{"id":"chatcmpl-reset-mid-body","partial":true,', 'utf8');
      await new Promise<void>((resolve) => {
        res.write(partial, () => resolve());
      });
      await new Promise((r) => setTimeout(r, 5));
      onBytesWritten(partial.length);
      res.socket?.destroy();
      throw new Error('CONNECTION_RESET_MID_BODY');
    }

    case 'ttft_hang': {
      // Intentionally never send headers or tokens. Wait until client aborts or server terminates.
      return new Promise<void>((_resolve, reject) => {
        if (abortSignal.aborted) {
          return reject(new Error('Aborted'));
        }
        abortSignal.addEventListener(
          'abort',
          () => {
            reject(new Error('Aborted'));
          },
          { once: true },
        );
      });
    }

    case 'mid_stream_drop': {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.flushHeaders?.();

      let written = 0;
      const initialChunk =
        'data: {"id":"chatcmpl-drop","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant"}}]}\n\n';
      const contentChunk =
        'data: {"id":"chatcmpl-drop","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Stream truncated before completion"}}]}\n\n';

      const b1 = Buffer.from(initialChunk, 'utf8');
      const b2 = Buffer.from(contentChunk, 'utf8');

      await new Promise<void>((resolve) => {
        res.write(b1);
        res.write(b2, () => resolve());
      });
      written = b1.length + b2.length;
      onBytesWritten(written);

      await new Promise((r) => setTimeout(r, 5));

      // Abruptly destroy socket without [DONE]
      res.socket?.destroy();
      throw new Error('MID_STREAM_DROP');
    }

    default: {
      const exhaustiveCheck: never = fixture.faultType;
      throw new Error(`Unhandled network fault: ${String(exhaustiveCheck)}`);
    }
  }
}
