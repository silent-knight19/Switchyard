import { MAX_PASSWORD_BYTE_LENGTH, validatePasswordInput } from '../../auth/password.js';

/**
 * Bounded, non-interactive administrator password input for the development demo seeder.
 *
 * The password is accepted only from stdin. Interactive terminals are rejected because no
 * no-echo mechanism is implemented, and command-line arguments are never parsed for secrets.
 * Input is bounded before it can grow into an unbounded buffer, decoded as strict UTF-8, checked
 * against the existing 128-byte password cap and never trimmed or otherwise transformed.
 */

export type SeedPasswordErrorCode =
  | 'INTERACTIVE_STDIN_FORBIDDEN'
  | 'EMPTY_PASSWORD'
  | 'PASSWORD_TOO_LONG'
  | 'INVALID_PASSWORD_ENCODING'
  | 'INVALID_PASSWORD'
  | 'STDIN_READ_FAILED';

export class SeedPasswordError extends Error {
  public readonly code: SeedPasswordErrorCode;

  constructor(code: SeedPasswordErrorCode, message: string) {
    super(message);
    this.name = 'SeedPasswordError';
    this.code = code;
  }
}

export interface PasswordInputStream extends NodeJS.ReadableStream {
  readonly isTTY?: boolean;
  destroy?: (error?: Error) => void;
}

/**
 * Read the administrator password from stdin up to the existing 128-byte UTF-8 cap.
 *
 * A trailing newline is preserved as part of the password; callers must use `printf '%s'` rather
 * than `echo`. Mutable input buffers are cleared on success and failure. The returned JavaScript
 * string cannot be deterministically zeroized, which is documented as a runtime limitation.
 */
export async function readPasswordFromStdin(stream: PasswordInputStream): Promise<string> {
  if (stream.isTTY === true) {
    throw new SeedPasswordError(
      'INTERACTIVE_STDIN_FORBIDDEN',
      'Interactive password input is not supported; pipe the password on stdin',
    );
  }

  const chunks: Buffer[] = [];
  let total = 0;

  try {
    for await (const raw of stream) {
      let chunk: Buffer;
      if (Buffer.isBuffer(raw)) {
        chunk = raw;
      } else if (typeof raw === 'string') {
        chunk = Buffer.from(raw, 'utf8');
      } else {
        throw new SeedPasswordError(
          'INVALID_PASSWORD_ENCODING',
          'Password input must be a byte stream',
        );
      }

      const remaining = MAX_PASSWORD_BYTE_LENGTH - total;
      if (chunk.length > remaining) {
        if (chunk !== raw) chunk.fill(0);
        throw new SeedPasswordError(
          'PASSWORD_TOO_LONG',
          `Password exceeds the maximum allowed length of ${MAX_PASSWORD_BYTE_LENGTH} UTF-8 bytes`,
        );
      }

      // Own a copy so stream buffer reuse cannot mutate the collected password.
      const owned = Buffer.from(chunk);
      if (chunk !== raw) chunk.fill(0);
      chunks.push(owned);
      total += owned.length;
    }

    if (total === 0) {
      throw new SeedPasswordError('EMPTY_PASSWORD', 'Password input must not be empty');
    }

    const combined = Buffer.concat(chunks, total);
    let password: string;
    try {
      password = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(combined);
    } catch {
      throw new SeedPasswordError(
        'INVALID_PASSWORD_ENCODING',
        'Password input is not well-formed UTF-8',
      );
    } finally {
      combined.fill(0);
    }

    try {
      // Reuse the authoritative authentication password validation and byte cap.
      validatePasswordInput(password);
    } catch {
      throw new SeedPasswordError('INVALID_PASSWORD', 'Password input is not acceptable');
    }

    return password;
  } catch (error: unknown) {
    if (error instanceof SeedPasswordError) {
      throw error;
    }
    throw new SeedPasswordError('STDIN_READ_FAILED', 'Failed to read password from stdin');
  } finally {
    for (const chunk of chunks) {
      chunk.fill(0);
    }
  }
}
