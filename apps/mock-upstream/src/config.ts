export interface MockConfig {
  nodeEnv: string;
  port: number;
  host: string;
  maxBodyBytes: number;
  controlSecret: string;
}

const CONTROL_SECRET_HEX_REGEX = /^[0-9a-fA-F]{64}$/;

export function isValidControlSecret(secret: string): boolean {
  return CONTROL_SECRET_HEX_REGEX.test(secret);
}

export function parseMockConfig(env: Record<string, string | undefined> = process.env): MockConfig {
  const nodeEnv = env['NODE_ENV'] ?? 'development';

  if (nodeEnv === 'production') {
    throw new Error(
      'Mock upstream server cannot run in production environment (NODE_ENV=production)',
    );
  }

  const port = env['MOCK_PORT']
    ? Number(env['MOCK_PORT'])
    : env['PORT']
      ? Number(env['PORT'])
      : 4000;
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`Invalid PORT or MOCK_PORT: ${port}`);
  }

  const host = env['MOCK_HOST'] ?? env['HOST'] ?? '127.0.0.1';
  const maxBodyBytes = 64 * 1024; // 64KB bounded limit

  const rawSecret = env['MOCK_CONTROL_SECRET'];
  let controlSecret = '';
  if (rawSecret !== undefined && rawSecret.trim().length > 0) {
    const trimmed = rawSecret.trim();
    if (!CONTROL_SECRET_HEX_REGEX.test(trimmed)) {
      throw new Error(
        'Invalid MOCK_CONTROL_SECRET: must be exactly 32 bytes encoded as 64 hexadecimal characters',
      );
    }
    controlSecret = trimmed.toLowerCase();
  }

  return {
    nodeEnv,
    port,
    host,
    maxBodyBytes,
    controlSecret,
  };
}
