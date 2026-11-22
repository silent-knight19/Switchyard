export interface MockConfig {
  nodeEnv: string;
  port: number;
  host: string;
  maxBodyBytes: number;
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

  return {
    nodeEnv,
    port,
    host,
    maxBodyBytes,
  };
}
