import { createMockServer } from './server.js';
import { parseMockConfig } from './config.js';

async function main(): Promise<void> {
  const config = parseMockConfig();
  const server = await createMockServer({
    port: config.port,
    host: config.host,
  });

  console.log(`Mock upstream server listening on ${server.getUrl()}`);

  const shutdown = async (): Promise<void> => {
    console.log('Shutting down mock upstream server...');
    await server.stop();
    process.exit(0);
  };

  process.on('SIGINT', () => {
    void shutdown();
  });
  process.on('SIGTERM', () => {
    void shutdown();
  });
}

main().catch((err: unknown) => {
  console.error('Fatal error starting mock upstream server:', err);
  process.exit(1);
});
