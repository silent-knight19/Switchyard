import { startServer } from './server.js';
import { getLogger } from './logging/index.js';

startServer().catch((err: unknown) => {
  const logger = getLogger();
  logger.fatal({ err }, 'Gateway fatal startup failure');
  process.exit(1);
});
