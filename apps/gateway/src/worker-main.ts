import { runHealthCheck, startWorker } from './worker/worker.js';
import { getWorkerLogger } from './logging/index.js';

if (process.argv.includes('--health')) {
  runHealthCheck();
} else {
  startWorker().catch((err: unknown) => {
    const logger = getWorkerLogger();
    logger.fatal(
      { err: err instanceof Error ? err : new Error(String(err)) },
      'Worker fatal startup failure',
    );
    process.exit(1);
  });
}
