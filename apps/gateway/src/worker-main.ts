import fs from 'node:fs';
import { startWorker } from './worker/worker.js';
import { getLogger } from './logging/index.js';

function runHealthCheck(): void {
  const healthFile = process.env.WORKER_HEALTH_FILE || '/tmp/switchyard-worker-health.json';

  try {
    if (!fs.existsSync(healthFile)) {
      process.stderr.write(`Health check failed: health file ${healthFile} not found\n`);
      process.exit(1);
    }

    const content = fs.readFileSync(healthFile, 'utf8');
    const data = JSON.parse(content) as {
      status?: string;
      pid?: number;
      timestamp?: number;
    };

    if (data.status !== 'ready') {
      process.stderr.write(`Health check failed: worker status is "${data.status}"\n`);
      process.exit(1);
    }

    if (!data.timestamp || Date.now() - data.timestamp > 15000) {
      process.stderr.write('Health check failed: worker heartbeat is stale (>15s)\n');
      process.exit(1);
    }

    if (typeof data.pid !== 'number') {
      process.stderr.write('Health check failed: invalid PID in health file\n');
      process.exit(1);
    }

    try {
      // Signal 0 tests process existence without delivering a signal
      process.kill(data.pid, 0);
    } catch {
      process.stderr.write(`Health check failed: worker PID ${data.pid} is not running\n`);
      process.exit(1);
    }

    process.exit(0);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Health check failed: ${msg}\n`);
    process.exit(1);
  }
}

if (process.argv.includes('--health')) {
  runHealthCheck();
} else {
  startWorker().catch((err: unknown) => {
    const logger = getLogger();
    logger.fatal(
      { err: err instanceof Error ? err.message : String(err) },
      'Worker fatal startup failure',
    );
    process.exit(1);
  });
}
