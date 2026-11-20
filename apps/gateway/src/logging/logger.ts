import pino from 'pino';
import { REDACTION_PATHS, CENSOR_VALUE, deepRedact } from './redaction.js';
import { safeErrorSerializer, safeReqSerializer, safeResSerializer } from './serializers.js';

export interface CreateLoggerOptions {
  level?: string;
  stream?: pino.DestinationStream;
  serviceName?: string;
  environment?: string;
}

export function createLogger(options: CreateLoggerOptions = {}): pino.Logger {
  const {
    level = process.env.LOG_LEVEL ?? (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
    stream,
    serviceName = '@switchyard/gateway',
    environment = process.env.NODE_ENV ?? 'development',
  } = options;

  const pinoOptions: pino.LoggerOptions = {
    name: serviceName,
    level,
    timestamp: pino.stdTimeFunctions.isoTime,
    base: {
      service: serviceName,
      env: environment,
      pid: process.pid,
    },
    redact: {
      paths: REDACTION_PATHS,
      censor: CENSOR_VALUE,
    },
    formatters: {
      log(object) {
        return deepRedact(object) as Record<string, unknown>;
      },
    },
    serializers: {
      err: safeErrorSerializer,
      error: safeErrorSerializer,
      req: safeReqSerializer,
      res: safeResSerializer,
    },
  };

  if (stream) {
    return pino(pinoOptions, stream);
  }

  return pino(pinoOptions);
}

let rootLogger: pino.Logger | null = null;

export function getLogger(): pino.Logger {
  if (!rootLogger) {
    rootLogger = createLogger();
  }
  return rootLogger;
}

export function resetLoggerForTesting(): void {
  rootLogger = null;
}
