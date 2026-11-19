import { ConfigValidationError } from './errors.js';
import { parseConfig, type GatewayConfig } from './schema.js';

let cachedConfig: GatewayConfig | null = null;

export { ConfigValidationError, type ConfigIssue } from './errors.js';
export { type GatewayConfig } from './schema.js';

/**
 * Loads and validates configuration from process.env or an explicit override dictionary.
 * Throws ConfigValidationError if configuration fails validation or security invariants.
 */
export function loadConfig(envOverride?: Record<string, string | undefined>): GatewayConfig {
  const envInput = envOverride ?? process.env;
  const result = parseConfig(envInput);

  if (!result.success) {
    throw new ConfigValidationError(result.issues);
  }

  if (!envOverride) {
    cachedConfig = result.data;
  }

  return result.data;
}

/**
 * Retrieves the loaded configuration singleton, or initializes from process.env if not yet loaded.
 */
export function getConfig(): GatewayConfig {
  if (!cachedConfig) {
    return loadConfig();
  }
  return cachedConfig;
}

/**
 * Resets cached configuration singleton for test isolation.
 */
export function resetConfigForTesting(): void {
  cachedConfig = null;
}
