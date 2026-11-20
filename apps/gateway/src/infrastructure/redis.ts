import { Redis } from 'ioredis';
import type { GatewayConfig } from '../config/index.js';

export interface RedisClient {
  redis: Redis;
  checkReadiness(timeoutMs?: number): Promise<{
    ok: boolean;
    policy?: string | undefined;
    code?: string | undefined;
    error?: string | undefined;
  }>;
  verifyAclRestrictions(timeoutMs?: number): Promise<{
    ok: boolean;
    code?: string | undefined;
    error?: string | undefined;
  }>;
  close(): Promise<void>;
}

export function createRedisClient(config: GatewayConfig, existingRedis?: Redis): RedisClient {
  const redis =
    existingRedis ??
    new Redis({
      host: config.REDIS_HOST,
      port: Number(config.REDIS_PORT),
      username: config.REDIS_USER,
      password: config.REDIS_PASSWORD,
      tls: config.REDIS_TLS === true ? {} : undefined,
      lazyConnect: true,
      connectTimeout: 2000,
      maxRetriesPerRequest: 1,
      retryStrategy: (times) => {
        if (times > 2) return null;
        return Math.min(times * 100, 500);
      },
    });

  // Attach silent error listener to prevent unhandled error event noise during connection failures
  if (typeof redis.on === 'function') {
    redis.on('error', () => {});
  }

  return {
    redis,
    async checkReadiness(timeoutMs = 2000) {
      let timer: NodeJS.Timeout | null = null;
      const timeoutPromise = new Promise<{
        ok: false;
        code: string;
        error: string;
      }>((resolve) => {
        timer = setTimeout(() => {
          resolve({ ok: false, code: 'TIMEOUT', error: 'Redis readiness check timed out' });
        }, timeoutMs);
      });

      const checkPromise = (async () => {
        try {
          const pong = await redis.ping();
          if (pong !== 'PONG') {
            return {
              ok: false,
              code: 'UNEXPECTED_PING_RESPONSE',
              error: 'Unexpected response from Redis ping probe',
            };
          }

          const info = await redis.info('memory');
          const policyMatch = info.match(/maxmemory_policy:([^\r\n]+)/);
          const policy = policyMatch ? policyMatch[1]?.trim() : undefined;

          if (policy !== 'noeviction') {
            return {
              ok: false,
              policy,
              code: 'UNSAFE_POLICY',
              error: `Unsafe Redis policy "${policy}": expected "noeviction"`,
            };
          }

          const persistenceInfo = await redis.info('persistence');
          const aofMatch = persistenceInfo.match(/aof_enabled:([^\r\n]+)/);
          const aofEnabled = aofMatch ? aofMatch[1]?.trim() : undefined;

          if (aofEnabled !== '1') {
            return {
              ok: false,
              policy,
              code: 'UNSAFE_AOF_PERSISTENCE',
              error: 'Redis AOF persistence is not enabled: expected "aof_enabled:1"',
            };
          }

          return { ok: true, policy };
        } catch (err: unknown) {
          const code =
            err && typeof err === 'object' && 'code' in err && typeof err.code === 'string'
              ? err.code
              : 'REDIS_ERROR';
          return { ok: false, code, error: 'Redis readiness check failed' };
        }
      })();

      try {
        return await Promise.race([checkPromise, timeoutPromise]);
      } finally {
        if (timer) clearTimeout(timer);
      }
    },

    /**
     * Verifies runtime Redis identity and safe, non-destructive ACL restrictions (Architecture v1.2 §19.1).
     *
     * BOUNDARY AND VERIFICATION DESIGN:
     * - In the Gateway runtime, destructive/state-changing administrative commands (FLUSHALL, FLUSHDB,
     *   SHUTDOWN, REPLICAOF, DEBUG) must NEVER be executed to test authorization, even with invalid arguments.
     * - Gateway runtime verification uses safe, side-effect-free probes:
     *   1. Identity check (ACL WHOAMI): Confirms connection is not using the default unrestricted user,
     *      and confirms the active identity strictly matches the Gateway configured REDIS_USER.
     *   2. Administrative check (CONFIG GET maxmemory): Confirms administrative category (-@admin, -CONFIG) is denied.
     *   3. Key enumeration check (KEYS probe): Confirms unrestricted key scans (-KEYS) are denied.
     *   4. ACL administration check (ACL LIST): Confirms user cannot view or modify ACLs.
     * - Comprehensive authorization verification of all prohibited commands (FLUSHALL, FLUSHDB, CONFIG, DEBUG,
     *   SHUTDOWN, REPLICAOF, KEYS) is performed via side-effect-free Redis `ACL DRYRUN` attestation at startup.
     */
    async verifyAclRestrictions(timeoutMs = 2000) {
      let timer: NodeJS.Timeout | null = null;
      const timeoutPromise = new Promise<{
        ok: false;
        code: string;
        error: string;
      }>((resolve) => {
        timer = setTimeout(() => {
          resolve({ ok: false, code: 'TIMEOUT', error: 'Redis ACL verification timed out' });
        }, timeoutMs);
      });

      const verifyPromise = (async () => {
        try {
          // Check 1: Runtime Identity Verification (ACL WHOAMI)
          // The Gateway must run under a dedicated restricted user, never the overprivileged 'default' admin user.
          let currentUser = '';
          try {
            currentUser = (await redis.acl('WHOAMI')) as string;
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            return {
              ok: false,
              code: 'WHOAMI_FAILED',
              error: `Failed to verify Redis runtime identity: ${msg}`,
            };
          }

          if (currentUser === 'default') {
            return {
              ok: false,
              code: 'DEFAULT_USER_FORBIDDEN',
              error:
                'Redis runtime identity is the overprivileged "default" user; a dedicated restricted identity is required',
            };
          }

          if (config.REDIS_USER && currentUser !== config.REDIS_USER) {
            return {
              ok: false,
              code: 'REDIS_USER_MISMATCH',
              error: `Redis runtime identity "${currentUser}" does not match configured user "${config.REDIS_USER}"`,
            };
          }

          // Check 2: Non-destructive administrative probe (CONFIG GET maxmemory)
          let configDenied = false;
          try {
            await redis.call('CONFIG', 'GET', 'maxmemory');
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg.startsWith('NOPERM')) {
              configDenied = true;
            } else {
              throw err;
            }
          }

          if (!configDenied) {
            return {
              ok: false,
              code: 'OVERPRIVILEGED_CONFIG_PERMITTED',
              error:
                'Redis runtime identity is overprivileged: administrative CONFIG command was permitted',
            };
          }

          // Check 3: Non-destructive key-enumeration probe (KEYS dummy_probe)
          let keysDenied = false;
          try {
            await redis.call('KEYS', '__switchyard_probe__');
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg.startsWith('NOPERM')) {
              keysDenied = true;
            } else {
              throw err;
            }
          }

          if (!keysDenied) {
            return {
              ok: false,
              code: 'OVERPRIVILEGED_KEYS_PERMITTED',
              error:
                'Redis runtime identity is overprivileged: unrestricted KEYS command was permitted',
            };
          }

          // Check 4: Non-destructive ACL administration probe (ACL LIST)
          let aclDenied = false;
          try {
            await redis.call('ACL', 'LIST');
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg.startsWith('NOPERM')) {
              aclDenied = true;
            } else {
              throw err;
            }
          }

          if (!aclDenied) {
            return {
              ok: false,
              code: 'OVERPRIVILEGED_ACL_PERMITTED',
              error:
                'Redis runtime identity is overprivileged: administrative ACL LIST command was permitted',
            };
          }

          return { ok: true };
        } catch (err: unknown) {
          const code =
            err && typeof err === 'object' && 'code' in err && typeof err.code === 'string'
              ? err.code
              : 'ACL_PROBE_ERROR';
          return { ok: false, code, error: 'Redis ACL verification failed' };
        }
      })();

      try {
        return await Promise.race([verifyPromise, timeoutPromise]);
      } finally {
        if (timer) clearTimeout(timer);
      }
    },

    async close() {
      try {
        if (
          redis.status === 'ready' ||
          redis.status === 'connecting' ||
          redis.status === 'connect'
        ) {
          await redis.quit();
        } else {
          redis.disconnect();
        }
      } catch {
        redis.disconnect();
      }
    },
  };
}

export const PROHIBITED_REDIS_COMMANDS: ReadonlyArray<readonly string[]> = [
  ['FLUSHALL'],
  ['FLUSHDB'],
  ['CONFIG', 'GET', 'maxmemory'],
  ['DEBUG', 'OBJECT', 'x'],
  ['SHUTDOWN'],
  ['REPLICAOF', 'NO', 'ONE'],
  ['KEYS', '*'],
];

export interface RedisAclAttestationResult {
  ok: boolean;
  code?: string;
  error?: string;
  prohibitedCommand?: string;
}

/**
 * Executes comprehensive ACL authorization attestation via administrative Redis context (Architecture v1.2 §19.1).
 * Uses side-effect-free Redis `ACL DRYRUN` to verify that the target runtime user identity
 * is denied from executing all mandatory prohibited commands without executing target commands.
 */
export async function verifyRedisAclAttestation(
  adminRedis: Redis,
  targetUser: string,
): Promise<RedisAclAttestationResult> {
  if (targetUser === 'default') {
    return {
      ok: false,
      code: 'DEFAULT_USER_FORBIDDEN',
      error: 'Target identity cannot be the overprivileged "default" user',
    };
  }

  for (const cmd of PROHIBITED_REDIS_COMMANDS) {
    const commandName = cmd[0] ?? 'UNKNOWN';
    try {
      const result = (await adminRedis.call('ACL', 'DRYRUN', targetUser, ...cmd)) as string;
      // Redis 7 ACL DRYRUN contract:
      // - If permitted: returns "OK"
      // - If denied: returns "User <targetUser> has no permissions to run the '<cmd>' command"
      // - If user not found: returns "ERR User '<targetUser>' not found"
      if (typeof result !== 'string' || !result.toLowerCase().includes('no permissions')) {
        const code = `OVERPRIVILEGED_${commandName}_PERMITTED`;
        return {
          ok: false,
          code,
          prohibitedCommand: commandName,
          error: `Redis ACL attestation failed: command "${cmd.join(' ')}" was permitted or indeterminate (${result}) for user "${targetUser}"`,
        };
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        ok: false,
        code: 'ATTESTATION_ERROR',
        prohibitedCommand: commandName,
        error: `Redis ACL attestation failed for command "${cmd.join(' ')}": ${msg}`,
      };
    }
  }

  return { ok: true };
}
