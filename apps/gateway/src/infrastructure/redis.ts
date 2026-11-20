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
     * Verifies runtime Redis identity and mandatory ACL restrictions (Finding 2, Architecture v1.2 §19.1).
     *
     * BOUNDARY AND VERIFICATION LIMITATION REPORT:
     * - In the Gateway runtime, destructive administrative commands (e.g. FLUSHALL, FLUSHDB, SHUTDOWN, REPLICAOF)
     *   must NEVER be executed to test authorization, as executing them would compromise system state or availability.
     * - Gateway runtime verification uses safe, non-destructive probes:
     *   1. Identity check (ACL WHOAMI): Confirms the connection is not using the default unrestricted user.
     *   2. Administrative check (CONFIG GET): Confirms administrative category (-@admin, -CONFIG) is denied with NOPERM.
     *   3. Key enumeration check (KEYS probe): Confirms unrestricted key scans (-KEYS) are denied with NOPERM.
     *   4. ACL administration check (ACL LIST): Confirms user cannot view or modify ACLs.
     * - Exhaustive authorization verification of all prohibited commands (FLUSHALL, FLUSHDB, DEBUG, SHUTDOWN, REPLICAOF)
     *   is performed safely via ACL DRYRUN in isolated test infrastructure where administrative credentials reside.
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

          // Check 5: Non-destructive FLUSHALL probe (syntax check: invalid args prevent execution if permitted)
          let flushallDenied = false;
          try {
            await redis.call('FLUSHALL', '__switchyard_probe_syntax_check__');
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg.startsWith('NOPERM')) {
              flushallDenied = true;
            } else if (msg.includes('ERR syntax error') || msg.includes('syntax error')) {
              // Permission was granted by ACL; syntax check rejected execution safely
              flushallDenied = false;
            } else {
              throw err;
            }
          }

          if (!flushallDenied) {
            return {
              ok: false,
              code: 'OVERPRIVILEGED_FLUSHALL_PERMITTED',
              error:
                'Redis runtime identity is overprivileged: administrative FLUSHALL command was permitted',
            };
          }

          // Check 6: Non-destructive FLUSHDB probe (syntax check: invalid args prevent execution if permitted)
          let flushdbDenied = false;
          try {
            await redis.call('FLUSHDB', '__switchyard_probe_syntax_check__');
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg.startsWith('NOPERM')) {
              flushdbDenied = true;
            } else if (msg.includes('ERR syntax error') || msg.includes('syntax error')) {
              flushdbDenied = false;
            } else {
              throw err;
            }
          }

          if (!flushdbDenied) {
            return {
              ok: false,
              code: 'OVERPRIVILEGED_FLUSHDB_PERMITTED',
              error:
                'Redis runtime identity is overprivileged: administrative FLUSHDB command was permitted',
            };
          }

          // Check 7: Non-destructive SHUTDOWN probe (SHUTDOWN ABORT safely errors if no shutdown in progress)
          let shutdownDenied = false;
          try {
            await redis.call('SHUTDOWN', 'ABORT');
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg.startsWith('NOPERM')) {
              shutdownDenied = true;
            } else if (
              msg.includes('ERR No shutdown in progress') ||
              msg.includes('No shutdown in progress')
            ) {
              shutdownDenied = false;
            } else {
              throw err;
            }
          }

          if (!shutdownDenied) {
            return {
              ok: false,
              code: 'OVERPRIVILEGED_SHUTDOWN_PERMITTED',
              error:
                'Redis runtime identity is overprivileged: administrative SHUTDOWN command was permitted',
            };
          }

          // Check 8: Non-destructive REPLICAOF probe (invalid port argument prevents replication changes)
          let replicaofDenied = false;
          try {
            await redis.call('REPLICAOF', '__switchyard_probe__', '__switchyard_probe__');
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg.startsWith('NOPERM')) {
              replicaofDenied = true;
            } else if (
              msg.includes('ERR Invalid master port') ||
              msg.includes('Invalid master port')
            ) {
              replicaofDenied = false;
            } else {
              throw err;
            }
          }

          if (!replicaofDenied) {
            return {
              ok: false,
              code: 'OVERPRIVILEGED_REPLICAOF_PERMITTED',
              error:
                'Redis runtime identity is overprivileged: administrative REPLICAOF command was permitted',
            };
          }

          // Check 9: Non-destructive DEBUG probe (DEBUG command not allowed or NOPERM)
          let debugDenied = false;
          try {
            await redis.call('DEBUG', '__switchyard_probe__');
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg.startsWith('NOPERM') || msg.includes('DEBUG command not allowed')) {
              debugDenied = true;
            } else {
              throw err;
            }
          }

          if (!debugDenied) {
            return {
              ok: false,
              code: 'OVERPRIVILEGED_DEBUG_PERMITTED',
              error:
                'Redis runtime identity is overprivileged: administrative DEBUG command was permitted',
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
