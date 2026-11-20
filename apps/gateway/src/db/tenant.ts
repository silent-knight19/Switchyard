import { AsyncLocalStorage } from 'node:async_hooks';
import type pg from 'pg';

/**
 * Thrown when an invalid or malformed organization ID is supplied to tenant operations.
 */
export class InvalidTenantIdError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidTenantIdError';
  }
}

/**
 * Thrown when a tenant transaction cannot be initialized, committed, rolled back,
 * or when nested/re-entrant withTenant calls are detected.
 */
export class TenantTransactionError extends Error {
  public readonly rollbackError?: unknown;

  constructor(message: string, options?: { cause?: unknown; rollbackError?: unknown }) {
    super(message, { cause: options?.cause });
    this.name = 'TenantTransactionError';
    this.rollbackError = options?.rollbackError;
  }
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Validates that the provided tenant ID is a non-empty, syntactically valid UUID string.
 * Fails closed on any non-string, null, undefined, empty, whitespace-only, or malformed input.
 */
export function validateTenantId(orgId: unknown): string {
  if (typeof orgId !== 'string') {
    throw new InvalidTenantIdError(
      `Invalid tenant ID: expected string, got ${orgId === null ? 'null' : typeof orgId}`,
    );
  }

  const trimmed = orgId.trim();
  if (trimmed.length === 0) {
    throw new InvalidTenantIdError('Invalid tenant ID: empty or whitespace-only string');
  }

  if (!UUID_REGEX.test(trimmed)) {
    throw new InvalidTenantIdError(`Invalid tenant ID: malformed UUID "${orgId}"`);
  }

  return trimmed;
}

interface TenantContextStore {
  orgId: string;
  client: pg.PoolClient;
}

const tenantStorage = new AsyncLocalStorage<TenantContextStore>();

/**
 * Returns the active tenant context for the current async execution chain, if any.
 */
export function getActiveTenantContext(): TenantContextStore | undefined {
  return tenantStorage.getStore();
}

/**
 * Executes an asynchronous callback within a transaction-scoped tenant context.
 *
 * Guaranteed lifecycle:
 * 1. Validates orgId syntax fail-closed before pool connection checkout.
 * 2. Rejects nested/re-entrant withTenant calls to avoid pool deadlocks and transaction misuse.
 * 3. Acquires a dedicated client connection from the supplied pg.Pool.
 * 4. Begins an explicit PostgreSQL transaction (`BEGIN`).
 * 5. Sets the transaction-local tenant context (`SELECT pg_catalog.set_config('app.current_org_id', $1, true)`).
 * 6. Invokes the callback with the checked-out client inside AsyncLocalStorage context.
 * 7. Commits the transaction (`COMMIT`) on callback success.
 * 8. Rolls back the transaction (`ROLLBACK`) on callback error.
 * 9. Destroys the connection (`client.release(true)`) if commit, rollback, or state is uncertain.
 * 10. Safely releases the connection back to the pool (`client.release()`) on clean completion.
 *
 * @param pool - PostgreSQL connection pool
 * @param orgId - Valid tenant UUID string
 * @param callback - Function to execute within the tenant transaction
 * @returns The resolved value of the callback
 */
export async function withTenant<T>(
  pool: pg.Pool,
  orgId: string,
  callback: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  // 1. Fail-closed input validation
  const validatedOrgId = validateTenantId(orgId);

  // 2. Reject nested withTenant invocations
  const activeContext = tenantStorage.getStore();
  if (activeContext) {
    throw new TenantTransactionError(
      'Nested withTenant() calls are not supported to prevent transaction misuse and pool deadlocks',
    );
  }

  // 3. Acquire connection from pool
  let client: pg.PoolClient;
  try {
    client = await pool.connect();
  } catch (err: unknown) {
    throw new TenantTransactionError('Failed to acquire PostgreSQL connection from pool', {
      cause: err,
    });
  }

  let insideTransaction = false;
  let connectionUncertain = false;
  let commitAttempted = false;

  // Intercept client.release during callback execution to prevent premature pool return
  const originalRelease = client.release.bind(client);
  client.release = () => {
    throw new TenantTransactionError('Callback must not invoke release() on withTenant client');
  };

  try {
    // 4. Begin explicit PostgreSQL transaction
    await client.query('BEGIN');
    insideTransaction = true;

    // 5. Set transaction-local tenant context GUC (is_local = true)
    await client.query("SELECT pg_catalog.set_config('app.current_org_id', $1, true)", [
      validatedOrgId,
    ]);

    // 6. Execute callback within AsyncLocalStorage scope
    const result = await tenantStorage.run({ orgId: validatedOrgId, client }, async () =>
      callback(client),
    );

    // 7. Commit transaction
    commitAttempted = true;
    await client.query('COMMIT');
    insideTransaction = false;

    return result;
  } catch (error: unknown) {
    if (commitAttempted) {
      connectionUncertain = true;
    }

    if (insideTransaction) {
      try {
        await client.query('ROLLBACK');
        insideTransaction = false;
      } catch (rollbackErr: unknown) {
        connectionUncertain = true;
        throw new TenantTransactionError('Transaction rollback failed after error', {
          cause: error,
          rollbackError: rollbackErr,
        });
      }
    }

    throw error;
  } finally {
    // Restore original release method
    client.release = originalRelease;

    if (connectionUncertain || insideTransaction) {
      // Invalidate connection to prevent uncertain state from being reused in the pool
      originalRelease(true);
    } else {
      originalRelease();
    }
  }
}
