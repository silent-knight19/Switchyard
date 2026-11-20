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
 * when transaction control tampering is attempted, or when nested/re-entrant
 * withTenant calls are detected.
 */
export class TenantTransactionError extends Error {
  public readonly rollbackError?: unknown;

  constructor(message: string, options?: { cause?: unknown; rollbackError?: unknown }) {
    super(message, { cause: options?.cause });
    this.name = 'TenantTransactionError';
    this.rollbackError = options?.rollbackError;
  }
}

/**
 * Options for withTenant lifecycle observation and diagnostics.
 */
export interface WithTenantOptions {
  onCleanupError?: (error: unknown) => void;
}

function reportCleanupWarning(error: unknown): void {
  const err =
    error instanceof Error ? error : new Error(typeof error === 'string' ? error : String(error));
  process.emitWarning(err.message, {
    type: 'TenantCleanupWarning',
    detail: err.stack,
  });
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

/**
 * Prohibited transaction control statements within a withTenant callback.
 * Transaction ownership and boundary management belong exclusively to withTenant.
 */
const PROHIBITED_TX_COMMANDS =
  /^\s*(BEGIN|COMMIT|ROLLBACK|START\s+TRANSACTION|END|ABORT|SAVEPOINT|RELEASE|PREPARE\s+TRANSACTION)\b/i;

/**
 * Strips leading whitespace, single-line SQL comments (`-- ...`), and block
 * comments (`/* ... *\/`, including nested block comments per PostgreSQL 16 standard)
 * from a SQL command string. Returns the string slice beginning at the first
 * non-comment, non-whitespace token.
 */
export function stripLeadingCommentsAndWhitespace(sql: string): string {
  let i = 0;
  const len = sql.length;

  while (i < len) {
    const ch = sql[i] ?? '';
    // 1. Skip whitespace
    if (/\s/.test(ch)) {
      i++;
      continue;
    }

    // 2. Single-line comment: -- ...
    if (sql[i] === '-' && i + 1 < len && sql[i + 1] === '-') {
      i += 2;
      while (i < len && sql[i] !== '\n' && sql[i] !== '\r') {
        i++;
      }
      continue;
    }

    // 3. Block comment: /* ... */ (supports nested block comments per PostgreSQL specification)
    if (sql[i] === '/' && i + 1 < len && sql[i + 1] === '*') {
      i += 2;
      let depth = 1;
      while (i < len && depth > 0) {
        if (sql[i] === '/' && i + 1 < len && sql[i + 1] === '*') {
          depth++;
          i += 2;
        } else if (sql[i] === '*' && i + 1 < len && sql[i + 1] === '/') {
          depth--;
          i += 2;
        } else {
          i++;
        }
      }
      continue;
    }

    break;
  }

  return sql.slice(i);
}

/**
 * Strips comments (line `--` and block `/* ... *\/`) and string literals (`'...'` and `$...$`)
 * from a SQL string to allow robust lexical inspection of top-level SQL commands without
 * mistaking string literal values or comments for transaction control statements.
 *
 * Adheres to PostgreSQL 16 `standard_conforming_strings = on`, where a backslash inside an
 * ordinary single-quoted string `'...'` is treated as a literal character rather than an escape.
 */
export function stripCommentsAndLiterals(sql: string): string {
  let result = '';
  let i = 0;
  const len = sql.length;

  while (i < len) {
    const ch = sql[i];
    const next = i + 1 < len ? sql[i + 1] : '';

    // Line comment: --
    if (ch === '-' && next === '-') {
      i += 2;
      while (i < len && sql[i] !== '\n' && sql[i] !== '\r') {
        i++;
      }
      result += ' ';
      continue;
    }

    // Block comment: /* ... */ (supports nested block comments)
    if (ch === '/' && next === '*') {
      i += 2;
      let depth = 1;
      while (i < len && depth > 0) {
        if (sql[i] === '/' && i + 1 < len && sql[i + 1] === '*') {
          depth++;
          i += 2;
        } else if (sql[i] === '*' && i + 1 < len && sql[i + 1] === '/') {
          depth--;
          i += 2;
        } else {
          i++;
        }
      }
      result += ' ';
      continue;
    }

    // C-style escape string literal: E'...' or e'...' (where \' is an escaped quote)
    if ((ch === 'E' || ch === 'e') && next === "'") {
      i += 2; // skip E and '
      while (i < len) {
        if (sql[i] === "'") {
          if (i + 1 < len && sql[i + 1] === "'") {
            // Escaped quote ''
            i += 2;
          } else {
            i++;
            break;
          }
        } else if (sql[i] === '\\' && i + 1 < len) {
          // Escaped char \' or \\ in C-escape string
          i += 2;
        } else {
          i++;
        }
      }
      result += ' ';
      continue;
    }

    // Standard single-quoted literal: '...' (standard_conforming_strings=on: backslash is literal)
    if (ch === "'") {
      i++;
      while (i < len) {
        if (sql[i] === "'") {
          if (i + 1 < len && sql[i + 1] === "'") {
            // Escaped quote ''
            i += 2;
          } else {
            i++;
            break;
          }
        } else {
          i++;
        }
      }
      result += ' ';
      continue;
    }

    // Dollar-quoted literal: $tag$...$tag$
    if (ch === '$') {
      const tagMatch = sql.slice(i).match(/^\$([a-zA-Z0-9_]*)\$/);
      if (tagMatch) {
        const fullTag = tagMatch[0];
        i += fullTag.length;
        const closeIdx = sql.indexOf(fullTag, i);
        if (closeIdx === -1) {
          i = len;
        } else {
          i = closeIdx + fullTag.length;
        }
        result += ' ';
        continue;
      }
    }

    result += ch;
    i++;
  }

  return result;
}

/**
 * Asserts that the SQL string contains no prohibited transaction-control commands
 * (BEGIN, COMMIT, ROLLBACK, START TRANSACTION, END, ABORT, SAVEPOINT, RELEASE, PREPARE TRANSACTION, etc.),
 * checking both the leading command statement and multi-statement sequences.
 */
export function assertNoTransactionControl(sql: string): void {
  // 1. Check leading statement token (ignoring leading whitespace and comments)
  const leading = stripLeadingCommentsAndWhitespace(sql);
  if (leading.length > 0 && PROHIBITED_TX_COMMANDS.test(leading)) {
    throw new TenantTransactionError(
      'Transaction control statements (BEGIN, COMMIT, ROLLBACK, etc.) are prohibited inside withTenant callback. Transaction lifecycle is owned exclusively by withTenant.',
    );
  }

  // 2. Also inspect statements across semicolons using standard_conforming_strings-aware lexer
  const stripped = stripCommentsAndLiterals(sql);
  const statements = stripped.split(';');

  for (const stmt of statements) {
    const trimmed = stmt.trim();
    if (trimmed.length > 0 && PROHIBITED_TX_COMMANDS.test(trimmed)) {
      throw new TenantTransactionError(
        'Transaction control statements (BEGIN, COMMIT, ROLLBACK, etc.) are prohibited inside withTenant callback. Transaction lifecycle is owned exclusively by withTenant.',
      );
    }
  }
}

/**
 * Restricted database client interface provided to the withTenant callback.
 * Prevents callers from accessing pool connection lifecycle methods (e.g. release())
 * or executing transaction-control statements directly.
 */
export interface TenantClient {
  query<R extends pg.QueryResultRow = pg.QueryResultRow, I extends unknown[] = unknown[]>(
    queryTextOrConfig: string | pg.QueryConfig<I>,
    values?: I,
  ): Promise<pg.QueryResult<R>>;
  escapeIdentifier(str: string): string;
  escapeLiteral(str: string): string;
}

interface TenantContextStore {
  readonly orgId: string;
  isActive: boolean;
}

export interface ActiveTenantContext {
  readonly orgId: string;
}

const tenantStorage = new AsyncLocalStorage<TenantContextStore>();

/**
 * Returns the active tenant context for the current async execution chain, if any.
 * Returns undefined if no transaction is active, or if the transaction has completed.
 * Does NOT expose raw PoolClient to prevent out-of-transaction connection misuse.
 */
export function getActiveTenantContext(): ActiveTenantContext | undefined {
  const store = tenantStorage.getStore();
  if (!store || !store.isActive) {
    return undefined;
  }
  return { orgId: store.orgId };
}

/**
 * Executes an asynchronous callback within a transaction-scoped tenant context.
 *
 * Guaranteed lifecycle:
 * 1. Validates orgId syntax fail-closed before pool connection checkout.
 * 2. Rejects nested/re-entrant withTenant calls while a transaction is active.
 * 3. Acquires a dedicated client connection from the supplied pg.Pool.
 * 4. Begins an explicit PostgreSQL transaction (`BEGIN`).
 * 5. Sets the transaction-local tenant context (`SELECT pg_catalog.set_config('app.current_org_id', $1, true)`).
 * 6. Invokes the callback with a restricted TenantClient inside AsyncLocalStorage context.
 * 7. Confirms COMMIT execution via PostgreSQL command tag ('COMMIT'). Rejects if PostgreSQL returns 'ROLLBACK'.
 * 8. Rolls back the transaction (`ROLLBACK`) on callback error.
 * 9. Destroys the connection (`client.release(true)`) if commit, rollback, or state is uncertain.
 * 10. Safely releases the connection back to the pool (`client.release()`) on clean completion.
 * 11. Marks AsyncLocalStorage context inactive upon transaction termination to protect detached async continuations.
 *
 * @param pool - PostgreSQL connection pool
 * @param orgId - Valid tenant UUID string
 * @param callback - Function to execute within the tenant transaction
 * @returns The resolved value of the callback
 */
export async function withTenant<T>(
  pool: pg.Pool,
  orgId: string,
  callback: (client: TenantClient) => Promise<T>,
  options?: WithTenantOptions,
): Promise<T> {
  // 1. Fail-closed input validation
  const validatedOrgId = validateTenantId(orgId);

  // 2. Reject nested withTenant invocations if an active transaction context exists
  const activeContext = tenantStorage.getStore();
  if (activeContext && activeContext.isActive) {
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
  let commitConfirmed = false;
  let connectionUncertain = false;
  let hasThrownError = false;
  const contextStore: TenantContextStore = { orgId: validatedOrgId, isActive: false };

  // Intercept client.release during callback execution to prevent premature pool return
  const originalRelease = client.release.bind(client);
  client.release = () => {
    throw new TenantTransactionError('Callback must not invoke release() on withTenant client');
  };

  // Build restricted TenantClient wrapper for callback
  const tenantClient: TenantClient = {
    query: async <R extends pg.QueryResultRow = pg.QueryResultRow, I extends unknown[] = unknown[]>(
      queryTextOrConfig: string | pg.QueryConfig<I>,
      values?: I,
    ): Promise<pg.QueryResult<R>> => {
      // Reject queries if transaction is no longer active (e.g. from detached async continuations)
      if (!contextStore.isActive) {
        throw new TenantTransactionError(
          'Cannot execute query: tenant transaction is no longer active',
        );
      }

      // Extract SQL query text
      let sqlText: string;
      let callerConfig: pg.QueryConfig<I> | undefined;

      if (typeof queryTextOrConfig === 'string') {
        sqlText = queryTextOrConfig;
      } else if (
        typeof queryTextOrConfig === 'object' &&
        queryTextOrConfig !== null &&
        typeof (queryTextOrConfig as pg.QueryConfig<I>).text === 'string'
      ) {
        callerConfig = queryTextOrConfig as pg.QueryConfig<I>;
        sqlText = callerConfig.text;
      } else {
        throw new TenantTransactionError(
          'Invalid query: query text must be a string or QueryConfig object',
        );
      }

      // Assert that callback is not attempting transaction control commands
      assertNoTransactionControl(sqlText);

      // Force extended query protocol so PostgreSQL strictly enforces single-statement execution (DB-30).
      // Caller-supplied queryMode cannot override this.
      const queryConfig = callerConfig
        ? {
            ...callerConfig,
            queryMode: 'extended',
            ...(values !== undefined ? { values } : {}),
          }
        : {
            text: sqlText,
            values,
            queryMode: 'extended',
          };

      return (
        client.query as (q: pg.QueryConfig<I> & { queryMode: string }) => Promise<pg.QueryResult<R>>
      )(queryConfig as pg.QueryConfig<I> & { queryMode: string });
    },
    escapeIdentifier: (str: string) => client.escapeIdentifier(str),
    escapeLiteral: (str: string) => client.escapeLiteral(str),
  };

  // Prevent callback from invoking release on tenantClient directly
  (tenantClient as unknown as { release: () => void }).release = () => {
    throw new TenantTransactionError('Callback must not invoke release() on withTenant client');
  };

  try {
    // 4. Begin explicit PostgreSQL transaction
    await client.query('BEGIN');
    insideTransaction = true;
    contextStore.isActive = true;

    // 5. Set transaction-local tenant context GUC (is_local = true)
    await client.query("SELECT pg_catalog.set_config('app.current_org_id', $1, true)", [
      validatedOrgId,
    ]);

    // 6. Execute callback within AsyncLocalStorage scope
    const result = await tenantStorage.run(contextStore, async () => callback(tenantClient));

    // 7. Commit transaction and verify PostgreSQL command tag
    let commitResult: pg.QueryResult;
    try {
      commitResult = await client.query('COMMIT');
    } catch (commitErr: unknown) {
      insideTransaction = false;
      connectionUncertain = true;
      throw new TenantTransactionError('Failed to execute COMMIT statement', { cause: commitErr });
    }

    insideTransaction = false;

    // PostgreSQL returns command tag 'ROLLBACK' when COMMIT terminates an aborted transaction
    if (commitResult.command !== 'COMMIT') {
      if (commitResult.command === 'ROLLBACK') {
        // Confirmed rollback by PostgreSQL; connection is clean but transaction failed to commit
        throw new TenantTransactionError(
          'Transaction failed to commit: PostgreSQL rolled back the aborted transaction',
        );
      }
      connectionUncertain = true;
      throw new TenantTransactionError(
        `Transaction failed to commit: unexpected completion outcome "${commitResult.command}"`,
      );
    }

    commitConfirmed = true;
    return result;
  } catch (error: unknown) {
    hasThrownError = true;
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
    // 11. Mark context inactive to prevent stale continuations from accessing transaction
    contextStore.isActive = false;

    // Restore original release method
    client.release = originalRelease;

    // Connection release cleanup & verification (DB-31, DB-33, DB-34)
    // Invariant: no reusable pooled connection may retain tenant identity from a completed transaction.
    // Use RESET ALL and DISCARD TEMP rather than DISCARD ALL to avoid destroying server-side prepared statements
    // cached on the client connection by node-postgres (DB-34 SQLSTATE 26000 avoidance).
    let cleanupError: unknown;
    if (!insideTransaction && !connectionUncertain) {
      try {
        await client.query('RESET ALL');
        await client.query('DISCARD TEMP');

        // Explicitly verify that app.current_org_id is empty/null
        const checkResult = await client.query<{ cur_org: string | null }>(
          "SELECT pg_catalog.current_setting('app.current_org_id', true) AS cur_org",
        );
        const remainingOrg = checkResult.rows[0]?.cur_org;
        if (remainingOrg && remainingOrg.trim().length > 0) {
          connectionUncertain = true;
          cleanupError = new TenantTransactionError(
            `Residual tenant context "${remainingOrg}" detected on pooled connection after transaction`,
          );
        }
      } catch (err: unknown) {
        connectionUncertain = true;
        cleanupError = err;
      }
    }

    if (connectionUncertain || insideTransaction) {
      // Invalidate connection to prevent uncertain or contaminated state from being reused in the pool
      originalRelease(true);
      if (cleanupError) {
        if (commitConfirmed) {
          // DB-33: Transaction committed durably on PostgreSQL.
          // Never report a confirmed durable COMMIT as an uncommitted or rolled-back transaction.
          // Destroy the contaminated connection and make the cleanup incident observable via diagnostics.
          if (options?.onCleanupError) {
            try {
              options.onCleanupError(cleanupError);
            } catch {
              // Ignore diagnostic hook errors to avoid masking committed result
            }
          } else {
            reportCleanupWarning(cleanupError);
          }
        } else if (!hasThrownError) {
          throw new TenantTransactionError(
            'Failed to sanitize or verify pooled connection state after transaction',
            { cause: cleanupError },
          );
        } else {
          // Preserve original callback error while observing cleanup failure
          if (options?.onCleanupError) {
            try {
              options.onCleanupError(cleanupError);
            } catch {
              // Ignore diagnostic hook errors
            }
          } else {
            reportCleanupWarning(cleanupError);
          }
        }
      }
    } else {
      originalRelease();
    }
  }
}
