# Switchyard — Development Environment Setup

This document describes the minimum reproducible development toolchain setup for Switchyard as established in SW-1.1.1.

## 1. Toolchain Versions

| Tool | Version | Verification Source |
|---|---|---|
| **Node.js** | `26.13.1` (Active LTS "Lithium") | Official distribution index: `https://nodejs.org/dist/index.json` (verified 2026-11-19) |
| **pnpm** | `12.21.0` (Stable) | Official npm registry: `https://registry.npmjs.org/pnpm` (verified 2026-11-19) |

## 2. Environment Activation & Installation

### Node.js (v26.13.1)
The exact Node.js LTS version is pinned in `.node-version`.

Activate or install using your preferred Node version manager:
- **fnm**: `fnm use` (or `fnm install 26.13.1`)
- **nvm**: `nvm use` (or `nvm install 26.13.1`)
- **mise / asdf**: `mise install` / `asdf install`

### pnpm (v12.21.0)
The exact pnpm version is pinned in `package.json` under the `packageManager` field.

Activate or install using one of:
- **corepack**: `corepack enable && corepack prepare pnpm@12.21.0 --activate`
- **npm**: `npm install -g pnpm@12.21.0`

## 3. Dependency Installation

To install dependencies reproducibly using the committed lockfile:

```bash
pnpm install --frozen-lockfile
```

## 4. Toolchain Verification Commands

Run the following commands to confirm your environment meets the toolchain contract:

```bash
node --version                    # Must output v26.13.1
pnpm --version                    # Must output 12.21.0
pnpm install --frozen-lockfile    # Must exit 0
git diff --check                  # Must report no whitespace/formatting errors
```

## 5. Workspace Structure

The monorepo workspace configuration (`pnpm-workspace.yaml`) defines:
- `apps/*`: Application containers (`apps/gateway`, `apps/web`, `apps/mock-upstream` to be initialized in SW-1.1.2)
- `packages/*`: Shared packages (`packages/shared` to be initialized in SW-1.1.2)

## 6. Task Naming, Workflow, and Evidence Governance

To ensure deterministic repository governance and auditability, all changes follow strict task naming, lifecycle gates, and verification expectations:

### 6.1 Naming Conventions

- **Branch Naming:** `task/sw-X.Y.Z-short-description` (e.g., `task/sw-1.1.4-ci-security-foundation`).
- **Commit Messages:** Conventional Commits scoped to the task or subsystem (e.g., `chore(ci): configure CI pipeline and security scanning`).
- **Pull Request Titles:** `SW-X.Y.Z: Short Description` (e.g., `SW-1.1.4: CI Pipeline, Security Scanning, and PR Governance`).

### 6.2 Review Lifecycle Gates

Every task must transition through five distinct states:

1. **`SPECIFIED`:** The task contract, dependencies, and acceptance criteria are documented in the implementation roadmap.
2. **`READY`:** Prerequisites and working-tree clean state are verified; a fresh task branch is cut from updated `main`.
3. **`IMPLEMENTED`:** Minimal authorized code is authored; all local baseline and negative-path checks pass.
4. **`REVIEWED`:** The independent Principal Software Architect inspects the implementation diff, verification matrix, and negative test evidence.
5. **`ACCEPTED`:** The Project Owner reviews the architect's findings, authorizes the merge, and integrates into `main`.

### 6.3 Evidence Expectations

- **Empirical Proof:** Never claim a check passed without running the named command and reporting the actual command output and exit code.
- **Negative-Path Verification:** Every quality gate (typechecking, linting, formatting, testing) must demonstrate failure detection via deliberate negative testing followed by confirmed recovery.
- **Credential Hygiene:** Never emit production credentials, live provider API keys, or raw payloads in tool reports, logs, commits, or pull requests.

### 6.4 Architectural Authority and Deviations

- Architecture v1.2 and accepted ADRs are normative.
- Existing code or tests describe implementation state but do not override architectural invariants.
- If an architectural conflict arises, work must stop, the conflict must be reported, and the Project Owner must approve any deviation before implementation.

## 7. Local Infrastructure (PostgreSQL, Redis, Docker Compose)

As established in SW-1.2.1, Switchyard uses Docker Compose to orchestrate local development and test instances of PostgreSQL and Redis with private network isolation and persistent named volumes.

### 7.1 Prerequisites & Pinned Image Versions

- **Docker:** Engine v24.0+ / Docker Desktop (Compose v2.20+)
- **PostgreSQL:** `postgres:16.8-alpine` (PostgreSQL 16+)
- **Redis:** `redis:7.4.2-alpine` (Redis 7+)

### 7.2 Configuration & Environment Variables

Copy the provided development defaults template:

```bash
cp .env.example .env
```

| Variable | Default Value | Purpose | Notes |
| :--- | :--- | :--- | :--- |
| `POSTGRES_USER` | `switchyard` | PostgreSQL development superuser | Local development only |
| `POSTGRES_PASSWORD` | `switchyard_dev_password` | PostgreSQL development password | Local development only |
| `POSTGRES_DB` | `switchyard` | PostgreSQL development database | Local development only |
| `POSTGRES_PORT` | `5432` | Host loopback port for PostgreSQL | Bound to `127.0.0.1` |
| `GATEWAY_POSTGRES_USER` | `gateway_app` | Restricted Gateway runtime PostgreSQL user | Least-privilege runtime role (Architecture §12.1, DB-12) |
| `GATEWAY_POSTGRES_PASSWORD` | `switchyard_app_password` | Gateway runtime PostgreSQL password | Runtime database connection password |
| `REDIS_PASSWORD` | `switchyard_dev_password` | Redis admin authentication password | Injected via stdin/environment for administrative/ops use |
| `REDIS_APP_USER` | `switchyard_app` | Restricted Redis application user | Runtime ACL user for application services |
| `REDIS_APP_PASSWORD` | `switchyard_app_password` | Restricted Redis application password | Runtime ACL password with prohibited administrative commands |
| `REDIS_PORT` | `6379` | Host loopback port for Redis | Bound to `127.0.0.1` |
| `REDIS_MAXMEMORY` | `64mb` | Redis memory allocation bound | Provisional development baseline; not benchmark-validated (production sizing requires Phase 2 load testing under `bench/`) |

#### 7.2.1 Provider Credential Envelope Encryption Configuration (SW-1.7.1/SW-1.7.2)

Provider credentials use per-organization AES-256-GCM DEKs wrapped under versioned environment KEKs. The central configuration module recognises:

| Variable | Required | Purpose |
| :--- | :---: | :--- |
| `MASTER_KEK_V1` | Conditional | Canonical unpadded base64url encoding of exactly 32 bytes (43 characters). |
| `MASTER_KEK_V2` | Conditional | Same representation; must not duplicate V1 material. |
| `ACTIVE_KEK_VERSION` | Conditional | Exact decimal string `1` or `2`; must reference a supplied valid KEK. |

Rules:
- Omit all three variables to leave the vault uninitialised. Existing Gateway startup does not require KEKs.
- Supplying any KEK value requires a valid active version and its matching key. Partial, padded, noncanonical, all-zero, duplicate, or inconsistent configurations are rejected at startup.
- Generate development KEKs with a cryptographically secure RNG, for example:
  ```bash
  node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64url'))"
  ```
- Never commit real KEKs, reuse one key for V1 and V2, or log configuration objects containing KEKs.
- SW-1.7.3 must require valid KEK configuration before enabling provider-credential management routes.
- Focused tests: `pnpm --filter @switchyard/gateway test src/vault/kek.test.ts src/vault/envelope.test.ts`.
- Real PostgreSQL evidence: `pnpm --filter @switchyard/gateway test:db` (includes `src/vault/envelope.db.test.ts`).

#### 7.2.2 Deterministic Mock Upstream Configuration (SW-1.8-A)

The private mock upstream (`apps/mock-upstream`) provides deterministic, seed/config-driven chat-completion responses, network faults, and SSE streaming edge cases for testing without external AI provider dependencies.

| Variable | Required | Purpose |
| :--- | :---: | :--- |
| `MOCK_PORT` | Optional (default: `4000`) | Internal port for mock upstream |
| `MOCK_HOST` | Optional (default: `127.0.0.1` locally, `0.0.0.0` in Docker) | Host bind address |
| `MOCK_CONTROL_SECRET` | Optional | Private test-control secret (32 random bytes, exactly 64 hexadecimal characters) |

Rules and private integration test workflow:
- The mock upstream container is attached to `switchyard-network` and **does not publish host ports** (`ports:` is omitted in Compose), maintaining strict private network isolation.
- When `MOCK_CONTROL_SECRET` is omitted or empty, the service automatically generates a random 32-byte (64 hex character) secret at startup.
- Authorized integration test runners can supply a known secret to both the test runner and the Compose service via `.env` or environment:
  ```bash
  export MOCK_CONTROL_SECRET=$(openssl rand -hex 32)
  docker compose up -d mock-upstream
  ```
- If explicitly supplied, `MOCK_CONTROL_SECRET` must be exactly 64 hexadecimal characters (`^[0-9a-fA-F]{64}$`). Any invalid/short/malformed value is rejected at startup with a descriptive error that never reflects the secret value.
- Authorized test clients authenticate to private control endpoints (`/__test/*`) and the `x-test-fixture-id` header using `X-Test-Control-Key: <secret>` or `Authorization: Bearer <secret>`. Missing or incorrect credentials return HTTP 401.
- Standard OpenAI-compatible callers (`POST /v1/chat/completions`) without fixture selection headers do not require authentication and return standard deterministic responses.
- `NODE_ENV=production` refuses startup unconditionally.

### 7.3 Service Management Commands

#### Safe Startup
```bash
docker compose up -d
```
Starts PostgreSQL, Redis, applies database migrations under advisory lock via the one-shot `migrate` service (`gateway_migrator`), and admits the Gateway (`gateway_app`) once migrations complete successfully.

#### Status & Health Inspection
```bash
docker compose ps
```
Displays container state, port bindings, and healthcheck status (`healthy` / `starting` / `unhealthy` / `exited` for completed one-shot migration).

#### Service Logs
```bash
docker compose logs -f [postgres|redis|migrate|gateway]
```

#### Safe Normal Shutdown (Preserves Volumes)
```bash
docker compose down
```
> [!TIP]
> Always use `docker compose down` for normal development shutdown. This stops and removes container instances while preserving the named data volumes (`switchyard_postgres_data` and `switchyard_redis_data`).

Alternatively, to pause services without removing containers:
```bash
docker compose stop
```

#### Prohibited Destructive Reset (`docker compose down -v`)
> [!CAUTION]
> **PROHIBITED DURING NORMAL DEVELOPMENT SHUTDOWN.**
> Executing `docker compose down -v` permanently destroys all persistent volumes, irrecoverably wiping all PostgreSQL database tables, migrations, user records, and Redis AOF persistence logs. Never execute `docker compose down -v` unless an explicit, clean-slate teardown is deliberately intended.

### 7.4 Health & Connectivity Verification

- **PostgreSQL Readiness:**
  Healthcheck executes `pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}` every 5s.
  To verify manually from host:
  ```bash
  docker compose exec postgres pg_isready -U switchyard -d switchyard
  ```
- **Redis Readiness:**
  Healthcheck executes Redis ping, verifies `noeviction` memory policy, verifies AOF persistence (`aof_enabled:1`), and performs comprehensive ACL attestation using `redis-cli ACL DRYRUN` against the configured application user identity to confirm all prohibited commands (`FLUSHALL`, `FLUSHDB`, `CONFIG`, `DEBUG`, `SHUTDOWN`, `REPLICAOF`, `KEYS`, `ACL LIST`) are denied without executing target commands. It runs every 5s using the container's `REDISCLI_AUTH` environment variable (preventing command-line credential exposure).
  To verify manually from host:
  ```bash
  docker compose exec redis redis-cli ping
  ```

### 7.5 Persistence Verification

- **PostgreSQL Volume (`switchyard_postgres_data`):** Mounted to `/var/lib/postgresql/data`. Schema and data persist across container restarts and normal recreations (`docker compose down && docker compose up -d`).
- **Redis Volume (`switchyard_redis_data`):** Mounted to `/data` with AOF persistence enabled (`appendonly yes`, `appendfsync everysec`, `maxmemory-policy noeviction`).

### 7.6 Local Security Limitations

- **Loopback-Only Binding:** Both PostgreSQL and Redis are bound exclusively to host loopback (`127.0.0.1:5432` and `127.0.0.1:6379`) to prevent external network exposure.
- **Restricted Redis Identity & ACL Enforcement:** Redis enforces distinct operational administrator (`default`) and application (`switchyard_app`) identities. The application role is granted `+@all -@admin -@dangerous +info -FLUSHALL -FLUSHDB -CONFIG -DEBUG -SHUTDOWN -REPLICAOF -KEYS`, preventing unauthorized administrative and destructive operations as required by Architecture v1.2 §19.1.
- **Process Credential Masking & Docker Inspection Boundary:** Redis credentials are provided to `redis-server` via standard input stream and to `redis-cli` via `REDISCLI_AUTH`, avoiding password visibility in process table listings (`ps aux`) and suppressing CLI warning banners. However, environment variables remain visible via `docker inspect <container>`; therefore, this mechanism is strictly intended for local development. Production deployments must not rely on environment variables for sensitive secrets and must utilize external secret management with separate least-privilege database roles as defined in Architecture v1.2 §19.
- **Development Credentials:** The default credentials (`switchyard_dev_password`, `switchyard_app_password`) are strictly intended for local development.

### 7.7 Database Bootstrap, Migrations, and Roles (SW-1.3.1, SW-1.3.2)

Two separate steps are required, in this order. Role provisioning is a privileged, one-time
cluster operation; schema migrations are ordinary forward-only migrations executed by an
unprivileged deployment role.

#### 7.7.1 Step 1 — provision roles (superuser, once per cluster/database)

```bash
# Reads POSTGRES_* (optionally BOOTSTRAP_POSTGRES_USER/PASSWORD) from the environment.
# Requires a superuser session.
pnpm --filter @switchyard/gateway bootstrap:roles
```

`apps/gateway/src/db/bootstrap/provision-roles.sql` is idempotent: it creates the roles if
absent and then re-asserts every security attribute, so it doubles as the drift-reconciliation
path. It also performs the superuser-only schema work:

- `REVOKE CREATE ON SCHEMA public FROM PUBLIC`
- `GRANT USAGE, CREATE ON SCHEMA public TO gateway_owner, gateway_migrator`
- `GRANT USAGE ON SCHEMA public TO gateway_startup, gateway_app, gateway_worker`
- creates `app_private` owned by `gateway_owner`, with no `PUBLIC` privilege

Role passwords are **not** created by this script; set deployment credentials separately per
Architecture v1.2 §19.2.

#### 7.7.2 Step 2 — apply migrations (as `gateway_migrator`)

```bash
pnpm --filter @switchyard/gateway migrate
```

`apps/gateway/src/db/migrate.ts` applies `apps/gateway/src/db/migrations/NNNN-name.sql` into the
`gateway_migrations` ledger, each file in its own transaction. `gateway_migrator` holds no
`CREATEROLE`/`SUPERUSER`; it only owns `gateway_migrations` and may `SET ROLE gateway_owner` to
apply tenant-table DDL.

Migration set: `0001-roles` (idempotent no-op when bootstrap ran first), `0002-org-tables`
(six core tables), `0003-rls-default-deny`, `0004-gateway-control-privileges`,
`0005-virtual-key-integrity`, `0006-schema-privilege-hardening`,
`0007-financial-observability-tables` (gateway_requests, provider_attempts, adjustments, trace_payloads),
`0008-financial-integrity` (financial immutability, append-only adjustments, monetary bounds). `0001`/`0002` are historical
and byte-frozen; corrections are forward-only migrations.

#### 7.7.3 Integrity: checksums and fail-closed history

Each ledger row stores the SHA-256 of the exact file bytes. Before applying anything the runner
validates the whole history and fails closed (`MigrationError` with a stable code):

| Condition | Code |
| --- | --- |
| Applied file missing from the directory | `MIGRATION_FILE_MISSING` |
| Applied file bytes changed | `MIGRATION_CHECKSUM_MISMATCH` |
| Ledger name differs from file name | `MIGRATION_NAME_MISMATCH` |
| Pending version older than the highest applied version | `MIGRATION_ORDER_INVALID` |
| Duplicate or non-contiguous versions in the directory | `MIGRATION_DUPLICATE_VERSION` / `MIGRATION_ORDER_INVALID` |
| Applied row has no checksum (pre-checksum ledger) | `MIGRATION_LEGACY_CHECKSUM_MISSING` |
| Advisory lock wait exceeded | `MIGRATION_LOCK_TIMEOUT` |
| A migration statement failed (transaction rolled back) | `MIGRATION_APPLY_FAILED` |

Installations created before checksums existed can be reconciled non-destructively:

```bash
pnpm --filter @switchyard/gateway migrate:adopt-legacy
```

This records the checksum of the **unmodified** file for each NULL-checksum row and emits an
`adopted` event per version. It never invents a checksum, never rewrites an applied version, and
never runs implicitly — without the flag the run fails closed.

#### 7.7.4 Concurrency: advisory lock

The runner takes a session-level advisory lock (`pg_advisory_lock(7312000001)`) on the **same
connection** that inspects history and applies migrations, with `lock_timeout` (default 10 s,
`lockTimeoutMs` override) so a stuck peer cannot block deployment forever. The lock is released
in `finally` on success, failure, and backend termination; an interrupted migration rolls back
and leaves no ledger row. A real three-way concurrent-runner test asserts each migration is
applied exactly once.

#### 7.7.5 Role matrix (Architecture v1.2 §12.1)

| Role | Login | Superuser | BypassRLS | Purpose |
| --- | --- | --- | --- | --- |
| `gateway_owner` | no | no | no | owns tenant tables and `app_private` |
| `gateway_migrator` | yes | no | no | deployment-only migrations; member of `gateway_owner` |
| `gateway_startup` | yes | no | no | startup/epoch; `SELECT` + `UPDATE (gateway_epoch)` on `gateway_control` |
| `gateway_app` | yes | no | no | request path; `SELECT` only on `gateway_control` |
| `gateway_worker` | yes | no | no | background work; no `gateway_control` privilege in Batch A |
| `gateway_auth_executor` | no | no | yes | owns future restricted authentication functions only |
| `gateway_ops_executor` | no | no | yes | owns the future restricted maintenance enumerator only |

Runtime roles hold **no** privilege on `organizations`, `users`, `web_sessions`,
`provider_keys`, or `virtual_keys`, no `CREATE` on `public` or `app_private`, and no membership
that would let them assume the owner or an executor. `gateway_control` grants are exactly
`SELECT` to `gateway_app`/`gateway_startup` plus column-scoped `UPDATE (gateway_epoch)` to
`gateway_startup`.

#### 7.7.6 Row-level security posture (Batch A: default deny, not isolation)

Tenant tables keep `ENABLE` + `FORCE ROW LEVEL SECURITY` with **zero policies**. That is a
deliberate default-deny posture: every non-bypassing role — including the table owner — sees no
rows and can write none. It is **not** tenant isolation and must not be described as such.

`0002-org-tables.sql` originally created two permissive policies per table (one carrying
`USING`, one carrying `WITH CHECK`); PostgreSQL ORs permissive policies, so that was not a
validated guarantee. `0003-rls-default-deny.sql` drops them. Comprehensive tenant policies, the
tenant-context helper, and per-role table grants are **Subphase 1.4** (SW-1.4.1/SW-1.4.2) work.
`gateway_control` is the only global table and intentionally has no RLS.

#### 7.7.7 Financial Immutability and Integrity (SW-1.3.4)

Established on top of accepted prerequisite SW-1.3.3 (`a193e12f0e270720fb37e1ec10c1a94dcaadadb6`),
migration `0008-financial-integrity.sql` hardens the financial ledger:

- **Immutable Billing Period & Admission Consistency:** `gateway_requests` enforces
  `CHECK (billing_period = to_char(admitted_at AT TIME ZONE 'UTC', 'YYYY-MM'))` and a `BEFORE UPDATE`
  trigger preventing modification to `billing_period`, `request_id`, `org_id`, `virtual_key_id`,
  `admitted_at`, and gateway epoch/instance metadata. Terminal status cannot be regressed.
- **Immutable Terminal Attempt Base Costs:** `provider_attempts` protects terminal rows
  (`status IN ('settled', 'interrupted')`) against mutations to `estimated_cost_microdollars`,
  `actual_cost_microdollars`, `cost_status`, `billing_period`, and identity fields. Status regressions
  back to `reserved` and terminal status flips are rejected.
- **Append-Only Cost Adjustments:** `provider_cost_adjustments` rejects all `UPDATE`, `DELETE`, and
  `TRUNCATE` operations via database triggers. Inserting an adjustment targeting an active `reserved`
  attempt is rejected (`23514`); adjustments require a terminal attempt.
- **Monetary Integrity & Authoritative Accounting (DB-22):** Architecture v1.2 §5.2 #3 applies
  the \$1 billion (`1,000,000,000,000,000` microdollars) bound to organization monthly budgets and Redis
  intermediate counters. In PostgreSQL, individual attempts and adjustments are not subject to an artificial
  \$1B cap; PostgreSQL is the canonical financial ledger (§5.2 #6) and must faithfully record actual costs
  and overspend (§5.2 #9) representable in BIGINT (`0 <= cost <= 9,223,372,036,854,775,807`) while strictly
  enforcing nonnegative bounds and integer-only arithmetic. Redis rejects or closes admission when
  intermediate balances exceed safe bounds; PostgreSQL never discards legitimate authoritative billing evidence.
- **Database vs Service Concurrency Boundaries (DB-24):** Database tests attest to PostgreSQL-level
  row immutability, check constraints, append-only triggers, and migration advisory lock serialization.
  Complete cross-store financial adjustment transaction serialization (locking organization/period scope,
  verifying prior canonical cost across stores, and applying Redis Lua deltas) is deferred to the
  financial service layer in Phase 2+.
- **RLS Default-Deny Posture:** RLS remains enabled and forced with zero permissive policies; runtime
  roles hold zero table privileges until Subphase 1.4.

#### 7.7.8 Transaction-Scoped Tenant Context & RLS Policies (SW-1.4.1 & SW-1.4.2)

Established on top of accepted prerequisite Subphase 1.3 (`1b13bbe464fbfa2ec9bd3b361ab36ecfae12096a`),
Subphase 1.4 Batch A delivers transaction-scoped tenant isolation and least-privilege PostgreSQL role grants.

##### 1. `withTenant(pool, orgId, callback)` Contract

Defined in `apps/gateway/src/db/tenant.ts`, `withTenant` executes tenant-scoped operations within a dedicated database transaction:

```typescript
export interface TenantClient {
  query<R extends pg.QueryResultRow = any, I extends any[] = any[]>(
    queryTextOrConfig: string | pg.QueryConfig<I>,
    values?: I,
  ): Promise<pg.QueryResult<R>>;
  escapeIdentifier(str: string): string;
  escapeLiteral(str: string): string;
}

export async function withTenant<T>(
  pool: Pool,
  orgId: string,
  callback: (client: TenantClient) => Promise<T>
): Promise<T>;
```

- **UUID Validation:** `orgId` is validated fail-closed upfront (`/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i`). Invalid tenant IDs throw `InvalidTenantIdError` without acquiring a pool client.
- **Protocol-Enforced Single-Statement Execution & Lexical Guard (DB-27, DB-30):**
  - In `tenantClient.query()`, `withTenant` unconditionally enforces PostgreSQL's extended query protocol (`queryMode: 'extended'`). Under extended query protocol, PostgreSQL natively rejects any multi-statement command string with SQLSTATE `42601` (`cannot insert multiple commands into a prepared statement`). Caller-supplied `queryMode` in `QueryConfig` cannot override this.
  - In addition, leading comment/whitespace stripping (`stripLeadingCommentsAndWhitespace`, supporting nested block comments per PostgreSQL 16) and `standard_conforming_strings`-aware lexical inspection reject standalone and embedded transaction control commands (`BEGIN`, `COMMIT`, `ROLLBACK`, `START TRANSACTION`, `END`, `ABORT`, `SAVEPOINT`, `RELEASE`, `PREPARE TRANSACTION`) before dispatch.
- **Confirmed COMMIT Verification (DB-26):** `withTenant` inspects PostgreSQL's command completion tag upon `COMMIT`. If PostgreSQL returns `ROLLBACK` (which occurs when `COMMIT` is executed on an aborted transaction block whose error was swallowed inside the callback), `withTenant` immediately throws `TenantTransactionError` and marks the transaction failed, guaranteeing that aborted transactions never silently report success.
- **AsyncLocalStorage Isolation & Lifetime (DB-29):** Active tenant context is tracked in `AsyncLocalStorage`. Inactive context state prevents detached asynchronous continuations from executing queries through stale `TenantClient` references or mistaking finished transactions for active ones. `getActiveTenantContext()` exposes only `{ orgId }` (never the raw client). Nested active `withTenant` calls are rejected.
- **Transaction-Local GUC:** Sets PostgreSQL application context `app.current_org_id` transaction-locally (`is_local = true`):
  ```sql
  SELECT pg_catalog.set_config('app.current_org_id', $1, true);
  ```
  Because `is_local = true`, the parameter automatically reverts when the transaction ends (commit or rollback).
- **Connection Hygiene, Pool Invalidation & Session Cleanup (DB-31, DB-33, DB-34):**
  - Client release is intercepted during the callback to prevent premature release.
  - **Connection Release Invariant (DB-31, DB-34):** No reusable pooled connection may retain tenant identity from a completed transaction. Outside an active transaction upon completion, `withTenant` issues `RESET ALL` and `DISCARD TEMP` to purge session-level GUC overrides (such as `SET app.current_org_id = ...` or `set_config('app.current_org_id', ..., false)`) and session temporary tables without destroying server-side prepared statements cached on client connections by `node-postgres` (DB-34 SQLSTATE `26000` prevention).
  - It then explicitly verifies `SELECT pg_catalog.current_setting('app.current_org_id', true) AS cur_org`. If residual context is detected or cleanup throws, the connection is marked uncertain and destroyed via `client.release(true)`.
  - **Confirmed COMMIT Durability & Diagnostic Reporting (DB-33):** Once PostgreSQL confirms `COMMIT`, the transaction has durably succeeded. If post-commit connection cleanup fails thereafter, the contaminated connection is invalidated via `client.release(true)`, and the cleanup incident is reported via diagnostics (`WithTenantOptions.onCleanupError` or `process.emitWarning`) without throwing a false transaction error that would cause callers to retry already committed operations.
  - On confirmed rollback, the clean idle connection is returned to the pool after session cleanup.
  - On uncertain connection state (unhandled commit failure, failed rollback, or unconfirmed outcome), the connection is destroyed via `client.release(true)`.
  - **Residual Limitations:** Custom GUCs provide application context, not cryptographic tokens (§12.6). A process compromised by arbitrary code execution could manipulate memory or execute queries directly; defense-in-depth requires strict input parameterization and application sandbox isolation.

##### 2. Migration `0009-tenant-rls-policies.sql` & Unified Policy Architecture

Migration `0009-tenant-rls-policies.sql` establishes:

- **Row-Level Security Posture:** Asserts `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` across all 9 tenant-owned tables (`organizations`, `users`, `web_sessions`, `provider_keys`, `virtual_keys`, `gateway_requests`, `provider_attempts`, `provider_cost_adjustments`, `trace_payloads`). `FORCE RLS` ensures policies apply even to table owner `gateway_owner`.
- **Unified Permissive Policies (DB-04 Guard):** Exactly one permissive policy per table (`FOR ALL TO PUBLIC USING (...) WITH CHECK (...)`). This permanently avoids the PostgreSQL vulnerability where multiple permissive policies are evaluated with logical `OR`. If `app.current_org_id` is unset or empty, the predicate evaluates to `NULL` (falsy), denying all access by default.
- **Least-Privilege Role Grants:**
  - `gateway_app`: Tenant-scoped CRUD on data/control plane tables; denied `DELETE` on financial ledger tables; denied `UPDATE`/`DELETE` on append-only adjustments.
  - `gateway_worker`: Non-secret metadata on organizations/provider keys; insert/update on attempts, adjustments, traces; secret columns (`wrapped_dek`, `ciphertext`, IVs, auth tags) and user/session tables strictly revoked/denied.
  - `gateway_startup` & `PUBLIC`: Zero table grants on all tenant tables.
  - Runtime roles possess no `BYPASSRLS` attribute and cannot alter RLS policies.

##### 3. Migration `0010-privileged-bootstrap-functions.sql` & Privileged Functions (SW-1.4.3 & SW-1.4.4)

Migration `0010-privileged-bootstrap-functions.sql` establishes secure, narrowly scoped `SECURITY DEFINER` functions in the `app_private` schema to support pre-tenant authentication lookups and background maintenance enumeration without granting broad cross-tenant `SELECT` permissions to runtime roles (Architecture §12.4).

- **Function Interfaces and Signatures:**
  1. `app_private.lookup_virtual_key_by_hash(p_key_hash BYTEA)`:
     - **Owner:** `gateway_auth_executor` (`NOLOGIN BYPASSRLS`).
     - **Purpose:** Resolves a virtual API key by exact 32-byte SHA-256 hash before tenant context is known.
     - **Return contract:** Minimal authorization columns only (`id`, `org_id`, `revoked_at`, `allowed_models`, `rpm_limit`, `tpm_limit`, `concurrent_stream_limit`, `exact_cache_enabled`, `semantic_cache_enabled`, `pii_redaction_enabled`, `store_payloads`). Returns zero rows for NULL, empty, malformed, or non-matching hashes. Never exposes plaintext keys, key hashes, DEKs, or provider secrets.
     - **EXECUTE:** Granted strictly to `gateway_app`. Denied to `gateway_worker`, `gateway_startup`, and `PUBLIC`.
  2. `app_private.lookup_user_for_login(p_email_normalized TEXT)`:
     - **Owner:** `gateway_auth_executor` (`NOLOGIN BYPASSRLS`).
     - **Purpose:** Resolves user identity for authentication by globally unique canonical normalized email before tenant context exists.
     - **Return contract:** Minimal login columns only (`id`, `org_id`, `role`, `password_hash`). Returns zero rows for NULL, empty, oversized (> 255 chars), noncanonical (mixed-case, leading/trailing whitespace, missing `@`), or non-matching emails. Never exposes session tokens, CSRF secrets, or DEKs. Note that `password_hash` is intentionally returned because the trusted authentication handler in SW-1.5.1 requires the stored Argon2id verifier string to authenticate credentials.
     - **EXECUTE:** Granted strictly to `gateway_app`. Denied to `gateway_worker`, `gateway_startup`, and `PUBLIC`.
  3. `app_private.create_organization_with_admin(p_org_id UUID, p_org_name TEXT, p_monthly_budget_microdollars BIGINT, p_kek_version INT, p_wrapped_dek BYTEA, p_dek_iv BYTEA, p_dek_auth_tag BYTEA, p_admin_user_id UUID, p_admin_email_normalized TEXT, p_admin_password_hash TEXT)`:
     - **Owner:** `gateway_auth_executor` (`NOLOGIN BYPASSRLS`).
     - **Purpose:** Atomically provisions a new organization and its initial administrator (`role = 'admin'`) before a tenant-scoped session exists.
     - **Return contract:** Confirmation record of two UUIDs (`org_id UUID`, `admin_user_id UUID`).
     - **Atomicity & Validation:** Strict validation fails closed with SQLSTATE `22004` (null IDs) and `22023` (invalid parameters, bounded budget up to $10^{15}$ microdollars, non-empty DEKs). Enforces canonical email normalization (lowercase, trimmed, valid email format, $\le 255$ chars; DB-36) and complete Argon2id PHC verifier representation validation (algorithm `argon2id`, version `v=19`, required positive integer parameters `m, t, p`, and non-empty separate salt and derived-hash tokens; DB-37, DB-39). Any uniqueness or persistence failure rolls back both inserts atomically, guaranteeing no orphan organizations or orphaned admin users.
     - **EXECUTE:** Granted strictly to `gateway_app`. Denied to `gateway_worker`, `gateway_startup`, and `PUBLIC`.
  4. `app_private.list_active_org_ids(p_after_id UUID DEFAULT NULL, p_limit INT DEFAULT 100)`:
     - **Owner:** `gateway_ops_executor` (`NOLOGIN BYPASSRLS`).
     - **Purpose:** Enumerates organization UUIDs for background worker maintenance tasks (recovery, retention, reconciliation).
     - **v1 Active Organization Interpretation:** Under accepted v1 design, every row currently existing in `public.organizations` is eligible for enumeration. No `is_active` column or artificial lifecycle is introduced.
     - **Return contract:** Exactly one column: `org_id UUID`. Strictly prohibits organization names, budgets, DEKs, or timestamps.
     - **Pagination:** Deterministic keyset pagination ordered strictly by `id ASC`. The cursor (`p_after_id`) is exclusive (`id > p_after_id`). Limit is strictly bounded between 1 and 100; invalid limits fail closed with SQLSTATE `22023`.
     - **EXECUTE:** Granted strictly to `gateway_worker`. Denied to `gateway_app`, `gateway_startup`, and `PUBLIC`.

- **Privileged Installation & Deployment Mechanism:**
  - `provision-roles.sql` grants role membership in `gateway_auth_executor` and `gateway_ops_executor` to deployment-only role `gateway_migrator` with explicit `WITH INHERIT FALSE, SET TRUE, ADMIN FALSE`.
  - `gateway_migrator` remains `NOCREATEROLE`, `NOSUPERUSER`, and `NOBYPASSRLS`. It explicitly assumes executor roles via `SET ROLE` within migration transactions.
  - `provision-roles.sql` grants `USAGE, CREATE ON SCHEMA app_private` to `gateway_owner`, `gateway_migrator`, `gateway_auth_executor`, and `gateway_ops_executor`. Runtime roles (`gateway_app`, `gateway_worker`, `gateway_startup`) and `PUBLIC` receive zero `CREATE` privilege on `app_private`.
  - Migration `0010` includes a fail-closed pre-flight assertion (`pg_has_role(CURRENT_USER, 'gateway_auth_executor', 'SET')`) verifying role assumption before applying DDL.
  - Public execution is revoked (`REVOKE ALL FROM PUBLIC`) within the same transaction as function creation.
- **Executor Column-Level Table Grants:**
  - `gateway_auth_executor`: Column-level `SELECT` on `virtual_keys` and `users`; column-level `INSERT` on `organizations` and `users`; `SELECT (id)` for `RETURNING`. Zero `UPDATE`, `DELETE`, or `TRUNCATE`.
  - `gateway_ops_executor`: Column-level `SELECT (id)` on `organizations` only. Zero access to any other column or table.
- **Fresh Bootstrap & Upgrade Procedure:**
  - **Fresh Bootstrap:** Superuser runs `pnpm bootstrap:roles --apply` (or Docker Compose entrypoint `01-provision-roles.sql`). Deployment role runs `pnpm migrate` applying migrations `0001` through `0010`.
  - **Version Upgrade (0009 -> 0010):** Superuser reconciles role memberships by executing `pnpm bootstrap:roles --apply`. Deployment role applies `pnpm migrate`. If `bootstrap:roles` was omitted, migration `0010` fails closed with SQLSTATE `42501`.
- **Known Limitations & Phase 1.5 Dependencies:**
  - Password hashing verification via Argon2id, dummy timing verification, login rate limiting, and generic auth responses belong to SW-1.5.1.
  - Server-side cookie sessions and CSRF synchronizer token protection belong to SW-1.5.2 and SW-1.5.3.
  - Application-level bootstrap self-enrollment controls and rate limits belong to SW-1.5.1.
  - Background maintenance execution with per-organization advisory locking belongs to Phase 2.

##### 4. Migration `0011-session-tenant-lookup.sql` & Pre-Tenant Session Lookup (ADR 0001, SW-1.5.2)

Migration `0011-session-tenant-lookup.sql` introduces an authorized, narrowly scoped `SECURITY DEFINER` function in the `app_private` schema to resolve tenant organization IDs from opaque browser session cookies without bypassing PostgreSQL Row-Level Security (ADR 0001, Architecture §12.4).

- **Function Interface and Signature:**
  - `app_private.lookup_session_org_by_hash(p_session_id_hash BYTEA)`:
    - **Owner:** `gateway_auth_executor` (`NOLOGIN BYPASSRLS`).
    - **Purpose:** Resolves tenant organization UUID from a 32-byte SHA-256 session verifier hash before tenant context is known.
    - **Return contract:** Exactly one column: `org_id UUID`. Zero or one row returned. Rejects NULL, empty, or wrong-length hashes fail-closed by returning zero rows. Never returns user IDs, CSRF tokens, expiration timestamps, or session secrets.
    - **EXECUTE:** Granted strictly to `gateway_app`. Denied to `gateway_worker`, `gateway_startup`, and `PUBLIC`.
- **Privilege & Schema Security:**
  - `gateway_auth_executor` receives minimal column-level `SELECT (session_id_hash, org_id)` on `public.web_sessions`.
  - Search path hardened to `pg_catalog, app_private, pg_temp` to prevent `pg_temp` object shadowing attacks.
  - Zero `BYPASSRLS` privileges granted to runtime roles; `public.web_sessions` maintains `FORCE ROW LEVEL SECURITY`.
- **Authentication & Session Services (SW-1.5.1 & SW-1.5.2):**
  - **Password Security:** Argon2id (`v=19`, `m=19456`, `t=2`, `p=1`) via `@node-rs/argon2`. Maximum 128-byte UTF-8 password cap with zero silent truncation.
  - **Argon2 Concurrency Limiter:** Shared semaphore bounding concurrent hashing operations (default 4) with bounded queue capacity (default 16) and timeout (5000ms), failing closed on overload.
  - **Email Normalization:** Canonical trimmed lowercase email matching `^[^@\s]+@[^@\s]+$` with maximum 255 characters.
  - **Login Abuse Protection:** Redis rate-limiting enforcing per-IP (30 / 15m) and per-account (5 / 15m) limits before expensive password operations. Irreversible SHA-256 account keys; fails closed on Redis downtime.
  - **Timing Equalization:** Dummy verification using genuine Argon2id hash on nonexistent accounts to mitigate enumeration.
  - **Session Lifecycle:** 256-bit opaque random secret in `__Host-session` cookie; SHA-256 verifier persistence; idle (2h) and absolute (7d) expiration; atomic rotation; user session revocation.
  - **Internal Bootstrap Service:** Typed internal service interface executing `app_private.create_organization_with_admin` atomically; public self-registration remains deferred until SW-1.7.
- **CSRF & Strict Origin Protection (SW-1.5.3):**
  - **Synchronizer Token:** 256-bit unpadded base64url CSRF tokens verified via SHA-256 hash in constant time (`timingSafeEqual`).
  - **Origin Verification:** Strict canonical origin comparison (`BROWSER_ORIGIN`) for state-changing browser methods (`POST`, `PUT`, `PATCH`, `DELETE`).
- **Default-Deny Route Authorization & RBAC (SW-1.5.4):**
  - **Default-Deny Assertion:** Registration-time Fastify `onRoute` hook requiring explicit `config.authz` metadata on every route (`AUTHZ_ROUTE_POLICY_INVALID`).
  - **Principal Separation:** Strict non-interchangeable separation between `anonymous`, `browser` (server-side web session), and `virtual_key` (data-plane key authenticator).
  - **Browser RBAC:** Two-tier role hierarchy (`admin` and `member`) evaluated fresh from PostgreSQL on each request.
  - **Composition:** Unified preHandler hook enforcing Origin, session validation, CSRF, and role authorization for browser mutations.
  - **Registration Helper:** `registerAuthorizedRoute` typed entry point enforcing metadata contract before Fastify registration.
- **Virtual API Key Issuance (SW-1.6.1):**
  - **Key Generation & Verification:** 256-bit cryptographically secure generation (`crypto.randomBytes(32)`), independent 8-byte public hint (`crypto.randomBytes(8)`), canonical `gw_live_<11>_<43>` format (63 ASCII chars), and SHA-256 verifier storage (`virtual_keys.key_hash BYTEA UNIQUE`).
  - **Canonical Validation (VK-01):** Strict format parser (`parseRawKey`) enforces envelope shape, length, and canonical base64url encoding (re-encoding equality to reject noncanonical trailing padding bits).
  - **One-Time Plaintext Disclosure:** Plaintext raw key is returned exactly once from `VirtualKeyService.createKey()` upon confirmed transaction commit; zero raw key persistence, logging, caching, or recovery interfaces. Memory hygiene clears mutable byte buffers (`.fill(0)`) on a best-effort basis while immutable V8 strings persist until GC.
  - **Tenant Transaction Boundary:** All creations execute inside `withTenant(pool, orgId)` using `gateway_app`. Direct insertion without tenant context and cross-tenant insertions are rejected by RLS.
  - **Initial Deny-All Policy:** New keys default to `allowed_models = '{}'` (empty array), `rpm_limit = 1`, `tpm_limit = 1`, `concurrent_stream_limit = 1` (satisfying migration `0005`'s NOT NULL and positive checks), `exact_cache = false`, `semantic_cache = false`, `pii_redaction = true`, `store_payloads = false`, `revoked_at = NULL`.
  - **Bounded Collision Recovery (VK-02):** At most 3 attempts for qualifying unique constraint violations (`virtual_keys_key_hash_key`, `virtual_keys_pkey`, `virtual_keys_id_org_id_key`); missing or unrecognized constraint names and non-collision database errors fail closed immediately without retry.

- **Virtual API Key Authentication & Hash Lookup (SW-1.6.2):**
  - **Authenticator Service (`VirtualKeyAuthenticatorService`):** Implements `VirtualKeyAuthenticator`, validates keys via `parseRawKey()`, decodes 32-byte secret, derives SHA-256 verifier, and invokes `app_private.lookup_virtual_key_by_hash($1::bytea)` with parameter binding.
  - **Per-IP Abuse Rate Limiting (`VirtualKeyRateLimiter`):** Redis-backed atomic fixed-window counter under key `auth:ratelimit:vk:ip:<ip>` (30 attempts / 15-minute window), enforced before PostgreSQL lookup on every bearer authentication attempt.
  - **Restricted Database Lookup:** Resolves identity and policy via `app_private.lookup_virtual_key_by_hash(BYTEA)` (owned by `gateway_auth_executor`, SECURITY DEFINER, granted strictly to `gateway_app`).
  - **Uniform HTTP 401 Responses:** Exact status 401 and response body `{ "statusCode": 401, "error": "Unauthorized", "message": "Authentication required" }` for all invalid, missing, malformed, noncanonical, unknown, or revoked credentials and credential crossovers.
  - **Fail-Closed Reliability:** Yields generic 429 on abuse rate limiting and generic 503 on database or Redis outages and corrupted policy rows.
  - **Principal Immutability & Privacy:** Attaches frozen `VirtualKeyPrincipal` with typed `VirtualKeyPolicy` to `req.principal`. Excludes all secret material, raw keys, verifiers, and headers.
  - **Phase 2 Admission Requirement:** Initial authentication lookup resolves pre-tenant identity only. It does not replace the Phase 2 requirement to execute durable row-locking and re-checking inside attempt admission.

- **Admin-Only Virtual API Key Management & Policy Administration (SW-1.6.3):**
  - **Management Service (`VirtualKeyManagementService`):** Tenant-scoped creation, metadata listing with microsecond-precision keyset pagination, atomic policy replacement, and idempotent permanent revocation.
  - **Admin-Only Authorization & Origin/CSRF Guards:** Endpoints (`/api/keys`) restricted to browser sessions with `admin` role, enforcing canonical Origin and cryptographically verified CSRF tokens.
  - **One-Time Plaintext Disclosure:** Raw key disclosed strictly once on `POST /api/keys` response under `Cache-Control: no-store` and `Pragma: no-cache`.

- **Virtual Key Revocation, Secret Secrecy & Phase 2 Admission Contract (SW-1.6.4):**
  - **Uniform HTTP 401 Identity:** Exact error equivalence across all 12 negative credential cases with zero protected-handler execution.
  - **Concurrency Serialization:** Proven row-lock serialization (`SELECT ... FOR UPDATE`) between revocation and simulated provider-attempt admission under PostgreSQL 16.
  - **Stale Principal Invalidation:** Demonstrated that retention of an authenticated principal cannot bypass admission-time database row rechecks.
  - **Worker Privilege Containment:** Proved that `gateway_worker` role cannot insert, update, revoke, delete, or invoke pre-tenant hash lookups on virtual keys.
  - **Phase 2 Admission Seam:** Formally documented handoff in [`docs/architecture/phase2-admission-key-recheck.md`](./architecture/phase2-admission-key-recheck.md) tracking `SW-2.2.3` and Architecture v1.2 §6.3.

- **Provider Credential Envelope Vault Completion (SW-1.7.1 – SW-1.7.4):**
  - **Envelope Crypto Foundation (SW-1.7.1 & SW-1.7.2):** AES-256-GCM envelope vault, versioned environment KEKs (`MASTER_KEK_V1`, `MASTER_KEK_V2`), random 32-byte organization DEK, authenticated metadata (`dek:<org_id>:v<kek_version>` and `pk:<org_id>:<provider_key_id>:<provider>`), and `0x01` blob format marker.
  - **Admin-Only Provider Credential Management APIs (SW-1.7.3):**
    - REST routes under `/api/provider-keys` for creation, keyset-paginated metadata listing, atomic replacement, and soft disable.
    - Admin-only browser session requirement (`config: { authz: { principal: 'browser', minRole: 'admin' } }`), enforcing canonical Origin and cryptographically verified CSRF tokens on mutating requests.
    - Keyset pagination with microsecond UTC cursors, strict DTO allowlists excluding all secret-bearing columns, and mandatory `Cache-Control: no-store` headers.
    - Key hint policy deriving `****` + last 4 display characters for standard credentials and entirely masked `****` for credentials of 4 or fewer characters.
    - KEK gating: When KEKs are absent, management routes return controlled HTTP 503 (`Service Unavailable`), preserving non-vault startup compatibility.
  - **Decrypt-Path Scrubbing, Privacy Verification & Backup/Rotation Compatibility (SW-1.7.4):**
    - Proven intermediate Buffer zeroization on both success and error paths.
    - Synthetic canary privacy probes confirming zero plaintext credential leakage into application logs, error serialization, or HTTP responses.
    - Worker column privilege containment verified under PostgreSQL 16 (worker denied ciphertext, IV, auth tags, and wrapped DEK columns with SQLSTATE 42501).
    - Historical KEK compatibility verified across V1 and V2 coexistence; missing historical KEK fails closed.
    - Formal database backup and future KEK rotation specifications documented in `docs/SECURITY.md`.

#### 7.7.9 Known limitations (Phase 2)

- Virtual API key authentication resolves identity and policy at request entry; keys revoked after initial authentication must be caught and rejected by durable row-locking inside Phase 2 provider-attempt admission.
- `gateway_startup` may update `gateway_epoch` but not `updated_at`; the §12.1 column grant is
  literal, so epoch bumps leave `updated_at` stale. A trigger or a widened grant is a Phase 2
  decision, not a Batch A deviation.
- §12.5 requires the epoch to change only while holding the singleton session lock and the
  exclusive transaction advisory lock. Column grants cannot enforce lock ordering; that
  admission-protocol invariant is a Phase 2 implementation concern.

#### 7.7.10 Database integration tests

```bash
pnpm --filter @switchyard/gateway test:db   # or: pnpm test:db from the repo root
```

`apps/gateway/vitest.db.config.ts` runs `src/**/*.db.test.ts` serially. Each test file starts its
own throwaway `postgres:16.8-alpine` container on a random loopback port, creates
`switchyard_test_*` databases, runs the real bootstrap, and destroys the container. Guards refuse
`NODE_ENV=production`, any database name that is not `switchyard_test_*`, a non-loopback
`TEST_POSTGRES_ADMIN_URL` (unless `ALLOW_NON_LOOPBACK_TEST_PG=true` for a disposable CI cluster),
and any admin URL that is not the `postgres` maintenance database. The persistent development
database is never contacted. A missing Docker daemon or unreachable PostgreSQL **fails** the run;
nothing is skipped.

The default `pnpm test` suite excludes `*.db.test.ts`, and CI runs them in a separate required
`database-integration` job so they cannot silently drop out of the gate.

The older `pnpm --filter @switchyard/gateway test:integration` suite (live Compose PostgreSQL and
Redis, gated by `INTEGRATION_TESTS`) still exists for connectivity tests; it is not a substitute
for `test:db`.

#### 7.7.11 Six-Component Service Topology & Runtime Integration (SW-P1-B01)

Resolving Phase 1 acceptance blocker `ARCH-P1-01` (Architecture v1.2 §23), Switchyard provides a clean-clone Docker Compose environment containing all six mandatory components:

| Component | Technology | Process / Command | Network / Ports | Health Check |
|---|---|---|---|---|
| **Gateway** | Node.js Fastify API server | `node apps/gateway/dist/index.js` | `127.0.0.1:${PORT:-3000}:3000` | HTTP `GET /health/ready` |
| **Worker** | Node.js worker daemon | `node apps/gateway/dist/worker-main.js` | Internal only (0 host ports) | CLI `node dist/worker-main.js --health` |
| **Web** | Next.js App Router (standalone) | `node apps/web/server.js` | `127.0.0.1:${WEB_PORT:-3001}:3001` | HTTP `GET /health/ready` |
| **PostgreSQL** | PostgreSQL 16.8 | `docker-entrypoint.sh` | `127.0.0.1:${POSTGRES_PORT:-5432}:5432` | `pg_isready` |
| **Redis** | Redis 7.4.2 | `redis-server` (AOF + noeviction) | `127.0.0.1:${REDIS_PORT:-6379}:6379` | `redis-cli ping` + ACL attestation |
| **Mock Upstream** | Node.js OpenAI mock | `node apps/mock-upstream/dist/index.js` | Internal only (4000, 0 host ports) | HTTP `GET /health/ready` |

##### Manual Startup Commands:
- **Worker standalone:**
  ```bash
  pnpm --filter @switchyard/gateway start:worker
  ```
- **Web standalone:**
  ```bash
  pnpm --filter @switchyard/web dev      # Development mode
  pnpm --filter @switchyard/web build    # Production build
  pnpm --filter @switchyard/web start    # Production runtime
  ```
- **Docker Compose (all 6 services):**
  ```bash
  docker compose up -d
  ```

##### Worker Readiness & Observability Semantics (WRK-01, WRK-02, WRK-03, WRK-04, WRK-05, WRK-06, WRK-07, WRK-08):
- **Readiness State & Bounded Probes (WRK-01, WRK-04):** Worker health is governed by continuous, bounded dependency probes (`WORKER_PROBE_INTERVAL_MS` default 5000ms, timeout 2000ms). Both PostgreSQL (`SELECT 1` under `gateway_worker`) and Redis (`PING` under `switchyard_worker`) must be healthy for the worker to report `ready`. If either dependency fails or times out, readiness immediately transitions to `unhealthy`, returning non-zero from `worker-main.js --health`. Probe timeouts enforce real cancellation and detachment: PostgreSQL clients are returned or destroyed (`client.release(true)`) preventing pool exhaustion, Redis offline queue accumulation is disabled (`enableOfflineQueue: false`), and probe sequence generation fencing prevents delayed stale results from corrupting newer readiness states. Readiness automatically recovers when dependencies are restored, even after prolonged outages exceeding short retry budgets.
- **Underlying Resource Cleanup & Leak Prevention (WRK-07):** A strict distinction is enforced between wrapper probe completion and underlying I/O resource cleanup. When database connection acquisition or query execution times out, underlying sockets are forcibly terminated: timed-out PostgreSQL clients are destroyed via `client.release(true)` and late-arriving connection promises are tracked as abandoned and immediately destroyed upon arrival. Repeated probe timeouts never increase active client allocations or starve pool waiting queues.
- **Signal-Driven Graceful Shutdown & Container Recovery (WRK-08):** Worker container lifecycle handles `SIGTERM` / `SIGINT` signals with bounded shutdown (< 500ms), safely closing Redis and PostgreSQL client pools, unlinking the health state file `/tmp/switchyard-worker-health.json` to prevent stale readiness artifacts, and exiting with status code 0 well before container runtime grace periods expire (distinguished from SIGKILL exit 137). Restarted worker containers re-establish healthy connections and pass CLI health checks without manual intervention.
- **Heartbeat Freshness & Operational Bounds (WRK-05):** Probe intervals (100ms - 30000ms) and timeouts (50ms - 10000ms) are strictly validated with invariant `WORKER_PROBE_TIMEOUT_MS <= WORKER_PROBE_INTERVAL_MS`. Operational failure detection occurs within at most one probe cycle ($I + T \le 7\text{s}$ under default configuration). Heartbeat freshness threshold is coherently derived as $\max(3 \times I, I + 2 \times T)$ (default 15000ms), eliminating false expiration while rejecting genuinely stale processes.
- **Production Credential Validation (WRK-06):** In production profiles (`NODE_ENV=production`), default development credentials (`switchyard_worker_password`, `switchyard_dev_password`, `switchyard_app_password`, `password`, `postgres`, `admin`, `root`) are rejected fail-closed. Sensitive credentials are never echoed in error messages or logs.
- **Canary Redaction (WRK-02):** Configuration validation errors and startup logs strictly redact environment values and synthetic canaries using allowlisted error codes and safe serializers.
- **Service Attribution (WRK-03):** Worker structured logs are identified with `service: "@switchyard/worker"` and `name: "@switchyard/worker"`, distinguishing worker daemon logs from Gateway server logs.

#### 7.7.12 Explicit Development-Only Demo Account Seeding (SW-P1-B02)

The demo seeder provisions one organization and one initial administrator for local development. It is an explicit, short-lived foreground CLI and reuses the production bootstrap contract (`app_private.create_organization_with_admin` via `bootstrapOrganizationWithAdmin`) and the production envelope vault (`EnvelopeVault.createOrganizationEnvelope`). Docker Compose, migrations, the Gateway entrypoint, and the worker never invoke it, so a clean clone starts with zero organizations and zero users.

##### Prerequisites

1. PostgreSQL is running and the role bootstrap plus migrations have been applied (`pnpm --filter @switchyard/gateway bootstrap:roles`, then `pnpm migrate` from the repository root, or `docker compose up`).
2. `POSTGRES_PASSWORD` is the password of the restricted `gateway_app` runtime role.
3. A valid KEK is configured. The seeder uses `MASTER_KEK_V1`/`MASTER_KEK_V2` and `ACTIVE_KEK_VERSION` exactly like the Gateway vault.

##### Required configuration

| Variable | Required | Meaning |
|---|---|---|
| `NODE_ENV` | yes | Must be exactly `development`; `production`, `test`, and missing values fail closed before any connection. |
| `DEMO_SEEDING_ENABLED` | yes | Must be exactly `true`. No default enablement. |
| `DEMO_ORG_ID` | yes | Canonical lowercase UUID. Reusing the same value makes invocations idempotent. |
| `DEMO_ORG_NAME` | yes | 1–255 characters, no control characters. Only applied on first creation. |
| `DEMO_ADMIN_EMAIL` | yes | Canonical email: trimmed, lowercase, at most 255 characters. |
| `DEMO_MONTHLY_BUDGET_MICRODOLLARS` | no | Nonnegative base-10 integer up to `1000000000000000`; defaults to `0`. Only applied on first creation. |
| `DEMO_SEEDING_TARGET` | no | `local` (default) or `compose`. See target restrictions below. |
| `POSTGRES_HOST` | no | `127.0.0.1`, `localhost`, or `::1` for `local`; exactly `postgres` for `compose`. |
| `POSTGRES_PORT` | no | Defaults to `5432`. |
| `POSTGRES_DB` | no | Defaults to `switchyard`. |
| `POSTGRES_USER` | yes | Must be exactly `gateway_app`; privileged, migrator, executor, and worker roles are rejected. |
| `POSTGRES_PASSWORD` | yes | Password for `gateway_app`. Never printed. |
| `MASTER_KEK_V1` / `MASTER_KEK_V2`, `ACTIVE_KEK_VERSION` | yes | Same canonical 32-byte base64url KEK contract as the Gateway. |

Connection overrides (`DATABASE_URL`, `PG*`, `MIGRATE_POSTGRES_*`, `BOOTSTRAP_POSTGRES_*`) are rejected rather than prioritized. After connecting, the seeder also verifies the effective `current_user`/`session_user` is the non-superuser, non-`BYPASSRLS` `gateway_app` role.

##### Host (local PostgreSQL) invocation

```bash
export NODE_ENV=development
export DEMO_SEEDING_ENABLED=true
export DEMO_ORG_ID=11111111-1111-4111-8111-111111111111
export DEMO_ORG_NAME="Local Demo Organization"
export DEMO_ADMIN_EMAIL=demo-admin@example.test
export POSTGRES_USER=gateway_app
export POSTGRES_PASSWORD=...
export MASTER_KEK_V1=...        # 32 random bytes, base64url
export ACTIVE_KEK_VERSION=1

# Read the administrator password from stdin. Use printf, not echo: a trailing
# newline is part of the password because input is never trimmed.
printf '%s' "$DEMO_ADMIN_PASSWORD" | pnpm seed:dev
```

`pnpm seed:dev` compiles the Gateway package and then executes the compiled CLI, so it always reflects the current source. In the Docker Compose runner image, invoke the already-compiled `apps/gateway/dist/db/seed-dev.js` directly (shown below).

##### Approved Docker Compose invocation

Inside the Compose network the database host is `postgres`, so `DEMO_SEEDING_TARGET=compose` is required. The command must attach to the existing `gateway` service definition (which already supplies `NODE_ENV=development`, `POSTGRES_HOST=postgres`, the `gateway_app` role and the database password) and must pass the demo/KEK variables explicitly:

```bash
docker compose up -d

export DEMO_ORG_ID=11111111-1111-4111-8111-111111111111
export DEMO_ORG_NAME="Local Demo Organization"
export DEMO_ADMIN_EMAIL=demo-admin@example.test
export DEMO_SEEDING_TARGET=compose
export MASTER_KEK_V1=...
export ACTIVE_KEK_VERSION=1

# -e NAME (without a value) copies the variable from the exported environment, so the
# KEK is not exposed in the process argument list.
printf '%s' "$DEMO_ADMIN_PASSWORD" | docker compose run --rm --no-deps -T \
  -e NODE_ENV=development \
  -e DEMO_SEEDING_ENABLED=true \
  -e DEMO_ORG_ID \
  -e DEMO_ORG_NAME \
  -e DEMO_ADMIN_EMAIL \
  -e DEMO_SEEDING_TARGET \
  -e MASTER_KEK_V1 \
  -e ACTIVE_KEK_VERSION \
  gateway node apps/gateway/dist/db/seed-dev.js
```

`-T` disables TTY allocation so the password arrives on a pipe. No default password exists, command-line arguments are rejected, and interactive stdin is refused because the CLI does not implement a no-echo prompt.

##### Idempotency and conflict semantics

| Status | Meaning | Database effect |
|---|---|---|
| `CREATED` | No account with `DEMO_ADMIN_EMAIL` existed; organization and admin were created atomically. | One organization and one admin inserted. Only the first run applies the name, budget, envelope, and password. |
| `ALREADY_PRESENT` | The canonical email already belongs to an `admin` in `DEMO_ORG_ID`. | No writes. Password, role, name, budget, and envelope are preserved. |
| `CONFLICT` | The email belongs to another organization, a non-admin role, or the organization UUID is already taken. | No writes. Resolve the collision manually; the seeder never adopts, promotes, or rewrites identities. |

Concurrent invocations converge on exactly one organization and one admin: the database function is atomic, and a duplicate-key race is re-verified before reporting `ALREADY_PRESENT` or `CONFLICT`.

##### Exit codes

| Code | Meaning |
|---|---|
| `0` | `CREATED` or `ALREADY_PRESENT`. |
| `1` | Operational failure (connection, privilege, or unexpected database error). Only an allowlisted error code is printed. |
| `2` | Invalid configuration, unsupported arguments, or invalid/empty/oversized password. Rejected before any database connection. |
| `3` | `CONFLICT`. The network/configuration were valid; no data was changed. |

##### Verification

- `apps/gateway/src/db/seed-dev.test.ts` — configuration matrix, bounded stdin handling, exit codes, secret redaction, and absence of HTTP/Redis/singleton-lock dependencies.
- `apps/gateway/src/db/seed-dev.db.test.ts` — real PostgreSQL 16: first creation, login through `AuthenticationService`, DEK envelope round-trip and tamper resistance, RLS, idempotent repeat, concurrency, conflicts, and zero orphan records.
- `apps/gateway/src/db/seed-dev.compose.db.test.ts` — isolated six-service Compose project: no implicit seeding, explicit `CREATED`, repeat `ALREADY_PRESENT`, `CONFLICT`, production rejection, restart persistence, and secret-free worker/web environments.

##### Limitations

- The seeder provisions one demo organization and one admin. It is not a general user-management or registration API.
- Re-running does not rotate the password or update name/budget. Use the normal authenticated administrative flows for later changes.
- The password arrives as an immutable JavaScript string and cannot be deterministically zeroized; temporary byte buffers are cleared, but V8 strings persist until garbage collection.
- Loss of the KEK used at creation makes the organization DEK unrecoverable, exactly as for any Gateway-created organization.
