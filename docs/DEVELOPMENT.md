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
| `REDIS_PASSWORD` | `switchyard_dev_password` | Redis admin authentication password | Injected via stdin/environment for administrative/ops use |
| `REDIS_APP_USER` | `switchyard_app` | Restricted Redis application user | Runtime ACL user for application services |
| `REDIS_APP_PASSWORD` | `switchyard_app_password` | Restricted Redis application password | Runtime ACL password with prohibited administrative commands |
| `REDIS_PORT` | `6379` | Host loopback port for Redis | Bound to `127.0.0.1` |
| `REDIS_MAXMEMORY` | `64mb` | Redis memory allocation bound | Provisional development baseline; not benchmark-validated (production sizing requires Phase 2 load testing under `bench/`) |

### 7.3 Service Management Commands

#### Safe Startup
```bash
docker compose up -d
```
Starts PostgreSQL and Redis in detached mode on the private `switchyard-network`.

#### Status & Health Inspection
```bash
docker compose ps
```
Displays container state, port bindings, and healthcheck status (`healthy` / `starting` / `unhealthy`).

#### Service Logs
```bash
docker compose logs -f [postgres|redis]
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
`0005-virtual-key-integrity`, `0006-schema-privilege-hardening`. `0001`/`0002` are historical
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

#### 7.7.7 Known limitations (Phase 2)

- `gateway_startup` may update `gateway_epoch` but not `updated_at`; the §12.1 column grant is
  literal, so epoch bumps leave `updated_at` stale. A trigger or a widened grant is a Phase 2
  decision, not a Batch A deviation.
- §12.5 requires the epoch to change only while holding the singleton session lock and the
  exclusive transaction advisory lock. Column grants cannot enforce lock ordering; that
  admission-protocol invariant is a Phase 2 implementation concern.

#### 7.7.8 Database integration tests

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
