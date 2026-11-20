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

### 7.7 Database Migrations and Roles (SW-1.3.1, SW-1.3.2)

The migration process applies versioned SQL migrations from `apps/gateway/src/db/migrations/` (`NNNN-name.sql`) into the `gateway_migrations` ledger table, in version order, each in its own transaction (`apps/gateway/src/db/migrate.ts`).

- Apply pending migrations from the gateway package root:

  ```bash
  pnpm --filter @switchyard/gateway migrate
  ```

- Local development runs migrations as the database superuser (`switchyard`); reruns are idempotent (no new ledger rows).
- After applying `0001-roles` locally, grant the tenant-table owner schema creation once (the migration `0002-org-tables` creates tenant tables via `SET ROLE gateway_owner`):

  ```bash
  docker exec switchyard-postgres psql -U switchyard -d switchyard -c "GRANT CREATE ON SCHEMA public TO gateway_owner;"
  pnpm --filter @switchyard/gateway migrate
  ```

  The `organizations`, `gateway_control`, `users`, `web_sessions`, `provider_keys`, and `virtual_keys` tables created by `0002-org-tables` are owned by `gateway_owner` with RLS ENABLE + FORCE per Architecture v1.2 §12.3.
- Real PostgreSQL migration and role-security tests: `pnpm --filter @switchyard/gateway test:integration` (real PG at `127.0.0.1:5432`; requires the local Compose stack from SW-1.2.1).
- Production bootstrap (one time, in order; production credentials are separate from development ones per `§19.2`):
  1. As the `switchyard` superuser: `CREATE ROLE gateway_migrator LOGIN NOSUPERUSER NOBYPASSRLS;`
  2. Run `pnpm --filter @switchyard/gateway migrate` as `gateway_migrator` with `POSTGRES_USER=gateway_migrator POSTGRES_PASSWORD=<secret>` — applies `0001-roles`.
  3. As the superuser: `GRANT CREATE ON SCHEMA public TO gateway_owner;` and `GRANT gateway_owner TO gateway_migrator;`
  4. Run `pnpm --filter @switchyard/gateway migrate` as `gateway_migrator` again — applies `0002-org-tables`.

The role matrix created by `0001-roles.sql` (Architecture v1.2 §12.1): `gateway_owner` (tenant-table owner; NOLOGIN), `gateway_migrator` (deployment-only; LOGIN, NOSUPERUSER, NOBYPASSRLS), `gateway_startup` (LOGIN, NOSUPERUSER, NOBYPASSRLS), `gateway_app` (LOGIN, NOSUPERUSER, NOBYPASSRLS), `gateway_worker` (LOGIN, NOSUPERUSER, NOBYPASSRLS), `gateway_auth_executor` (NOLOGIN, BYPASSRLS; owns restricted authentication/bootstrap functions only), `gateway_ops_executor` (NOLOGIN, BYPASSRLS; owns the restricted maintenance enumerator only).
