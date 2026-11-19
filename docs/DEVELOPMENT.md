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
