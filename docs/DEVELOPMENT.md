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
