# SW-P1-B03 — Independent Phase 1 Acceptance Audit

**Audit status:** REVIEWED — **RECOMMEND OWNER ACCEPTANCE**; not formally ACCEPTED until the project owner explicitly approves.
**Architecture authority:** `docs/architecture/architecture-v1.2.md` (§§11–14, 18–21 and §23 Phase 1); `docs/roadmap/implementation-roadmap-v1.md` (Phase 1 acceptance gate); accepted ADR 0001.
**Audited repository:** `silent-knight19/Switchyard`
**Frozen source baseline:** `main` at `475e52fb7f5b58259941066174fdf23d510daf00` (PR #23 merge commit).
**Audit date:** 2026-11-23 (Asia/Kolkata).
**Audit scope:** SW-P1-B03; Phase 1 only. No application, SQL, schema, runtime configuration, or CI behavior was changed.

## 1. Executive disposition

**24/24 Phase 1 acceptance criteria: PASS with repository/CI evidence at the frozen baseline.** No confirmed open Critical, High, or Medium Phase 1 blocker was found in the bounded verification performed. Phase 1 implementation is merged and qualified for **project-owner acceptance**, not self-accepted by the architect.

- PR #22 (SW-P1-B01, six-service worker/web runtime bridge): merged into `main`.
- PR #23 (SW-P1-B02, explicit demo seeding): merged into `main`; its prior independent review findings SEED-01/02/03 have remediation and regression evidence at the audited source baseline.
- The original SW-1.8.4 acceptance evidence is a historical snapshot and still contains 'awaiting review' wording. This document supersedes that **status assessment**, not the original test evidence.
- The first public chat-completion Gateway request path, durable accounting, and production dashboard are **not** Phase 1 deliverables (planned for later phases). Do not use this audit to imply they exist.

## 2. Evidence methodology and limitations

1. Inspected the actual merged `main` commit, GitHub PR history, Docker Compose service definitions, CI workflow, migration/RLS policy, tenant transaction helper, authorization/CSRF modules, seeding remediation, and named test files.
2. Verified **post-merge GitHub Actions** by exact SHA, including step status and detailed job logs. This is independent source/log verification, **not a claim that the auditor reran Docker locally**.
3. Checked the original 24-item acceptance matrix against existing test sources and the live CI database gate. Positive, negative, privilege-denied, wrong-tenant, fail-closed, restart and synthetic-canary tests were inspected via named suites.
4. A PASS means the requirement has direct source/test coverage and the matching integration/quality gate passed at this commit; it is **not** a guarantee against undiscovered vulnerabilities or a substitute for a production penetration test.

### CI evidence — post-merge `main` (source of result counts)

- **Workflow:** https://github.com/silent-knight19/Switchyard/actions/runs/45069646218 — conclusion **success**; head SHA `475e52fb7f5b58259941066174fdf23d510daf00`.
- **Quality and Security Gate:** success. `pnpm install --frozen-lockfile`, `pnpm format:check`, `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm build`, `pnpm audit --audit-level=high`, Gitleaks. Job logs show **770 passed workspace tests** = 656 Gateway + 110 mock upstream + 4 Web, with zero failing tests. Gitleaks: no leaks detected.
- **Database Migration and Privilege Gate:** success. `pnpm --filter @switchyard/gateway test:db` ran **599 passed tests across 28 test files**, with no failing tests, using disposable PostgreSQL and Compose test environments.
- **Within the DB gate:** `compose-init.db.test.ts` **21 passed**, `seed-dev.db.test.ts` **15 passed**, `seed-dev.compose.db.test.ts` **8 passed**. These are actual logged CI test-file totals, not estimates.
- **CI provenance:** `.github/workflows/ci.yml` on the audited SHA; `apps/gateway/vitest.db.config.ts` includes `src/**/*.db.test.ts`, file-parallelism disabled. Earlier superseded CI runs on intermediate PR commits are not used as acceptance evidence.

## 3. Criterion-by-criterion acceptance matrix

| ID | Architecture / Phase 1 acceptance requirement | Verified disposition | Primary source / executable evidence |
|---|---|---|---|
| P1-01 | Gateway clean-clone startup | PASS on audited CI baseline | apps/gateway/src/db/compose-init.db.test.ts (gateway ready); apps/gateway/src/gateway.test.ts |
| P1-02 | Worker clean-clone startup | PASS on audited CI baseline | apps/gateway/src/db/compose-init.db.test.ts (six services, role/ACL, readiness); apps/gateway/src/worker/worker.test.ts |
| P1-03 | Web clean-clone startup | PASS on audited CI baseline | apps/gateway/src/db/compose-init.db.test.ts (six services, loopback Web health); apps/web/src/__tests__/web.test.ts |
| P1-04 | PostgreSQL readiness and migrations | PASS on audited CI baseline | apps/gateway/src/db/compose-init.db.test.ts; apps/gateway/src/db/migrate.db.test.ts |
| P1-05 | Redis persistence, ACL, readiness | PASS on audited CI baseline | apps/gateway/src/db/compose-init.db.test.ts; apps/gateway/src/auth/rate-limiter.redis.db.test.ts |
| P1-06 | Private mock-upstream startup | PASS on audited CI baseline | apps/gateway/src/db/compose-init.db.test.ts; apps/mock-upstream/src/test/stage-d.test.ts |
| P1-07 | Explicit local-only dev seeding | PASS on audited CI baseline | apps/gateway/src/db/seed-dev.test.ts; seed-dev.db.test.ts; seed-dev.compose.db.test.ts |
| P1-08 | Default-deny FORCE RLS | PASS on audited CI baseline | apps/gateway/src/db/migrations/0009-tenant-rls-policies.sql; apps/gateway/src/db/tenant-rls.db.test.ts |
| P1-09 | Composite tenant FKs | PASS on audited CI baseline | apps/gateway/src/db/tenant-rls.db.test.ts; financial-schema.db.test.ts |
| P1-10 | Least-privilege roles/functions | PASS on audited CI baseline | apps/gateway/src/db/privileges.db.test.ts; privileged-functions.db.test.ts; docs/architecture/adr/0001-restricted-pre-tenant-session-lookup.md |
| P1-11 | Pooled transaction-local tenant context | PASS on audited CI baseline | apps/gateway/src/db/tenant.ts; apps/gateway/src/db/tenant-rls.db.test.ts |
| P1-12 | Browser sessions and revocation | PASS on audited CI baseline | apps/gateway/src/auth/session.db.test.ts; auth.db.test.ts |
| P1-13 | CSRF and strict Origin | PASS on audited CI baseline | apps/gateway/src/auth/csrf.http.db.test.ts; csrf.db.test.ts |
| P1-14 | Admin/member RBAC and principal separation | PASS on audited CI baseline | apps/gateway/src/auth/authorization.http.db.test.ts; authorization.db.test.ts |
| P1-15 | Virtual API key issue/auth/revoke | PASS on audited CI baseline | apps/gateway/src/auth/virtual-key-authenticator.db.test.ts; virtual-key-management.db.test.ts; virtual-key-revocation.db.test.ts |
| P1-16 | Provider credential envelope vault | PASS on audited CI baseline | apps/gateway/src/vault/envelope.db.test.ts; apps/gateway/src/auth/provider-key-management.db.test.ts |
| P1-17 | No secrets in tested logs/read APIs | PASS on audited CI baseline | apps/gateway/src/logging/logging.test.ts; auth/provider-key-management.db.test.ts; config/config.test.ts |
| P1-18 | Deterministic mock JSON/SSE | PASS on audited CI baseline | apps/mock-upstream/src/test/stage-a.test.ts; stage-d.test.ts |
| P1-19 | Deterministic fault matrix | PASS on audited CI baseline | apps/mock-upstream/src/test/stage-b.test.ts; apps/gateway/src/db/compose-init.db.test.ts |
| P1-20 | Private mock fixture authorization | PASS on audited CI baseline | apps/mock-upstream/src/test/stage-d.test.ts; apps/gateway/src/db/compose-init.db.test.ts |
| P1-21 | Production mock refusal | PASS on audited CI baseline | apps/mock-upstream/src/test/stage-d.test.ts (compiled subprocess and in-process rejection) |
| P1-22 | Production insecure config/seed refusal | PASS on audited CI baseline | apps/gateway/src/config/config.test.ts; apps/gateway/src/db/seed-dev.test.ts |
| P1-23 | No published mock port | PASS on audited CI baseline | docker-compose.yml; apps/gateway/src/db/compose-init.db.test.ts (live Docker inspection) |
| P1-24 | Bounded cleanup and restart paths | PASS on audited CI baseline | apps/mock-upstream/src/test/stage-b.test.ts, stage-d.test.ts; apps/gateway/src/worker/worker.test.ts; db/compose-init.db.test.ts |

**Grouping:** P1-01–07 establish the local service/bootstrap contract; P1-08–11 database isolation; P1-12–17 authentication/secrets; P1-18–23 mock/private/production constraints; P1-24 resource and shutdown behavior.

## 4. Remediation closure verified

| Finding | Status at audited commit | Specific verification |
|---|---|---|
| ARCH-P1-01 | Closed as implementation blocker | Six-service Docker Compose includes PostgreSQL, Redis, migrate, Gateway, worker, Web and private mock; the six mandatory runtime services are exercised by `compose-init.db.test.ts`. Worker has its own role/ACL and no KEK. |
| ARCH-P1-02 | Closed as implementation blocker | Explicit `pnpm seed:dev`, development/enablement/target restrictions, bounded stdin, real encrypted org DEK, correct admin bootstrap, no implicit Compose seeding and real Compose repeat/production rejection tests. |
| SEED-01 | Remediated and tested | Existing-account `ALREADY_PRESENT` path authenticates stored DEK using configured KEK under `withTenant`; wrong KEK/tampered envelope fail without mutation (real PostgreSQL and Compose tests). |
| SEED-02 | Bounded cleanup behavior tested; limitation disclosed below | Seed pool shutdown has a timed graceful attempt and requests active client close; never-settling shutdown test returns controlled failure instead of false success. |
| SEED-03 | Remediated and tested | Authentication/bootstrap failure output restricted to recognized codes; arbitrary canary and newline-injection error reasons are not echoed. |

## 5. Residual observations (not concealed)

### DOC-P1-01 — Low — Stale historical planning and acceptance language

`START-HERE.md`, the original SW-1.8.4 report, and the opening status language in `AGENTS.md` retain pre-implementation/template framing. The original acceptance report is preserved as a historical, reviewed artifact rather than silently rewritten. `START-HERE.md` is updated in this audit PR to point to this current disposition; the historical documents should not be interpreted as current status.

### OPS-P1-02 — Low — Development seeder shutdown cannot guarantee pathological socket disposal

The seeder bounds its wait for `pool.end()` and attempts to close tracked clients. The unit test for a never-settling `pool.end()` establishes a bounded **function result**, not an OS-level guarantee that an unresponsive PostgreSQL transport leaves no live handle. Under pathological driver/socket hangs, process exit itself is not proved hard-bounded. This is a disclosed **development-only CLI** limitation, not a demonstrated production Gateway defect; no seeding success is reported on cleanup failure. Reassess if the seeder is reused operationally.

### GOV-P1-03 — Informational — CI concurrency

Obsolete intermediate PR commits previously launched redundant workflow runs because `.github/workflows/ci.yml` does not define concurrency cancellation. Introduce separately reviewed PR-scoped `cancel-in-progress` when authorized. This audit deliberately batches all documentation changes into one commit and does not alter CI topology.

### ARCH-P1-04 — Informational — Explicit Phase 2 dependencies

Virtual-key recheck inside the **real durable request-admission transaction**, singleton Gateway fencing, Redis budget state machine, and BullMQ recovery are Phase 2 work. Existing Phase 1 key-revocation row-lock tests establish the integration seam, not Phase 2 completion. The Web app is currently a runnable shell; the full control-plane interface is Phase 4 work.

### SECURITY LIMITATIONS — Documented, not evidence of a new bug

Tenant GUC/RLS does not prevent a fully compromised Gateway runtime from selecting another tenant context; PostgreSQL authorization must be paired with application integrity. The Gateway can access provider plaintext in memory during use. Environment-backed KEKs are not a hardware KMS. These limitations are recorded in `docs/SECURITY.md` and architecture §26.

## 6. Acceptance decision and dependency gate

**Architect disposition:** `SW-P1-B03 = REVIEWED; RECOMMEND ACCEPTANCE` based on the frozen merged source and successful post-merge CI. No implementation change is requested as a Phase 1 gate blocker on the inspected evidence.

**Owner action required:** Review this audit PR, authorize its merge, and explicitly approve `Phase 1 = ACCEPTED`. Until then, formal Phase 1 status remains `REVIEWED / AWAITING OWNER ACCEPTANCE` and **Phase 2 remains blocked** under the dependency workflow.

**Review record:** Baseline `main` SHA and CI run are immutable evidence; audit PR document changes do not retroactively alter which implementation was tested. If substantive code changes land on `main` before acceptance, recheck the affected criteria and the new main SHA.

## 7. Reproduction commands (not claimed executed locally by this auditor)

```bash
pnpm install --frozen-lockfile
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm audit --audit-level=high
pnpm --filter @switchyard/gateway test:db
docker compose up --build -d
docker compose ps
```

Use a fresh disposable test environment for the DB/Compose suite; do not run destructive resets against persistent development volumes. No paid provider credentials are required for the Phase 1 mock acceptance tests.
