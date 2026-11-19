# Switchyard — Architect-Led Implementation Roadmap
**Roadmap:** v1.0 | **Source:** Architecture & Engineering Specification v1.2 (approved baseline) | **Status:** planning only; no implementation claimed
**Governance:** ChatGPT = architect/specification/review; OpenCode and Antigravity = implementation/test execution; developer = merge and design-change authority.

> This roadmap expands §23 of the approved v1.2 specification. It is an execution plan, not a replacement for the normative invariants in §§5–8 or the test requirements in §21. When a roadmap summary differs from the approved specification, the specification wins and the agent reports the contradiction for an explicit decision. No fresh broad architecture audit is authorized by this plan.

## 0. Execution policy and definitions
- **Hierarchy:** Phase → subphase → atomic task. The code agent receives one atomic task at a time, with a bounded diff and explicit acceptance evidence.
- **Dependencies:** A subphase is READY only when *all* listed dependencies are ACCEPTED; tasks within a subphase are executed in listed order unless the architect explicitly allows parallel work. A task is never considered done merely because the agent says it is done.
- **Status:** `BACKLOG → READY → IMPLEMENTED → REVIEWED → ACCEPTED` (or `CHANGES_REQUESTED` then back to IMPLEMENTED). Initial status for every task is `BACKLOG`; no task has been executed.
- **Review artifact:** task ID, architecture anchors, diff/commit, commands, exit codes, raw tests/logs (secret-scrubbed), known limits, and requested deviations. Review on actual diffs/code, not a summary alone.
- **Review priority:** tenant boundaries, financial state, durable admission, secrets, client disconnects, and recovery require real PostgreSQL/Redis integration and deterministic fault barriers. Unit-only tests are insufficient.
- **Decision control:** implementation agents cannot quietly change SQL grants/RLS, budgets, API contracts, provider billing assumptions, deployment topology, or library choices. Escalate as an ADR proposal.
- **Scope:** one active gateway, PostgreSQL canonical ledger, standalone Redis, bounded BullMQ workers, deterministic private mock, Next.js control plane, OpenAI first; Gemini/Groq later; caching strictly optional.
- **Dependency-driven ordering adjustment:** §23 lists RPM/TPM/concurrency in Phase 4, but §§6.1 and 10.5 require pre-dispatch enforcement. We move **minimal correctness enforcement** to Task Group 2.5 before any public dispatch; Phase 4 provides management UI and final load/security evidence. This does not add functionality.
- **Privacy ordering:** PII redaction/trace policy becomes fully enabled before public mock or real-provider dispatch (3.3). Intermediate internal Phase-2 dispatch harness must reject redaction-required keys until enforcement exists.
- **Reality check:** Phase 1 provides secure identity/mock; Phase 2 proves admission/accounting via internal synthetic dispatch; **first full public mock chat-completion vertical slice is 3.4**; Phase 4 is the core portfolio release; Phase 5 is optional and non-blocking.

## 1. Work summary
| Phase | Focus | Subphases | Atomic tasks | Release milestone |
|---|---|---:|---:|---|
| 1 | Foundation + tenant security | 8 | 32 | Secure local foundation |
| 2 | Admission + financial correctness | 8 | 35 | Accounting invariant gate |
| 3 | Streaming + first real provider | 7 | 26 | End-to-end mock Gateway |
| 4 | Control plane + launch evidence | 8 | 29 | Core release / portfolio demo |
| 5 | Optional cache research | 3 | 11 | Optional experiment |
| **Total** | | **34** | **133** | Phase 5 excluded from core DoD |

## 2. Critical path and prerequisite graph
The representative gating path is `1.1 → 1.2 → 1.3 → 1.4 → 1.5/1.6/1.7 + 1.8 → 2.1 → 2.2 → 2.3 → 2.4 → 2.5 → 2.6 → 2.7 → 2.8 → 3.1 → 3.2 → 3.3 → 3.4 → 3.5 → 3.6 → 3.7 → 4.1/4.2/4.3/4.4/4.5 + 4.6/4.7 → 4.8` (with other dependencies listed per subphase).

Parallel work is permitted only for genuinely disjoint changes and after stable contracts. Examples: mock upstream (1.8) can follow the environment setup while schema/auth development proceeds; extra adapters (4.6) can proceed independently of dashboard UX after Phase 3 passes. Avoid parallel commits against the same accounting or security-sensitive module.

## 3. Detailed phase/subphase/task backlog

### Phase 1 — Foundation, identity, tenant isolation, and deterministic mock
**Source anchors:** §§3–4, 11–14, 18–20, 23 Phase 1. **Objective:** Establish a reproducible, tenant-safe control foundation without sending paid provider requests.

#### 1.1 — Repository contract and CI foundation
**Depends on:** none. **Objective:** Create agent-friendly, strict, repeatable monorepo foundations.

- **`SW-1.1.1`** — Pin Node LTS and pnpm versions; initialize root workspace files and committed lockfile. **Acceptance evidence:** A fresh environment can install with frozen lockfile; exact versions documented.
- **`SW-1.1.2`** — Create app/package workspace boundaries (`apps/gateway`, `apps/web`, `apps/mock-upstream`, `packages/shared`, `bench`) with no business behavior. **Acceptance evidence:** Workspace dependency graph resolves and has no circular app imports.
- **`SW-1.1.3`** — Configure strict TypeScript, lint, formatting, and scripts for typecheck/test/build across packages. **Acceptance evidence:** Deliberate type error fails CI; baseline checks run on clean clone.
- **`SW-1.1.4`** — Add initial CI pipeline and secret/dependency scanning; define PR evidence and task naming conventions. **Acceptance evidence:** PR CI runs documented checks; test failure makes pipeline fail.

**Subphase exit gate:** `pnpm install --frozen-lockfile`, typecheck, lint and build baseline pass; architecture and agent governance files have stable paths.

#### 1.2 — Local stack, config, and readiness
**Depends on:** `1.1`. **Objective:** Provide secure, repeatable service boot and environment behavior.

- **`SW-1.2.1`** — Pin PostgreSQL 16+, Redis 7+ and runtime container images; configure private Docker Compose networking, volumes and health checks. **Acceptance evidence:** Fresh volumes and restart preserve data; only intended ports are exposed on loopback.
- **`SW-1.2.2`** — Create central Zod-validated configuration with development/test/production profiles and no fail-open option. **Acceptance evidence:** Invalid settings reject startup; production rejects mock, demo seeds, insecure cookies/TLS and unsafe Redis configuration.
- **`SW-1.2.3`** — Configure structured logs with secret redaction and bounded error serialization. **Acceptance evidence:** Sensitive test fixtures are absent from stdout/stderr and HTTP errors.
- **`SW-1.2.4`** — Implement minimal liveness/readiness endpoints and deterministic boot/shutdown ordering. **Acceptance evidence:** Readiness fails on missing mandatory dependencies; SIGTERM exits cleanly within bounded grace.

**Subphase exit gate:** `docker compose up --build` and health checks work from a clean clone without provider credentials.

#### 1.3 — SQL schema, roles, migrations, and tenant FKs
**Depends on:** `1.2`. **Objective:** Make PostgreSQL the durable authority before higher-level functionality.

- **`SW-1.3.1`** — Establish migration process and distinct owner/migrator/startup/app/worker/auth-executor/ops-executor roles with least privilege. **Acceptance evidence:** Runtime roles do not own tenant tables, cannot assume executor roles, cannot DDL or bypass RLS.
- **`SW-1.3.2`** — Create organizations, gateway_control, users, sessions, provider/virtual keys with constraints and encrypted-secret columns. **Acceptance evidence:** Fresh and repeat migrations validate defaults, uniqueness, role grants and expected columns.
- **`SW-1.3.3`** — Create gateway_requests, provider_attempts, adjustments and trace_payloads with composite tenant FKs and pagination/recovery indexes. **Acceptance evidence:** Cross-organization child references fail at database level; required indexes exist.
- **`SW-1.3.4`** — Enforce immutable terminal base-cost/billing-period fields, adjustment append-only rules and monetary bounds at DB level. **Acceptance evidence:** Direct unauthorized UPDATE/DELETE and mismatched adjustment calculations fail in integration tests.

**Subphase exit gate:** Empty-DB migration works; schema privilege and composite-FK tests pass under actual runtime roles.

#### 1.4 — RLS context and privileged bootstrap functions
**Depends on:** `1.3`. **Objective:** Guarantee default-deny tenant access and tightly scoped pre-login/maintenance capability.

- **`SW-1.4.1`** — Implement transaction-scoped `withTenant(orgId, callback)` with pooled connection hygiene and safe missing/invalid context behavior. **Acceptance evidence:** No-context/empty/invalid-context reads are denied; concurrent pool reuse does not leak tenant context.
- **`SW-1.4.2`** — Apply ENABLE + FORCE RLS, explicit USING/WITH CHECK policies, and tenant-safe grants to every tenant-owned table. **Acceptance evidence:** SELECT/INSERT/UPDATE/DELETE cross-tenant matrix passes for app and worker roles.
- **`SW-1.4.3`** — Add hardened authentication bootstrap/lookup functions owned by dedicated NOLOGIN BYPASSRLS auth executor. **Acceptance evidence:** PUBLIC cannot EXECUTE; restricted result fields; `pg_temp` shadowing tests fail safely.
- **`SW-1.4.4`** — Add bounded ID-only maintenance enumerator owned by separate ops executor with precise EXECUTE grants. **Acceptance evidence:** Worker enumeration returns only permitted org IDs; cannot read other tenant details directly.

**Subphase exit gate:** `withTenant`, RLS, definer-function and privilege regression suite passes against real PostgreSQL.

#### 1.5 — Browser authentication, CSRF, and authorization
**Depends on:** `1.4`. **Objective:** Secure the control plane without conflating browser sessions with data-plane keys.

- **`SW-1.5.1`** — Implement organization/admin bootstrap, normalized email lookup and Argon2id password verification with byte cap and bounded hashing concurrency. **Acceptance evidence:** Unknown-user timing path includes dummy verify; rate-limited login returns generic failures.
- **`SW-1.5.2`** — Implement opaque server-side hashed sessions: creation, rotation, expiry, revoke on logout/password/privilege change. **Acceptance evidence:** Only hash stored; cookie flags match environment; revoked/expired sessions fail.
- **`SW-1.5.3`** — Implement session-bound CSRF synchronizer token plus strict Origin verification for state-changing browser routes. **Acceptance evidence:** Forged/missing token, absent/wrong Origin and cross-site requests are rejected.
- **`SW-1.5.4`** — Add default-deny route metadata enforcing principal type (`browser`, `virtual_key`, `anonymous`) and admin/member RBAC. **Acceptance evidence:** Undeclared route fails registration; member cannot mutate admin resources; principal types never cross.

**Subphase exit gate:** Session/CSRF/RBAC/account-enumeration and login-abuse integration tests pass.

#### 1.6 — Virtual API keys and policy metadata
**Depends on:** `1.4`, `1.5`. **Objective:** Issue and revoke high-entropy credentials while leaving admission re-check to Phase 2.

- **`SW-1.6.1`** — Generate 256-bit gateway keys, store SHA-256 verifiers and public hints, display plaintext once only. **Acceptance evidence:** Raw key never persists or appears in logs; collisions/reuse treated safely.
- **`SW-1.6.2`** — Create parameterized restricted hash lookup and identical external 401 responses for unknown, malformed, missing, revoked keys. **Acceptance evidence:** No Redis auth cache; lookup results contain only minimal identity/policy fields.
- **`SW-1.6.3`** — Add admin-only create/list/revoke and model/RPM/TPM/concurrency/privacy policy validation, with empty allowlist denying all. **Acceptance evidence:** Authorization and model-policy tests pass; policies never silently default to allow-all.
- **`SW-1.6.4`** — Test revocation and log secrecy; define explicit Phase 2 admission-row lock integration seam. **Acceptance evidence:** Invalid/revoked responses are indistinguishable; future admission re-check is a tracked dependency.

**Subphase exit gate:** Authenticated admin can create/revoke a gateway key; worker and member cannot; no raw key is recoverable.

#### 1.7 — Provider credential envelope vault
**Depends on:** `1.4`, `1.5`. **Objective:** Encrypt BYOK data at rest without exposing decryption to background workers.

- **`SW-1.7.1`** — Implement per-organization DEK wrap/unwrap using versioned environment KEK and `dek:<org>:v<version>` AAD. **Acceptance evidence:** Wrong org/version or tag alteration fails authentication; no plaintext in storage.
- **`SW-1.7.2`** — Implement AES-256-GCM provider-key encrypt/decrypt with `pk:<org>:<id>:<provider>` AAD. **Acceptance evidence:** Ciphertext moved between orgs/IDs/providers cannot decrypt.
- **`SW-1.7.3`** — Implement admin-only provider-key create/update/list hint/disable and never-return-plaintext read APIs. **Acceptance evidence:** Worker role lacks credential read/decrypt access; API returns only masked hints.
- **`SW-1.7.4`** — Add decrypt-path scrubbing/privacy tests and document key-backup/rotation compatibility; no rotation CLI yet. **Acceptance evidence:** Secret scanning and log probes pass; encryption format embeds version for later rotation.

**Subphase exit gate:** Provider vault round-trips through gateway role; worker access fails; tampering/cross-tenant decrypt fails.

#### 1.8 — Deterministic private mock upstream
**Depends on:** `1.2`. **Objective:** Build a reliable integration-test instrument independent of real provider pricing/uptime.

- **`SW-1.8.1`** — Implement seed/config-driven deterministic mock chat-completions JSON and SSE fixtures with exact usage and delays. **Acceptance evidence:** Fixed fixture gives byte-identical output and timing controls.
- **`SW-1.8.2`** — Implement error/fault profiles: 4xx, 429 Retry-After, 5xx, refusal/reset, TTFT hang, mid-stream drop and client-abort observation. **Acceptance evidence:** Named tests trigger each failure deterministically without sleep-only coordination.
- **`SW-1.8.3`** — Implement fragmented UTF-8, usage-only tail, malformed frames, oversized lines/events and non-SSE responses. **Acceptance evidence:** All fixtures can be selected by private test controls.
- **`SW-1.8.4`** — Verify mock controls unavailable in production and no public binding; run phase-one acceptance suite. **Acceptance evidence:** Production config rejects mock control endpoints and insecure seed choices.

**Subphase exit gate:** Mock contract tests run without paid tokens; private endpoint cannot be registered in production.

**Phase 1 acceptance gate (architect reviews evidence; developer approves):**
- [ ] Clean-clone Docker Compose startup runs gateway, worker, web, PostgreSQL, Redis, and private mock upstream; explicit development seed only.
- [ ] All tenant RLS, composite FK, restricted-function/role, pooled-connection, browser-session, CSRF, RBAC, and secret-redaction integration tests pass.
- [ ] Create/revoke a virtual key; manage provider credentials with envelope encryption; no raw secrets appear in logs or read APIs.
- [ ] Mock provider responds deterministically to streaming/JSON and fault fixtures, with no production exposure.


### Phase 2 — Durable admission, Redis accounting, fencing, and recovery
**Source anchors:** §§5–8, 11, 15, 19–21, 23 Phase 2. **Objective:** Prove that no upstream side effect precedes durable admission, and that budget state can survive concurrency, crashes and uncertain outcomes.

#### 2.1 — Money, pricing, capability and attempt domain
**Depends on:** `1.8`, `1.6`, `1.3`. **Objective:** Define exact, testable domain contracts before coordinating two stores.

- **`SW-2.1.1`** — Add bigint-only microdollar types, decimal-string JSON codec, overflow/budget cap validation and price arithmetic. **Acceptance evidence:** Property tests reject unsafe numbers, rounding drift and amounts beyond 10^15 microdollars.
- **`SW-2.1.2`** — Define shared request/attempt/outcome enums, discriminated errors, capability/pricing entry contracts and mock-only priced model. **Acceptance evidence:** Unknown or unpriced model is denied; estimates are labeled estimated, not actual.
- **`SW-2.1.3`** — Implement logical request admission/finalization repository with PostgreSQL UTC `admitted_at` and immutable `billing_period`. **Acceptance evidence:** No provider call required; month boundary test proves period derives from DB clock.
- **`SW-2.1.4`** — Define provider adapter interface, dispatch spy and single-attempt finalizer ownership contract, without public streaming route. **Acceptance evidence:** Fake transport records calls; failure paths expose structured outcomes for later integration.

**Subphase exit gate:** Typecheck and money/property/domain tests pass; period and terminal transitions persist once.

#### 2.2 — Gateway singleton lock and epoch fences
**Depends on:** `2.1`. **Objective:** Establish the single-active-Gateway safety contract with separate PostgreSQL lock purposes.

- **`SW-2.2.1`** — Add reserved key registry for session singleton lock and transaction epoch lock; verify no key collision. **Acceptance evidence:** Second live gateway cannot acquire the singleton lock.
- **`SW-2.2.2`** — Implement dedicated startup connection, exclusive epoch transaction lock and durable increment using startup-only role. **Acceptance evidence:** Concurrent admission transaction ordering is deterministic; app role cannot update epoch.
- **`SW-2.2.3`** — Implement shared epoch lock and virtual-key row lock inside provider-attempt admission transaction. **Acceptance evidence:** Key revocation winning row lock forbids later admission; epoch mismatch forbids insertion.
- **`SW-2.2.4`** — Implement heartbeat, `isFenced` shutdown/abort policy and pre-dispatch epoch/deadline guard. **Acceptance evidence:** Lock loss self-fences; no post-fence new dispatch; local old process must stop before replacement.

**Subphase exit gate:** Deterministic barriers exercise old/new epoch, two-process startup and key-revocation interleavings.

#### 2.3 — Redis global gates, generation and lazy hydration
**Depends on:** `2.2`. **Objective:** Reject unknown Redis state; initialize safe organization-period projection from PostgreSQL.

- **`SW-2.3.1`** — Implement Redis client ACL and startup safety checks (`noeviction`, auth, run ID) plus global recovering/ready generation gate. **Acceptance evidence:** Wrong ACL/settings, missing gate and Redis run-ID changes reject admission.
- **`SW-2.3.2`** — Define generation-scoped organization-period key layouts, pointers and typed `FENCED`/`RECOVERY_REQUIRED`/`NEEDS_HYDRATION` outcomes. **Acceptance evidence:** Unknown period is never misread as zero-spend ready.
- **`SW-2.3.3`** — Implement per-org/period pinned PostgreSQL advisory lock and bounded staged hydrate from canonical SQL state. **Acceptance evidence:** Parallel first requests converge on one verified new generation.
- **`SW-2.3.4`** — Implement atomic pointer publish and gate reopen only after count/total validation against SQL snapshot. **Acceptance evidence:** Injected staged-build failures leave gate recovering and old family untouched.

**Subphase exit gate:** New org, new period and missing generation hydrate safely; no mutation of unverified projection.

#### 2.4 — Lua financial transition machine
**Depends on:** `2.3`, `2.1`. **Objective:** Implement each state transition as a bounded, preflight-validated, generation-checked atomic operation.

- **`SW-2.4.1`** — Implement `RESERVE` with Redis TIME, duplicate detection, sum-of-categories equation and pre-mutation validation. **Acceptance evidence:** Concurrency over tight budget admits only safe reservations; bad key types fail closed.
- **`SW-2.4.2`** — Implement `RENEW_LEASE` and bounded `EXPIRE_LEASE` reaper; expiry transfers cost to hold. **Acceptance evidence:** Expired budget never becomes newly available merely due to lease timeout.
- **`SW-2.4.3`** — Implement `COMPLETE_STREAM` transition to pending with allowlisted metadata and strict no resurrection. **Acceptance evidence:** Duplicate completion after pending/ACK is no-op; no PII enters Redis.
- **`SW-2.4.4`** — Implement `ACK_LEDGER` from SQL committed amount and narrow `CANCEL_RESERVATION` with proof-of-rollback/old-epoch guard. **Acceptance evidence:** ACK drains exactly one prior bucket; current-epoch sweeper cannot cancel by a stale no-row snapshot.
- **`SW-2.4.5`** — Build model/property tests for transition matrix, conservation, duplicate/reordered operations and script uncertainty. **Acceptance evidence:** Every terminal path has a deterministic test; unexpected Lua error stops admission and requires rebuild.

**Subphase exit gate:** Full matrix and monetary conservation pass against actual Redis; scripts have bounded runtime/memory.

#### 2.5 — Pre-dispatch policy and resource limits
**Depends on:** `2.1`, `2.4`, `1.6`. **Objective:** Implement safety requirements that must exist before *any* public provider dispatch.

- **`SW-2.5.1`** — Implement pre-key IP abuse throttling with explicit trusted-proxy configuration. **Acceptance evidence:** Random-key flood is blocked before expensive SQL key lookups.
- **`SW-2.5.2`** — Implement per-key RPM/TPM integer token buckets with Redis TIME and attempt-scoped idempotent TPM refund. **Acceptance evidence:** Concurrent limits are atomic; duplicate refund cannot over-credit.
- **`SW-2.5.3`** — Enforce model allowlist, output cap, global/org/key in-flight limits and provider connection admission. **Acceptance evidence:** Unsupported request/overload is rejected without sending provider calls.
- **`SW-2.5.4`** — Validate request size/unknown fields and add policy guard: reject PII-redaction-enabled dispatch until Phase 3 redactor is active. **Acceptance evidence:** No bypass of a requested security/privacy policy during intermediate milestones.

**Subphase exit gate:** No dispatched attempt bypasses IP/key/model/rate/concurrency checks or unmet privacy controls.

#### 2.6 — Two-store admission and bounded synthetic dispatch
**Depends on:** `2.2`, `2.4`, `2.5`. **Objective:** Integrate Redis reservation with durable SQL request+attempt admission; prevent unsafe cancellation.

- **`SW-2.6.1`** — Implement `gateway_requests` admission and primary attempt resolver with immutable UTC period, verified mock capability and bounded estimate. **Acceptance evidence:** Request row exists before reserve/attempt; invalid policy never creates upstream side effects.
- **`SW-2.6.2`** — Implement Redis reserve → SQL epoch/key-lock transaction → durable attempt row → safe dispatch guard. **Acceptance evidence:** Forced SQL rollback prevents dispatch and safely cancels; uncertain commit preserves hold.
- **`SW-2.6.3`** — Implement bounded internal mock dispatch spy and attempt finalizer hooks for success/abort/failure. **Acceptance evidence:** Provider spy sees exactly one call only after SQL committed; no public SSE yet.
- **`SW-2.6.4`** — Implement idempotent logical request status finalization plus stale-request eligibility. **Acceptance evidence:** Duplicate finalization cannot overwrite a terminal logical request.

**Subphase exit gate:** `PostgreSQL INSERT failure`, key revoke race, fence race and ambiguous commit all deny unsafe dispatch.

#### 2.7 — Ledger persistence, adjustments and queue repair
**Depends on:** `2.6`. **Objective:** Persist final attempt outcomes once and connect Redis pending state to canonical SQL amounts.

- **`SW-2.7.1`** — Implement `persist_attempt` worker job with deterministic attempt ID, row locks and terminal cost immutability. **Acceptance evidence:** Repeated job execution leaves a single SQL terminal cost and stable outcome.
- **`SW-2.7.2`** — Implement post-commit Redis ACK that reads SQL effective cost; retry and repair completed/failed/missing BullMQ job IDs. **Acceptance evidence:** Duplicate ACK does not double-settle; failed retained jobs use supported retry path.
- **`SW-2.7.3`** — Implement append-only cost adjustments with canonical prior value, stable source/idempotency and per-org accounting lock. **Acceptance evidence:** Late estimated→confirmed correction changes canonical aggregate exactly once.
- **`SW-2.7.4`** — Implement conservative timeout recovery for stale SQL `reserved` rows and stale logical `in_progress` rows. **Acceptance evidence:** Only after hard deadline+grace; uncertainty never silently settles free.
- **`SW-2.7.5`** — Implement orphan pending sweeper and keep all queue payloads credential/prompt-free. **Acceptance evidence:** Crash between completion and enqueue is eventually recovered without a second bill.

**Subphase exit gate:** Integration tests pass for duplicate job delivery, orphan jobs, interrupted estimates, append-only adjustment replays.

#### 2.8 — Global rebuild, reconciliation and fault-injection
**Depends on:** `2.3`, `2.4`, `2.7`. **Objective:** Demonstrate safe recovery after lost or corrupted derived Redis state.

- **`SW-2.8.1`** — Implement admission stop/drain protocol on Redis run-ID mismatch, lost gate, script uncertainty or `noeviction` OOM. **Acceptance evidence:** No new provider dispatch until verified rebuild; active callbacks cannot mutate old generation.
- **`SW-2.8.2`** — Implement globally enumerated, bounded per-tenant staged hydration with `withTenant` and callback-to-SQL completion fallback. **Acceptance evidence:** Hydration-versus-stream-complete/ACK barriers converge without missing cost.
- **`SW-2.8.3`** — Implement accounting reconciler comparing SQL canonical spend and Redis settled/pending/hold/reservation sums. **Acceptance evidence:** Detected drift closes affected gate; never applies guessed counter adjustments.
- **`SW-2.8.4`** — Add deterministic recovery matrix: restart, isolated FLUSHALL, bad key type, partial Lua failure, midnight UTC, old-epoch orphan. **Acceptance evidence:** All documented failure cases fail closed, recover, and reach verified totals.
- **`SW-2.8.5`** — Wire bounded metrics for drift, pending age, expiry holds, gate state and recovery failures. **Acceptance evidence:** Metrics reflect actual states and reveal a stuck-recovering gate.

**Subphase exit gate:** No unexplained drift after recovery; all phase-two invariants have reproducible commands.

**Phase 2 acceptance gate (architect reviews evidence; developer approves):**
- [ ] Durable logical request and per-attempt `reserved` SQL rows precede any dispatch; revocation and epoch races serialize correctly.
- [ ] `RESERVE`, renewal, expiry hold, completion, ACK and safe cancellation satisfy full state matrix and budget equation under duplicate/reordered calls.
- [ ] Persist/repair worker, lazy hydration, staged rebuild and Redis restart/noeviction/partial-error scenarios converge to PostgreSQL canonical costs.
- [ ] Pre-dispatch rate/concurrency guards are in place; Phase 2 uses an internal synthetic mock transport harness, not an unsafe public stream endpoint.


### Phase 3 — Safe streaming, privacy, OpenAI adapter, and resilience
**Source anchors:** §§6, 9–10, 14–16, 18, 21, 23 Phase 3. **Objective:** Expose a functioning OpenAI-shaped API and then add one verified paid-provider adapter without compromising accounting and streaming invariants.

#### 3.1 — Incremental SSE parsing and provider contracts
**Depends on:** `2.8`. **Objective:** Parse untrusted provider streams without assuming network-chunk boundaries.

- **`SW-3.1.1`** — Build incremental UTF-8 SSE parser with BOM, CRLF/LF/CR, comments, multiline data, `[DONE]` and EOF behavior. **Acceptance evidence:** Fragmentation and multibyte fixtures reconstruct the same events as unsplit input.
- **`SW-3.1.2`** — Bound line (256 KiB), event (1 MiB), stream bytes, malformed frames and content-type handling. **Acceptance evidence:** Overflow or invalid UTF-8 terminates with structured provider error and bounded RSS.
- **`SW-3.1.3`** — Define canonical content/usage/error streaming events and normalized JSON reply shape in shared provider contract. **Acceptance evidence:** Mock and future OpenAI adapter pass the same schema/contract tests.

**Subphase exit gate:** Parser fixture suite includes usage-only final chunks, malformed events and split byte boundaries.

#### 3.2 — Fastify transport, backpressure, and abort lifecycle
**Depends on:** `3.1`, `2.7`. **Objective:** Connect bounded upstream IO to safe downstream HTTP semantics.

- **`SW-3.2.1`** — Implement `reply.hijack()` streaming route with correct pre-hijack headers, SSE event mapping and single terminal marker. **Acceptance evidence:** No double-send/after-end in normal completion or errors.
- **`SW-3.2.2`** — Implement slow-client backpressure gate: pause upstream consumption on write=false, resume on drain or abort. **Acceptance evidence:** Fast-upstream/slow-client test keeps buffers and RSS bounded.
- **`SW-3.2.3`** — Implement premature response close, timeout, upstream error and SIGTERM propagation through one attempt finalizer. **Acceptance evidence:** Upstream mock records abort; settlement/final request transitions occur at most once.
- **`SW-3.2.4`** — Implement capped `stream:false` response path (default 4 MiB) with equivalent accounting, abort, timeouts and safe error mapping. **Acceptance evidence:** Oversized JSON body is rejected; normal request completion is not falsely classified as abort.

**Subphase exit gate:** Transport handles malformed/slow/disconnected clients and does not grow unbounded memory.

#### 3.3 — Privacy and upstream trust boundary
**Depends on:** `3.1`, `3.2`. **Objective:** Enforce privacy and egress security before public dispatch is enabled.

- **`SW-3.3.1`** — Implement opt-in regex PII redaction for documented email/phone/payment-card/API-key fixtures, before outbound dispatch. **Acceptance evidence:** Redaction-enabled requests are transformed before provider receives them; limitations documented.
- **`SW-3.3.2`** — Enforce `store_payloads=false`, trace capture cap, seven-day retention metadata and sanitized failure logging. **Acceptance evidence:** No raw request/response cached or persisted for opted-out keys.
- **`SW-3.3.3`** — Restrict provider endpoints to fixed HTTPS origins, redirects=error, validated models and outbound/inbound header allowlists. **Acceptance evidence:** Redirect/private endpoint tricks and leaked Authorization/Cookie/Set-Cookie are rejected.
- **`SW-3.3.4`** — Configure bounded upstream connections, header sizes, deadline/TTFT/inactivity timers and fail-closed TLS verification. **Acceptance evidence:** Timeout/oversize handling aborts and carries estimated-cost settlement.

**Subphase exit gate:** Privacy fixture suite and SSRF/headers/size regression tests pass before real provider use.

#### 3.4 — First runnable mock Gateway vertical slice
**Depends on:** `3.2`, `3.3`, `2.6`. **Objective:** Release a demonstrable request path without paid credentials.

- **`SW-3.4.1`** — Wire authenticated chat completions route to request admission, mock capability, Redis reserve, SQL attempt and private mock adapter. **Acceptance evidence:** Gateway virtual key makes a request; mock sees dispatch only after durable attempt admission.
- **`SW-3.4.2`** — Wire normalized streaming/non-streaming success, completion persistence, ACK, usage and final response semantics. **Acceptance evidence:** Client receives response and SQL/Redis account for the same attempt once.
- **`SW-3.4.3`** — Add end-to-end scripts for good request, budget deny, rate deny, key revoke, stream abort and recovery. **Acceptance evidence:** Clean-clone tests run with synthetic fixtures, no provider secrets.
- **`SW-3.4.4`** — Record thin-slice demo transcript and test-evidence table mapped to invariants. **Acceptance evidence:** Reviewer can reproduce mock request and inspect SQL/Redis/trace without privileged app credentials.

**Subphase exit gate:** First usable, key-authenticated end-to-end gateway demo passes with no real provider dependencies.

#### 3.5 — OpenAI capability/pricing and adapter
**Depends on:** `3.4`. **Objective:** Introduce exactly one real provider behind verified contract and pricing.

- **`SW-3.5.1`** — Verify current official OpenAI chat endpoint/model field support, stream usage, limits and prices; record last_verified/source URLs. **Acceptance evidence:** No unknown model, stale price or unsupported requested parameter is silently accepted.
- **`SW-3.5.2`** — Implement fixed-origin authenticated OpenAI adapter with parameter mappings and model capability gates. **Acceptance evidence:** Unsupported non-default parameters get structured errors; no client secrets forwarded upstream.
- **`SW-3.5.3`** — Normalize OpenAI SSE/JSON completion, usage-only tail, error classes, token counts and costs. **Acceptance evidence:** Provider contract fixtures pass; estimated vs confirmed outcomes stay distinct.
- **`SW-3.5.4`** — Add optional credentialed smoke tests behind explicit opt-in; keep CI fully mock-driven. **Acceptance evidence:** Default test suite uses no billable tokens and has deterministic behavior.

**Subphase exit gate:** One real adapter validates against official documented semantics; pricing metadata is dated/source-linked.

#### 3.6 — Circuit breakers, one-step failover, and edge cases
**Depends on:** `3.5`. **Objective:** Preserve attempt-level billing while responding safely to provider failures.

- **`SW-3.6.1`** — Implement per-org/provider Redis CLOSED/OPEN/HALF_OPEN circuit breaker with eligible error classification and SET NX probe. **Acceptance evidence:** 429/5xx/timeouts trip where configured; 400/401/403/422 do not trip.
- **`SW-3.6.2`** — Implement pre-first-content-token fallback eligibility and provider/model capabilities; always abort primary first. **Acceptance evidence:** Fallback gets unique attempt ID/reservation; primary retains estimated/actual billable cost.
- **`SW-3.6.3`** — Enforce strict max two attempts, budget check for fallback and failover prohibition after downstream content. **Acceptance evidence:** Insufficient fallback budget fails safely; mid-stream failure emits SSE error rather than switching.
- **`SW-3.6.4`** — Exercise TTFT timeout, Retry-After, mid-stream error, disconnect and failover race with deterministic mock faults. **Acceptance evidence:** Exactly-once attempt finalization and logical outcome are verified across both attempts.

**Subphase exit gate:** Contract and chaos tests demonstrate bounded failover with separate attempt accounting.

#### 3.7 — Streaming and provider acceptance gate
**Depends on:** `3.4`, `3.5`, `3.6`. **Objective:** Close Phase 3 with reproducible critical-path safety evidence.

- **`SW-3.7.1`** — Build combined tests for parser, HTTP teardown, backpressure, header controls, privacy and stream/nonstream consistency. **Acceptance evidence:** All §21.4 tests pass with real Redis/PostgreSQL and deterministic mock upstream.
- **`SW-3.7.2`** — Run failure matrix across reservation, primary dispatch, fallback, worker settlement, disconnect and recovery. **Acceptance evidence:** All SQL attempts and Redis costs reconcile; no unobserved provider side effects.
- **`SW-3.7.3`** — Document verified provider limitations, implemented safeguards, and known residual risks. **Acceptance evidence:** No production-ready/zero-overspend claims; demo setup has safe defaults.

**Subphase exit gate:** Approve Phase 3 only after E2E mock and optional real-OpenAI smoke evidence satisfy their distinct guarantees.

**Phase 3 acceptance gate (architect reviews evidence; developer approves):**
- [ ] `POST /v1/chat/completions` works with local mock via real virtual key in stream:true and stream:false modes; billing persists.
- [ ] SSE framing, UTF-8 splitting, size limits, slow downstream, client disconnect, deadline/shutdown and once-only settlement tests pass.
- [ ] OpenAI adapter uses verified live model capabilities/pricing and protects upstream/downstream headers/TLS/redirect boundaries.
- [ ] One primary + at most one fallback; no fallback after first content token; PII redaction/storage policies enforced.


### Phase 4 — Control plane, optional provider expansion, verification and release
**Source anchors:** §§13–17, 19–23, 25–27. **Objective:** Deliver a usable browser control plane, operational evidence, robust benchmarks and honest portfolio documentation.

#### 4.1 — Read models and aggregated observability
**Depends on:** `3.7`. **Objective:** Expose accurate SQL-backed operational views, not Redis-derived financial guesses.

- **`SW-4.1.1`** — Build tenant-scoped monthly canonical spend query (effective base plus adjustments), budget remainder and attempt/request counts. **Acceptance evidence:** Queries reconcile against financial ledger; money serialized as decimal strings.
- **`SW-4.1.2`** — Add TTFT/latency/error/provider-distribution aggregates with explicitly defined sample population. **Acceptance evidence:** Correct percentile behavior tested on small known datasets.
- **`SW-4.1.3`** — Implement trace metadata filtering and `(created_at, request_id)` keyset pagination. **Acceptance evidence:** Equal timestamps cannot drop/duplicate records; cross-tenant pages are denied.
- **`SW-4.1.4`** — Create request detail/attempt timeline read model including cost status and per-attempt adjustments. **Acceptance evidence:** Primary/fallback and late corrections shown separately, without inferring actual from estimate.

**Subphase exit gate:** Aggregates, pagination and tenant-isolation tests pass under browser session auth.

#### 4.2 — Next.js same-origin shell and session UX
**Depends on:** `4.1`, `1.5`. **Objective:** Provide a securely authenticated browser entry point and navigation.

- **`SW-4.2.1`** — Implement same-origin BFF/proxy topology and authenticated login/logout/session bootstrap page. **Acceptance evidence:** Secure cookie and CSRF token stay out of localStorage and browser console.
- **`SW-4.2.2`** — Implement role-aware navigation and minimal accessible dashboard overview with budget/usage cards. **Acceptance evidence:** Members see read-only views; forbidden actions are not callable even if UI is altered.
- **`SW-4.2.3`** — Add resilient empty/loading/error states and accessible responsive design. **Acceptance evidence:** No secrets rendered in HTML hydration payloads; basic a11y checks pass.

**Subphase exit gate:** Login, CSRF flow, role checks and overview function across clean Compose boot.

#### 4.3 — Keys, credentials and organization admin UI
**Depends on:** `4.2`, `1.6`, `1.7`. **Objective:** Make management features usable while preserving admin-only boundaries.

- **`SW-4.3.1`** — Build virtual-key create/show-once/list/revoke and model/RPM/TPM/concurrency/privacy settings forms. **Acceptance evidence:** Raw key displayed once, never in later read response/log, member forbidden.
- **`SW-4.3.2`** — Build provider vault create/update/disable/list-hint UX and safe connectivity status. **Acceptance evidence:** Plaintext credentials never returned after creation or exposed in browser persistence.
- **`SW-4.3.3`** — Implement organization monthly-budget settings and authenticated user/role controls limited to declared RBAC matrix. **Acceptance evidence:** Unauthorized mutation blocked server-side; session invalidation on privilege change works.

**Subphase exit gate:** All admin paths exercise real DB constraints, session auth and CSRF; negative RBAC tests pass.

#### 4.4 — Trace explorer, payload policy and operational housekeeping
**Depends on:** `4.1`, `4.2`, `3.3`. **Objective:** Make request-attempt lineage inspectable without turning observability into a data leak.

- **`SW-4.4.1`** — Create filterable trace list and request detail with per-attempt fallback/latency/usage/status/cost. **Acceptance evidence:** Keyset pagination preserves stable navigation; tenant isolation maintained.
- **`SW-4.4.2`** — Build admin-only raw redacted payload detail with omitted/truncated indicators and seven-day TTL visibility. **Acceptance evidence:** Member cannot view raw payload; opted-out traces have metadata only.
- **`SW-4.4.3`** — Implement bounded tenant-scoped trace retention pruner using ops enumerator and `withTenant`. **Acceptance evidence:** Deletes expired payload only in batches; financial rows remain; backup-retention caveat documented.

**Subphase exit gate:** List/detail/payload visibility and retention tests pass under two organizations and two roles.

#### 4.5 — Safe streaming playground
**Depends on:** `4.2`, `3.7`. **Objective:** Demonstrate streaming through server-side session authorization, not exposed long-lived keys.

- **`SW-4.5.1`** — Implement authenticated short-lived server-side playground operation bound to org/user with appropriate RBAC and CSRF. **Acceptance evidence:** Browser never receives provider key or virtual key secret.
- **`SW-4.5.2`** — Stream live mock output with TTFT, latency, normalized tokens and attempt history in the UI. **Acceptance evidence:** Client cancel aborts upstream and causes one conservative finalization.
- **`SW-4.5.3`** — Add fixtures for budget deny, timeout, mid-stream SSE error and recovery-safe UX. **Acceptance evidence:** UI visibly distinguishes incomplete/error stream from successful completion.

**Subphase exit gate:** Reviewer can demonstrate streaming locally without paid provider key or privileged dev-only endpoint.

#### 4.6 — Gemini/Groq capability-gated adapters
**Depends on:** `3.7`. **Objective:** Extend compatibility only where documented normalization can be proven.

- **`SW-4.6.1`** — Verify current official Gemini OpenAI-compatible endpoint/model field/pricing/usage semantics; record date/source. **Acceptance evidence:** Unsupported fields and missing usage are explicitly handled; no invented compatibility.
- **`SW-4.6.2`** — Implement Gemini adapter and shared provider contract tests with mock fixtures. **Acceptance evidence:** Non-equivalent requested parameters are rejected; token/cost normalization tested.
- **`SW-4.6.3`** — Verify current official Groq endpoint/model field/pricing/rate-limit semantics; record date/source. **Acceptance evidence:** Pricing and model limits have source URLs and effective dates.
- **`SW-4.6.4`** — Implement Groq adapter and provider-specific failure/usage tests, keeping real API smoke opt-in. **Acceptance evidence:** No real keys needed for baseline CI, test harness or demo.

**Subphase exit gate:** Provider matrix makes implemented versus unsupported features explicit; new adapters pass common tests.

#### 4.7 — Operational hardening and optional KEK rotation
**Depends on:** `4.3`, `3.7`. **Objective:** Close real deployment and credential-lifecycle risks without feature creep.

- **`SW-4.7.1`** — Test SIGTERM/SIGKILL/worker stop/postgres disconnect/Redis interruption against documented bounded shutdown. **Acceptance evidence:** Advisory locks released; active attempts recover conservatively.
- **`SW-4.7.2`** — Audit production-mode assertions, HTTP headers/CORS, infrastructure network bindings, Redis ACL and no-demo behavior. **Acceptance evidence:** Production config never registers mock/fault controls or permits insecure TLS/cookies.
- **`SW-4.7.3`** — OPTIONAL: implement idempotent batched KEK rewrap CLI with compare-and-swap and backup restoration tests. **Acceptance evidence:** Old KEK retained for backup window; crash between batches can resume safely.
- **`SW-4.7.4`** — Produce ops runbooks for gateway fencing, Redis rebuild, stuck queue jobs, and restoring encrypted backups. **Acceptance evidence:** Every runbook references a test or demonstrated command; no unsupported guarantees.

**Subphase exit gate:** Operational failure policy §24 is exercised; optional rotation is separately marked complete/deferred.

#### 4.8 — Benchmark suite, documentation and release gate
**Depends on:** `4.3`, `4.4`, `4.5`, `4.6`, `4.7`. **Objective:** Make measurable engineering evidence the final release criterion.

- **`SW-4.8.1`** — Build undici streaming benchmark comparing direct mock vs Gateway and p50/p95/p99 TTFT/latency. **Acceptance evidence:** Raw results and first-content-token timing are preserved, not full-response-buffer timing.
- **`SW-4.8.2`** — Run 10/50/100 concurrency budget benchmark plus admission/lock/Lua/rebuild timing. **Acceptance evidence:** Equation verified during admission as well as at terminal settlement; benchmark includes exact failure model.
- **`SW-4.8.3`** — Run slow-reader memory/load experiment capturing RSS, event-loop lag, sockets and queue depth. **Acceptance evidence:** No fabricated 500-stream gate; test machine and limits disclosed.
- **`SW-4.8.4`** — Add clean-clone integration CI, migration checks, dependency/secret audit, deterministic race/chaos matrix. **Acceptance evidence:** CI output links to runnable tests for all externally stated guarantees.
- **`SW-4.8.5`** — Publish README/demo steps, diagrams, SECURITY/ARCHITECTURE/BENCHMARKS docs and residual-risk disclosures. **Acceptance evidence:** Reviewer can reproduce mock demo and metrics from tagged commit without paid tokens.

**Subphase exit gate:** All 12 core v1 definition-of-done conditions in §25 pass, or unresolved gaps are explicitly recorded as blockers.

**Phase 4 acceptance gate (architect reviews evidence; developer approves):**
- [ ] Admin/member dashboard and safe same-origin streaming playground work without ever exposing long-lived virtual/provider keys in browser JS.
- [ ] Usage/traces/attempts are tenant-scoped, keyset-paginated and display estimated vs confirmed vs adjusted spend correctly.
- [ ] Additional providers are added only after adapter contracts and verified pricing; core CI and demo remain provider-credential-free.
- [ ] CI, security suite, deterministic chaos runs, reproducible benchmark data, architecture/security docs and README match implemented capabilities.


### Phase 5 — Optional opt-in exact and semantic caching
**Source anchors:** §§2.2, 11.11, 16, 21, 23 Phase 5. **Objective:** Improve latency only if privacy, correctness and measured hit-quality prerequisites are already established.

#### 5.1 — Exact cache key policy and storage
**Depends on:** `4.8`. **Objective:** Provide an opt-in, tenant-scoped cache without cross-context or privacy leakage.

- **`SW-5.1.1`** — Define canonical semantic request schema and HMAC of original pre-redaction input, including model/version, instructions, tools, parameters and privacy identity. **Acceptance evidence:** Changing any material context misses; cross-org entries never collide.
- **`SW-5.1.2`** — Implement exact cache eligibility for complete deterministic text-only success; bypass errors, partial, tools, multimodal and no-store. **Acceptance evidence:** `store_payloads=false` always bypasses; cache never stores a truncated stream.
- **`SW-5.1.3`** — Implement bounded TTL no longer than raw payload retention and tenant-scoped invalidation/pruning. **Acceptance evidence:** Expired entries disappear; raw prompts not stored in pre-redaction form.
- **`SW-5.1.4`** — Integrate cache hit into logical request admission with zero provider attempts and recorded cache metadata. **Acceptance evidence:** No provider dispatch/reservation on valid hit; request/metrics remain durable.

**Subphase exit gate:** Exact caching defaults off and passes privacy, tenant and request-equivalence tests.

#### 5.2 — Semantic embeddings and tenant isolation
**Depends on:** `5.1`. **Objective:** Only attempt similarity reuse with explicit conservative eligibility.

- **`SW-5.2.1`** — Add RLS-protected pgvector 0.8+ semantic schema with exact 384-dimension vectors and context hash. **Acceptance evidence:** Cross-tenant access denied by RLS; schema/migrations reversible.
- **`SW-5.2.2`** — Implement bounded ONNX embeddings in worker_threads, explicit task queue/backpressure and timeout. **Acceptance evidence:** HTTP event loop remains responsive under embedding load.
- **`SW-5.2.3`** — Implement safe single-turn-only, tool/multimodal/identifier/number/negation guards and context equality checks. **Acceptance evidence:** Known hard negatives never return semantic cache hits.
- **`SW-5.2.4`** — Compare tenant-bucket exact cosine against HNSW approximate recall under skew before choosing an index strategy. **Acceptance evidence:** Report recall by tenant size; do not assume physical per-tenant isolation.

**Subphase exit gate:** Semantic cache disabled until guard tests and accuracy benchmarking are accepted.

#### 5.3 — Calibration, rollout and opt-out
**Depends on:** `5.2`. **Objective:** Publish quality evidence or leave semantic caching intentionally disabled.

- **`SW-5.3.1`** — Curate 500–1,000 labeled similar/dissimilar prompt pairs, including deliberately hard negatives and context shifts. **Acceptance evidence:** Dataset and labels are versioned, with no stored personal/provider secrets.
- **`SW-5.3.2`** — Measure precision, recall, false positives, latency and false-hit consequences on held-out cases. **Acceptance evidence:** Reproducible metrics and thresholds documented before enablement.
- **`SW-5.3.3`** — Add per-key opt-in, monitoring and one-step kill switch; verify retention and privacy bypass after rollout. **Acceptance evidence:** Failure or unacceptable false-positive rate disables semantic cache without affecting base Gateway.

**Subphase exit gate:** Optional feature ships only if evidence supports safe use; otherwise record intentional deferral.

**Phase 5 acceptance gate (architect reviews evidence; developer approves):**
- [ ] Phase 4 is accepted before any caching work begins; caching disabled by default and bypassed for `store_payloads=false` or `no-store`.
- [ ] Exact cache identity includes all relevant request semantics, provider/model/version and privacy policy; only full eligible successes stored.
- [ ] Semantic cache, if built, has calibrated precision/recall/false-positive evidence and bounded embedding worker pool; otherwise deliberately omitted.

## 4. Task handoff protocol
Every future task prompt to OpenCode/Antigravity must include:
1. **Identity:** `SW-<phase>.<subphase>.<task>`, branch suggestion, architecture section references, and accepted dependency commit hash.
2. **Objective / in-scope files:** exact behavior and permitted paths; a narrow list of prohibited changes.
3. **Interface contracts / invariants:** relevant auth, tenant, money, provider, SQL transaction, queue, abort and failure behavior. Never infer from naming alone.
4. **Implementation approach:** inspect current repository state, reuse established patterns, choose simplest solution, avoid unrelated refactors; report conflicts before changing architecture.
5. **Verification:** explicit commands, negative tests, fault barriers, permissions tests, and expected results. Do not claim a command was run if it was not run.
6. **Output report:** modified files, brief design rationale, commands/exit codes, test counts and failures, security implications, assumptions, known limitations, diff/commit reference, and explicit request for architecture review.
7. **Review gate:** architect inspects actual diffs and evidence, returns ACCEPT/CHANGES_REQUESTED with severity; only project owner authorizes merge.

## 5. Minimum evidence checklist (used for every task)
- [ ] Task scope and dependencies correspond to accepted baseline and current commit.
- [ ] No secrets, provider credentials, prompts, or raw request bodies in logs and task reports.
- [ ] New public/privileged routes have declared principal and role; new tenant tables use RLS and composite FKs.
- [ ] Financial changes use bigint/SQL canonical ledger, bounded Redis scripts, generation gates and deterministic tests.
- [ ] Provider changes do not dispatch before durable reserved attempt and maintain fixed HTTPS/allowlisted headers.
- [ ] Failure/abort/cancellation behavior tested; uncertainty does not become a guessed free cost.
- [ ] Relevant integration tests use real PostgreSQL/Redis; mock provider for deterministic network conditions.
- [ ] Changed files and test commands reported; no unexplained dependency, topology, schema or spec deviation.
- [ ] Reviewer gives explicit disposition; only accepted work unlocks dependent tasks.

## 6. Milestones for the developer
1. **M1 / Phase 1:** Reproducible private Compose, login, tenant security, API keys and deterministic mock (not a full chat Gateway yet).
2. **M2 / Phase 2:** SQL-before-dispatch admission and conservative financial invariants with internal mock dispatch and recovery tests.
3. **M3 / Phase 3:** First public streaming/nonstream mock Gateway vertical slice, then verified OpenAI and safe bounded failover.
4. **M4 / Phase 4:** Usable control plane, optional additional real adapters, benchmark evidence, complete core definition-of-done.
5. **M5 / Phase 5:** Optional cache experimentation; skip if it threatens core correctness or shipping.

## 7. First task to delegate
**`SW-1.1.1`: Pin Node LTS and pnpm versions; initialize workspace manifest and frozen lockfile.** Do not combine this with 1.1.2 or broader app scaffolding. Refer to `switchyard_SW-1.1.1_agent_brief.md` for the complete implementation-agent instructions. First review the baseline repo state; the agent should not overwrite an existing project or make commits without user authorization.

---
**Source of truth:** `ai_gateway_architecture_engineering_plan_final_v1.2.md`, especially the normative invariants (§5), sequence/fencing/accounting (§§6–8), deployment/security assumptions (§§11–14, 19), verification (§21), original five phases (§23), and definition of done (§25). This roadmap does not assert that any phase or task is implemented.
