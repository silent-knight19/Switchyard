# Production-Inspired AI Gateway & Observability Plane
## Final Engineering Specification v1.2 — Pre-Implementation Baseline

**Status:** Final targeted revision after three independent architecture/security audits  
**Target:** 2027 fresher SDE-1 / SWE-1 portfolio project  
**Implementation model:** One developer, modular monolith, one active Gateway instance  
**Primary objective:** Demonstrate strong backend engineering, security fundamentals, distributed-systems reasoning, testing discipline, and measurable performance without building unnecessary enterprise infrastructure.

> This document is the implementation baseline. It describes an intentionally bounded, production-inspired system—not a claim that the future implementation is production-ready or immune to every failure. Any guarantee is valid only within the assumptions and failure model stated here. Do not add new infrastructure or features unless implementation evidence demonstrates a need.

---

# 1. Executive summary

## 1.1 Problem

Applications that call LLM providers directly from application servers often lack a consistent place to enforce and observe:

1. Organization-level spend limits and per-key request limits.
2. Provider failure handling, bounded retries, and controlled fallback.
3. Streaming correctness, client-disconnect cancellation, and resource limits.
4. Per-request and per-provider-attempt usage, cost, latency, and failure visibility.
5. Provider credential protection and tenant-level data isolation.

## 1.2 Product

Build a **multi-tenant, OpenAI-compatible AI Gateway and Observability Control Plane**.

A client sends a chat-completion request to the Gateway using a gateway-issued virtual API key. The Gateway authenticates the key, validates the request, checks organization and key policies, reserves budget, durably records each provider attempt in PostgreSQL, and only then dispatches to an upstream provider. It normalizes provider responses and streams them to the client with bounded memory and cancellation behavior.

The Control Plane manages organizations, users, virtual keys, provider credentials, request traces, cost analytics, and a streaming playground.

## 1.3 Portfolio positioning

This is not an attempt to invent a new AI product category or outperform LiteLLM, Portkey, Helicone, or Cloudflare AI Gateway as a commercial service. It is a backend infrastructure project designed to demonstrate that the developer can reason about and implement:

- Durable admission before external side effects.
- Tenant-aware PostgreSQL access and database constraints.
- Redis-backed concurrent reservations and rate limits.
- Idempotent attempt settlement and recovery.
- Provider adapters and pre-first-token failover.
- Backpressure-safe SSE streaming and client aborts.
- Credential encryption, session security, and explicit authorization.
- Deterministic tests, failure injection, and honest benchmarks.

For a fresher candidate, a smaller system with correct invariants and strong evidence is more valuable than a sprawling feature checklist. Interview value comes from explaining the actual implementation and its limitations—not from describing this document as “staff-grade.”

## 1.4 Honest quality bar

The project may be described as:

> A production-inspired, multi-tenant backend infrastructure system with documented failure behavior and measured reliability characteristics.

Do not call it production-ready, enterprise-grade, staff-grade, zero-overspend, or perfectly secure. Only publish performance and reliability numbers obtained from reproducible tests.

---

# 2. Scope and feasibility

## 2.1 Essential v1 capabilities

1. OpenAI-compatible `POST /v1/chat/completions` endpoint.
2. Virtual API key creation, authentication, revocation, and model allowlists.
3. Organization-level monthly budgets using integer microdollars.
4. PostgreSQL as the durable source of truth for logical requests and provider attempts.
5. Redis for atomic budget reservations, attempt-state acceleration, rate limits, and circuit-breaker state.
6. One active Gateway process, protected by a PostgreSQL advisory lock and durable epoch.
7. SSE streaming with bounded parsing, backpressure, and upstream abort propagation.
8. One primary real provider in the first working release, plus a deterministic mock provider. Additional real providers are added only after the core path is stable.
9. Provider credentials encrypted at rest using application-level AES-256-GCM envelope encryption.
10. Server-side control-plane sessions, explicit `admin` / `member` authorization, CSRF protection, and tenant-aware database access.
11. Attempt-level cost accounting, a documented adjustment mechanism, background recovery, and consistency checks.
12. Trace metadata, a limited trace explorer, and a usable local demonstration.
13. A deterministic mock upstream with fault injection and integration-test support.

## 2.2 Deferred capabilities

The following are not required to demonstrate the core engineering value and must not delay it:

- Semantic caching with ONNX and pgvector.
- Multi-Gateway active-active deployment.
- Redis Cluster.
- Kubernetes, Kafka, service mesh, or microservice decomposition.
- Native Anthropic Messages API translation.
- Prompt versioning, prompt evaluations, datasets, and LLM-as-a-judge.
- Per-virtual-key sub-budgets.
- Hardware KMS integration.
- Per-key expiration overlap / zero-downtime key rotation UI.
- Multi-region recovery.

Exact caching is also deferred until the base Gateway is correct. If implemented, it is an opt-in enhancement with the privacy rules in Section 16.

## 2.3 Provider rollout

**First implementation milestone:** deterministic mock provider only.  
**First real-provider milestone:** OpenAI adapter.  
**Later extension:** Gemini and Groq adapters after the shared provider contract tests pass.

Do not implement three real providers simultaneously in the first phase. Provider behavior differs in usage reporting, supported parameters, tokenization, model limits, and error semantics. Establish one correct adapter contract before adding others.

Provider model IDs and prices are time-sensitive. Verify the exact endpoints, supported fields, token limits, usage semantics, and pricing against official documentation when the adapter is implemented. Keep a `last_verified` date and source URL with each pricing/capability entry.

## 2.4 Deployment assumptions

V1 intentionally supports:

- One active Gateway instance.
- One standalone Redis instance.
- One PostgreSQL 16+ instance.
- Multiple concurrent clients and bounded background workers.
- One local Docker Compose deployment for reproducible review.

A second Gateway replica is not supported by v1. The startup lock and epoch are safety controls for a single active process, not a complete multi-region or active-active consensus protocol.

## 2.5 Feasibility rule

Do not add a role, table, worker, queue, abstraction, or infrastructure component unless it protects a stated invariant or removes a demonstrated operational risk. Prefer one modular monolith and a small number of explicit workflows.

---

# 3. Technology choices

| Area | Choice | Reason |
|---|---|---|
| Runtime | Node.js LTS + TypeScript | Existing full-stack skill base; strong streaming and web ecosystem |
| HTTP | Fastify | Lightweight, typed request lifecycle, good performance |
| Web | Next.js App Router + React | Control Plane and demo UI |
| Database | PostgreSQL 16+ | Durable attempt ledger, transactions, constraints, RLS |
| ORM | Drizzle | Typed queries and schema support; use explicit SQL for RLS, roles, functions, locks, and critical constraints |
| Coordination | Redis 7+ | Atomic Lua operations, reservations, rate limits, circuit breakers |
| Jobs | BullMQ | Retryable background trace and attempt-persistence work |
| Validation | Zod | Strict request and configuration validation |
| Password hashing | Argon2id | Memory-hard password hashing |
| Credential encryption | AES-256-GCM envelope encryption | Confidentiality and integrity for provider keys |
| Local deployment | Docker Compose | Repeatable environment without unnecessary orchestration |
| Tests | Vitest or equivalent + real PostgreSQL/Redis integration tests | Exercise actual locking, RLS, Lua, and queue semantics |
| Load harness | TypeScript + undici streaming client | Measure first token and stream behavior without full-response buffering |

Pin Node, PostgreSQL, Redis, package, and container versions. Keep `pnpm-lock.yaml` committed. Do not claim provider compatibility based only on an OpenAI-shaped JSON request.

---

# 4. High-level architecture

```text
                         UNTRUSTED CLIENTS
              SDK / API clients / Browser Dashboard
                              |
                   HTTPS + virtual API key
                              |
                 +------------v-------------+
                 |      Fastify Gateway     |
                 |                          |
                 | Auth + validation        |
                 | Tenant/policy checks     |
                 | Rate limits              |
                 | Budget reservation       |
                 | Provider routing         |
                 | SSE proxy / abort        |
                 | Control-plane API        |
                 +----+----------------+----+
                      |                |
             SQL/TLS  |                | HTTPS/TLS
                      |                v
              +-------v------+   +----------------------+
              | PostgreSQL   |   | OpenAI / Gemini /     |
              |              |   | Groq / Mock           |
              | Requests     |   +----------------------+
              | Attempts     |
              | Adjustments  |         Redis
              | Users        |   +----------------------+
              | Keys         |   | Reservations         |
              | Sessions     |   | Attempt state        |
              | Traces       |   | Rate limits          |
              | RLS          |   | Circuit breakers     |
              +-------+------+   | BullMQ queues        |
                      |          +----------+-----------+
                      |                     |
                      +----------+----------+
                                 |
                       +---------v---------+
                       | Background Workers |
                       | Persistence /      |
                       | Recovery / Pruning |
                       +--------------------+

                 Next.js Control Plane UI
           Same-origin browser session + CSRF token
```

## 4.1 Responsibility boundaries

- **Routes:** HTTP parsing, schema validation, authentication handoff, response mapping. No Redis Lua or SQL business logic embedded in handlers.
- **Application services:** Use-case orchestration and transaction ownership.
- **Budget module:** All money-mutating Redis calls and budget invariants. No other module may mutate accounting keys.
- **Database module:** Explicit SQL transactions, RLS context helper, repository queries, and migration support.
- **Provider adapters:** Provider-specific request/response normalization. They do not import database or budget implementations.
- **Proxy module:** SSE parser, downstream writer, abort lifecycle, and response caps.
- **Workers:** Retryable persistence, reconciliation, retention, and trace jobs. Workers do not decrypt provider keys.
- **Web application:** Dashboard and user interactions. Browser JavaScript never receives long-lived gateway virtual keys or provider secrets.

## 4.2 Dependency direction

```text
routes / workers / web API clients
             |
             v
       application services
             |
             v
      domain decisions/types
             |
             v
         ports/interfaces
             |
             v
   PostgreSQL / Redis / provider adapters
```

Avoid circular dependencies. Do not let route handlers directly manipulate Redis keys, execute financial SQL, or call provider-specific fetch logic.

---

# 5. Core invariants

These are normative. Every implementation decision and test must preserve them.

## 5.1 Admission and request invariants

1. Every provider call has a unique `attempt_id`.
2. A durable PostgreSQL `provider_attempts` row in `reserved` state exists before the upstream request is sent.
3. Every logical client request has a durable `gateway_requests` row before any provider dispatch.
4. A fallback provider call is a separate attempt with a new ID and its own reservation.
5. No provider call is sent if authentication, authorization, model capability, budget reservation, durable admission, or current-epoch checks fail.
6. A client request can have zero provider attempts (cache hit), one attempt, or a bounded number of attempts (v1 maximum: one primary plus one fallback).
7. The request's billing period is derived once from the PostgreSQL admission timestamp in UTC and is immutable for all its attempts.

## 5.2 Financial invariants

1. Money is stored in integer microdollars. `$1.00 = 1,000,000` microdollars.
2. TypeScript uses `bigint` for all money arithmetic. JSON transports microdollar amounts as decimal strings or formatted currency, never as unsafe floating-point values.
3. Redis Lua arithmetic is bounded below the exact integer range of IEEE-754 doubles. V1 caps an organization's monthly budget and all intermediate monetary counters at `1,000,000,000,000,000` microdollars ($1 billion), well below `2^53 - 1`.
4. An estimate is never labelled confirmed actual usage.
5. The initial base cost of a settled attempt is immutable. Late usage/invoice corrections are append-only adjustments.
6. PostgreSQL is the financial source of truth. Redis counters are derived enforcement state and can be rebuilt.
7. Redis ACK is idempotent. Replaying settlement cannot double-increment settled spend.
8. Lease expiry does not release budget while the upstream call may still be active or the Gateway may be paused.
9. No unconditional zero-overspend guarantee is made. Reservation accuracy depends on token estimation, provider pricing, hidden reasoning-token behavior, and provider-side billing after aborts.

## 5.3 Tenant/security invariants

1. All tenant-owned tables use PostgreSQL RLS with `ENABLE` and `FORCE` and explicit `USING` and `WITH CHECK` policies.
2. Composite foreign keys enforce that child records reference parents from the same organization.
3. Runtime roles are not superusers, do not have `BYPASSRLS`, and do not own tenant tables.
4. `SECURITY DEFINER` functions are narrowly scoped, owned by dedicated non-login roles, have a hardened search path, and are not executable by `PUBLIC`.
5. The browser Control Plane uses a revocable server-side session. The data plane uses virtual API keys. The two principal types are not interchangeable.
6. Provider secrets, virtual keys, session IDs, CSRF tokens, and raw prompts are never written to logs.
7. RLS protects against missing tenant predicates and accidental cross-tenant queries. It does not protect against arbitrary SQL execution with a compromised runtime credential that can set the tenant GUC.

## 5.4 Streaming invariants

1. A TCP chunk is not assumed to equal an SSE event.
2. Parser buffers and full response bodies have explicit limits.
3. Downstream backpressure stops upstream consumption until the client is ready or the request is aborted.
4. Client disconnect aborts the upstream request and enters the attempt finalization path exactly once.
5. Failover is allowed only before the first content token is emitted downstream.
6. Once downstream bytes are committed, a mid-stream failure becomes an SSE error; it is not a provider switch.

---

# 6. Request lifecycle

## 6.1 Pre-admission checks

1. Accept only the configured HTTP method and route.
2. Enforce Fastify body-size limits before parsing large request bodies.
3. Apply a cheap per-IP abuse limiter before virtual-key lookup. Only trust forwarded client IP headers when `trustProxy` is explicitly configured for the known reverse proxy.
4. Parse and validate the request with Zod. Reject unknown or unsupported request fields unless explicitly permitted by the API contract.
5. Hash the presented `gw_live_...` key and call the restricted PostgreSQL key lookup. Do not cache virtual-key authorization in Redis in v1.
6. Return one generic `401` for missing, malformed, unknown, or revoked virtual keys. Do not reveal whether a key prefix or tenant exists.
7. Check model allowlist and the provider/model capability table.
8. Apply per-key request-rate limits and maximum input/output caps before creating durable request rows.
9. Apply configured PII redaction before provider dispatch and any persistence that is intended to contain redacted payloads.

Rejected requests may be represented by sampled metrics/log counters. Do not write one full `gateway_requests` row for every malformed or rate-limited request; this would allow a valid key or anonymous caller to create avoidable PostgreSQL write amplification.

## 6.2 Logical request admission

After cheap validation and rate checks:

1. Create a `gateway_requests` row in PostgreSQL with `status='in_progress'`.
2. Set `admitted_at` using the PostgreSQL clock and derive `billing_period` as UTC `YYYY-MM` from that timestamp.
3. Store `gateway_instance_id` and the current `gateway_epoch`.
4. The returned immutable `billing_period` is reused by every provider attempt and every later cost adjustment for the request.
5. If PostgreSQL cannot create the row, reject the request before any provider dispatch.

## 6.3 Provider attempt admission

For each primary or fallback provider attempt:

1. Generate a new UUID `attempt_id` and `attempt_number`.
2. Resolve the exact provider/model and its verified capability/pricing entry.
3. Estimate the maximum cost for the input estimate, declared output cap, and model-specific reasoning allowance.
4. Execute Redis `RESERVE` with organization, billing period, attempt ID, estimated microdollars, current Redis generation, and current Gateway epoch.
5. If `RESERVE` returns `NEEDS_HYDRATION`, perform the lock-serialized per-organization/period hydration in Section 8.4 and retry once. If it returns `FENCED`, `RECOVERY_REQUIRED`, or `REJECTED_BUDGET`, do not dispatch.
6. In a PostgreSQL transaction, acquire the shared epoch transaction advisory lock (Section 8.1), re-read the current durable epoch, and verify it matches the process epoch.
7. Lock and re-check the virtual key's active status in the same transaction. The revocation transaction and attempt admission must serialize on the virtual-key row. A key revoked before the admission transaction's lock/check cannot create a new attempt.
8. Insert the `provider_attempts` row with `status='reserved'`, estimate, provider/model, attempt number, Gateway ID/epoch, hard deadline, and the logical request's immutable billing period.
9. Commit the PostgreSQL admission transaction.
10. Only after both Redis reservation and durable PostgreSQL attempt admission succeed may the Gateway dispatch upstream.
11. If the PostgreSQL insert is known to have rolled back, release the Redis reservation through `CANCEL_RESERVATION` and do not dispatch. If the commit outcome is ambiguous, leave the reservation held and resolve from PostgreSQL; never cancel budget based on an uncertain commit.
12. Immediately before provider dispatch, verify the process is not fenced, the deadline has not elapsed, and the attempt is still eligible. The single-Gateway process supervisor contract in Section 8.2 is also required.

## 6.4 Logical request finalization

`gateway_requests` is created at admission, not by a BullMQ finalization job.

The Gateway performs an idempotent PostgreSQL update from `in_progress` to a terminal state (`completed`, `failed`, `client_aborted`, or `interrupted`). It does not rely on enqueueing a `finalize_request` job after the response has finished.

For streaming requests, finalize the logical request before sending the final `[DONE]` marker where practical. If PostgreSQL finalization fails after a bounded retry, emit a terminal stream error and leave the row eligible for the stale-request recovery process. Do not tell the client that the request completed durably when it did not.

A recovery worker finds stale `in_progress` rows older than the maximum request duration plus teardown grace and marks them `interrupted`, deriving the final attempt summary from durable attempt rows.

---

# 7. Distributed budget and attempt accounting

## 7.1 Cost model

Use integer microdollars throughout:

```text
1 USD = 1,000,000 microdollars
```

Per provider attempt:

- `estimated_cost_microdollars`: reservation estimate and conservative fallback cost.
- `actual_cost_microdollars`: nullable provider-reported authoritative cost.
- `effective_cost_microdollars`: generated base cost `COALESCE(actual_cost_microdollars, estimated_cost_microdollars)`.
- `cost_status`: `estimated` or `confirmed` for the initial settlement.

The canonical cost of an attempt is:

```text
base effective_cost_microdollars
+ SUM(provider_cost_adjustments.delta_microdollars)
```

### Initial settlement and late corrections

At initial settlement:

- If authoritative provider usage is available, set `actual_cost_microdollars` and `cost_status='confirmed'`.
- If usage is unavailable or ambiguous, keep `actual_cost_microdollars=NULL`, retain the estimate, and set `cost_status='estimated'`.
- A connection failure can be confirmed zero only when the implementation can prove no request bytes were transmitted. Do not assume every 429/5xx response is free.

Once an attempt is settled or interrupted, its base cost fields are immutable. If later provider usage or an invoice changes the canonical amount, append a `provider_cost_adjustments` row. Do not update `actual_cost_microdollars` and also insert a delta for the same correction.

Each adjustment records:

- Unique `adjustment_id`.
- `attempt_id` and `org_id`.
- `previous_cost_microdollars` (the canonical amount before this adjustment).
- `corrected_cost_microdollars` (the new canonical amount).
- `delta_microdollars = corrected - previous`.
- Source (`provider_usage`, `provider_invoice`, `manual_review`).
- Creation timestamp and optional source reference.

The transaction locks the attempt/organization accounting scope, verifies the expected previous canonical amount, inserts the adjustment once, and rejects an adjustment ID replay with conflicting payload. All corrections after initial settlement use this path, including late authoritative usage for an attempt previously marked interrupted at an estimate.

## 7.2 Budget equation

For organization `org` and billing period `period`:

```text
settled_spend
+ pending_total
+ res_total
+ expired_hold_total
+ new_estimated_reservation
<= monthly_budget_microdollars
```

Where:

- `settled_spend` is the PostgreSQL canonical cost aggregate projected into Redis.
- `pending_total` is completed usage awaiting durable PostgreSQL persistence.
- `res_total` is active stream reservation amount.
- `expired_hold_total` is an expired lease that may still represent upstream work.
- `new_estimated_reservation` is the proposed new attempt amount.

Every transition must move value between categories without dropping it or counting it twice. Expired leases remain counted. An unknown outcome is treated conservatively at the original estimate until better evidence arrives.

## 7.3 Redis key model

V1 uses standalone Redis. Redis Cluster is out of scope because global admission gates and multi-key scripts would require a different key-slot design.

Global keys:

```text
gateway:admission_gate          STRING ready|recovering
gateway:admission_generation    STRING <redis_run_id>|<gateway_epoch>
```

Per-organization/per-period keys (the active generation is referenced by an organization-period generation pointer):

```text
{org}:{period}:active_generation
{org}:{period}:budget_gate                 ready|recovering
{org}:{period}:settled_spend               integer microdollars
{org}:{period}:attempt_state               HASH attempt_id -> state
{org}:{period}:res_exp                     ZSET attempt_id -> expiry_ms
{org}:{period}:res_amt                     HASH attempt_id -> estimate_microdollars
{org}:{period}:res_total                   integer microdollars
{org}:{period}:expired_hold_total          integer microdollars
{org}:{period}:pending_settle              HASH attempt_id -> allowlisted completion metadata
{org}:{period}:pending_total               integer microdollars
{org}:{period}:applied_adjustments         HASH adjustment_id -> delta_microdollars
```

The physical keys include an active generation suffix for staged rebuilds. A single atomic generation-pointer switch publishes the rebuilt key family. Old generations remain inaccessible to normal admission and are pruned after successful verification.

`pending_settle` may contain only IDs, provider/model identifiers, token counts, cost values, timestamps, outcome enums, and retry metadata. It must never contain raw prompts, response text, provider credentials, virtual API keys, cookies, or PII.

## 7.4 Attempt state machine

The Redis attempt state is one-way:

```text
NONE
  |
  | RESERVE
  v
RESERVED_ACTIVE ---------------------------> PENDING_SETTLE -----------> ACKED
  |                                             ^
  | lease expires                               |
  v                                             |
LEASE_EXPIRED_HOLD ----------------------------+
  |
  | safe cancellation only after proven rollback
  | or old epoch fenced + no PG admission row
  v
CANCELLED
```

Definitions:

- `RESERVED_ACTIVE`: active reservation with a renewable lease.
- `LEASE_EXPIRED_HOLD`: lease expired; amount remains in `expired_hold_total` and cannot be reused.
- `PENDING_SETTLE`: completion payload is awaiting durable PostgreSQL settlement.
- `ACKED`: PostgreSQL has the terminal attempt row and Redis settled spend has been incremented or reconstructed.
- `CANCELLED`: provider dispatch was impossible because the PostgreSQL admission was conclusively rolled back or an old epoch was fenced and no admission row exists.

No operation may recreate `ACKED` or `CANCELLED` state. An attempt ID is never reused. `COMPLETE_STREAM` after `ACKED` is a no-op. Any impossible state transition is an invariant violation, not a best-effort success.

## 7.5 Operation/state matrix

The implementation must explicitly handle every relevant state. No implicit fall-through is allowed.

| Operation | NONE | RESERVED_ACTIVE | LEASE_EXPIRED_HOLD | PENDING_SETTLE | ACKED | CANCELLED |
|---|---|---|---|---|---|---|
| `RESERVE` | Create reservation | Duplicate/conflict | Duplicate/conflict | Duplicate/conflict | Duplicate/conflict | Reject reuse |
| `RENEW_LEASE` | Missing/invalid | Renew only if unexpired and generation matches | Return expired; do not renew | No-op/invalid | No-op | No-op |
| `EXPIRE_LEASE` | No-op | Move `res_total` to `expired_hold_total` | No-op | No-op | No-op | No-op |
| `COMPLETE_STREAM` | Recovery required; never create | Move active amount to pending and store completion | Move expired hold to pending and store completion | No-op | No-op | Invariant violation/no-op; never resurrect |
| `ACK_LEDGER` | Recovery required | Remove active reservation, add committed settled cost, mark ACKED | Remove expired hold, add committed settled cost, mark ACKED | Remove pending amount, add committed settled cost, mark ACKED | No-op | Invariant violation; a dispatched attempt cannot be cancelled |
| `CANCEL_RESERVATION` | No-op | Release only with confirmed rollback / safe old-epoch recovery | Release only with confirmed rollback / safe old-epoch recovery | Reject | Reject | No-op |
| `HYDRATE` | Rebuild from PG | Rebuild from PG | Rebuild from PG | Rebuild from PG | Rebuild from PG | Rebuild/retain terminal state as appropriate |

`ACK_LEDGER` must use the committed PostgreSQL effective amount, never trust the BullMQ payload as the financial source. If it finds `RESERVED_ACTIVE` or `LEASE_EXPIRED_HOLD`, it releases that reservation category before adding settled spend. This avoids a reservation remaining counted after the PostgreSQL row becomes terminal.

## 7.6 Redis operation requirements

### `RESERVE`

1. Verify global admission gate is `ready`.
2. Verify global Redis run ID + Gateway epoch generation matches the process.
3. Verify organization-period gate and active generation.
4. Reject duplicate attempt IDs in any existing state.
5. Validate key types, arguments, monetary ranges, state values, and arithmetic bounds before the first mutation.
6. Read current time from Redis `TIME` inside the script; do not trust arbitrary client clocks for lease expiry.
7. Check the budget equation.
8. Create `RESERVED_ACTIVE`, expiry score, estimate, and `res_total` update atomically.
9. Return a typed result: `RESERVED`, `REJECTED_BUDGET`, `DUPLICATE`, `NEEDS_HYDRATION`, `RECOVERY_REQUIRED`, or `FENCED`.

### `RENEW_LEASE`

- Use Redis `TIME`.
- Verify global/per-organization generation and gate.
- Renew only an unexpired `RESERVED_ACTIVE` attempt.
- If the lease has expired, atomically move it to `LEASE_EXPIRED_HOLD`; do not renew it after expiry.
- If the gate is recovering or the generation is stale, return `RECOVERY_REQUIRED` / `FENCED` and make the Gateway abort/finalize the stream.

### `EXPIRE_LEASE`

- Do not scan an unbounded ZSET inside `RESERVE`.
- A bounded background reaper processes a small batch (for example, at most 100 expired members per invocation).
- Expiry moves an amount from `res_total` to `expired_hold_total`; it does not release budget.
- `RESERVE` may process a small bounded number of expired entries as an optimization, but correctness must not depend on a full sweep.

### `COMPLETE_STREAM`

- Operates only when the global and organization gates are `ready` and the caller's generation matches.
- `RESERVED_ACTIVE`: remove active reservation, add effective cost to `pending_total`, store allowlisted completion metadata, transition to `PENDING_SETTLE`.
- `LEASE_EXPIRED_HOLD`: remove expired hold, add effective cost to `pending_total`, store metadata, transition to `PENDING_SETTLE`.
- `PENDING_SETTLE` or `ACKED`: no-op.
- `CANCELLED`: invariant violation; do not recreate state.
- Missing/stale generation: return `RECOVERY_REQUIRED`; the Gateway records any known completion directly in PostgreSQL under the organization lock and lets hydration rebuild Redis.

### `ACK_LEDGER`

1. Worker commits the terminal attempt state in PostgreSQL first.
2. It reads the committed effective cost from PostgreSQL.
3. Redis checks the active generation and budget gate.
4. Redis removes the attempt from exactly one reservation/pending category based on its state.
5. Redis increments `settled_spend` by the committed effective cost and marks the attempt `ACKED`.
6. Repeated ACK for `ACKED` is a no-op.
7. If the gate is recovering or the generation is mismatched, it does not mutate old keys; the next hydration reconstructs the accounting state.

### `CANCEL_RESERVATION`

This is deliberately narrow:

- Same-process cancellation is allowed only after the PostgreSQL attempt-admission transaction is conclusively rolled back.
- The background sweeper must **never cancel a current-epoch reservation merely because a PostgreSQL lookup returned no visible row**. “No row visible in this snapshot” does not prove that an in-flight admission transaction cannot commit later.
- A sweeper may cancel an old-epoch reservation only after the Gateway epoch has advanced under the epoch-fencing protocol, the old Gateway process is confirmed stopped/fenced, the hard deadline plus teardown grace has elapsed, and a successful tenant-scoped PostgreSQL lookup confirms no attempt row exists.
- If the database result is ambiguous or the old process may still dispatch, keep the reservation as an expired hold.

## 7.7 Lua correctness, time, and memory

Redis Lua scripts serialize execution and prevent other Redis commands from interleaving while the script runs. This is not a cross-system transaction and must not be treated as automatic rollback of earlier writes when a later command returns a runtime error.

Requirements:

- Preflight every key type, argument, state, and integer range before the first mutation.
- Calculate all amounts and transition decisions before mutating counters.
- Use a bounded maximum budget/counter below `2^53 - 1` microdollars so Lua numeric comparisons remain exact.
- Use TypeScript `bigint`; serialize integer amounts as decimal strings across client boundaries.
- Never use floating-point currency calculations.
- Use Redis `TIME` inside scripts for lease and token-bucket time.
- Keep scripts short and bounded. Never loop through an unbounded number of members on an admission request.
- Configure Redis `maxmemory-policy noeviction`; provision memory headroom and alert before the limit.
- Use Redis ACLs and a private network. Runtime users must not be allowed to invoke `FLUSHALL`, `FLUSHDB`, `CONFIG`, `DEBUG`, `SHUTDOWN`, `REPLICAOF`, or unrestricted administrative/keyspace commands.
- If a script returns an unexpected runtime error or the client cannot determine whether it completed, stop budget-sensitive admission for the affected organization or globally, mark the state as requiring recovery, and rebuild from PostgreSQL before reopening.
- Do not assume that `noeviction` makes OOM errors impossible. It causes write failures rather than silently evicting keys; the application must fail closed on write errors.

## 7.8 Provider attempt persistence and BullMQ

`provider_attempts` is durable before dispatch. After stream completion:

1. `COMPLETE_STREAM` stores the compact pending payload in Redis.
2. The Gateway enqueues `persist_attempt` with deterministic `jobId = attempt_<attempt_id>`.
3. The worker locks the PostgreSQL attempt row and changes `reserved` to `settled` or `interrupted`, persisting actual or estimated usage. If already terminal, it verifies/replays idempotently rather than overwriting the record.
4. After PostgreSQL commits, the worker performs `ACK_LEDGER` with the committed amount.
5. If the Redis ACK fails, the job remains retryable and the organization is marked for reconciliation where possible. The pending Redis payload and durable PostgreSQL row are both recovery inputs.

BullMQ job ID behavior must be handled deliberately:

- If a job is waiting, delayed, or active, do not add a duplicate.
- If a retained job is failed, use BullMQ's supported retry path for the existing job; do not blindly call `add` with the same ID.
- If a job is completed, verify PostgreSQL is terminal and Redis is ACKED/current. If not, run the repair/hydration path.
- If the job is absent or removed, re-enqueue with the deterministic ID. PostgreSQL uniqueness/state transitions make duplicate processing harmless.
- BullMQ job existence is not proof of financial settlement.

The orphan sweeper scans stale `pending_settle` records. It checks the existing job state and follows the rules above. If Redis loses pending payloads, the durable PostgreSQL `reserved` attempt row remains the recovery anchor; after the hard deadline and teardown grace, recovery settles it conservatively at the estimate. Do not store raw prompts, responses, or credentials in BullMQ payloads.

## 7.9 Late provider usage and cost adjustments

If an attempt is interrupted/estimated and later authoritative provider usage arrives:

- Do not mutate the settled base amount.
- Insert one append-only adjustment that moves the canonical amount from the estimate to the newly observed amount.
- Use a stable provider source reference when available.
- Enforce uniqueness on the adjustment ID/source reference.
- Verify that an adjustment replay carries identical values; a conflicting replay is an invariant violation.
- Apply the delta to Redis once under the same organization-period lock. If Redis is recovering, do not apply it to the old generation; it is included in the next PostgreSQL-derived rebuild.

## 7.10 Accounting consistency checks

- PostgreSQL canonical spend is the authoritative aggregate.
- On Redis process restart, missing global gate, generation mismatch, script uncertainty, or detected counter drift, stop admission and rebuild the affected accounting generation.
- A periodic consistency audit compares each active organization-period's Redis totals with the corresponding PostgreSQL canonical aggregate and the sums of Redis reservation/pending structures.
- Any unexplained mismatch closes the relevant budget gate and triggers a rebuild. Do not silently “nudge” counters by a guessed delta.
- Emit metrics for `budget_equation_drift`, `pending_settle_age_max`, `expired_hold_total`, `recovery_duration`, `recovery_failures`, and `accounting_gate_state`.

---

# 8. Gateway fencing, recovery, and billing periods

## 8.1 Gateway epoch lock without unsafe row privileges

`gateway_control` is a global operational table outside tenant RLS. It contains a singleton `gateway_epoch`.

Use two distinct PostgreSQL advisory-lock purposes:

1. A **session-level exclusive advisory lock** held on a dedicated `gateway_startup` connection for the lifetime of the single active Gateway process. If another process holds it, the new process refuses to start admission.
2. A **transaction-level shared/exclusive advisory lock** for epoch fencing:
   - Each provider-attempt admission transaction takes a shared transaction advisory lock on a documented reserved key, reads the durable epoch, verifies it matches the process epoch, and inserts the attempt before committing.
   - Gateway startup takes the matching exclusive transaction advisory lock before incrementing the epoch. It waits for in-flight admission transactions to finish; subsequent admissions see the new epoch and reject stale processes.

This avoids the `SELECT ... FOR SHARE` privilege problem: PostgreSQL requires `UPDATE` privilege on at least one column for `SELECT ... FOR SHARE`. The runtime role remains SELECT-only on `gateway_control` and cannot update the epoch.

Use separate fixed advisory-lock key constants for the singleton process lock and the epoch read/write fence. Document them in one module and test collision avoidance.

## 8.2 Singleton process health and stale-process behavior

- Keep the dedicated `gateway_startup` connection open for the process lifetime.
- Configure PostgreSQL TCP keepalives and run an active heartbeat (for example, `SELECT 1` every two seconds with a bounded timeout).
- If the connection or advisory lock is lost, set an in-memory `isFenced=true`, reject all new requests including cache hits, abort active streams, and terminate the Gateway process through the process supervisor.
- Startup of a replacement Gateway is permitted only after the previous local process/container is confirmed stopped. The advisory lock is a guard, not a magical way to kill a process paused by an arbitrary host/network partition.
- Before dispatch, verify the process has not been fenced, the durable epoch still matches, the attempt remains eligible, and the hard deadline has not elapsed.
- Existing admitted attempts remain budget-held until they settle or are conservatively recovered. The project does not claim that a network abort can prove the provider stopped billing.

This is a single-instance v1 operational contract. Multi-host split-brain prevention and active-active dispatch fencing are post-v1 work.

## 8.3 Redis generation and global admission gate

Redis `INFO server` exposes a `run_id` for the current Redis process. On every connection-ready/reconnect event, compare the current run ID and Gateway epoch against the published generation.

On process restart, generation mismatch, missing global gate, detected data loss, or accounting script uncertainty:

1. Close the global admission gate (`recovering`) before admitting further provider attempts.
2. Stop new admissions and abort/drain active streams within a bounded grace period.
3. Set affected organization-period gates to `recovering`.
4. Ensure active Gateway callbacks cannot mutate the old Redis generation. All budget-mutating scripts must check both global and local gates/generation.
5. Finalize known attempt usage directly in PostgreSQL under the per-organization accounting lock when Redis cannot be safely updated.
6. Rebuild organization-period state from PostgreSQL as described below.
7. Verify rebuilt counts and totals.
8. Publish the organization generation and set its gate to `ready` only after verification.
9. Reopen the global admission gate only after every organization discovered by the maintenance enumerator is ready. A newly created organization can still use lazy per-period hydration before its first attempt.

## 8.4 Staged organization-period hydration

Do not rebuild a large organization-period history with one unbounded Lua loop. Do not mutate the active key family while admission is open.

Hydration procedure:

1. Acquire a per-organization/per-period PostgreSQL session advisory lock on a pinned connection.
2. Mark the organization-period budget gate `recovering` and ensure global admission is closed when recovery is global.
3. Read a consistent PostgreSQL snapshot of:
   - canonical settled spend (base effective costs plus all committed adjustments),
   - all still-reserved attempts and their original estimates,
   - pending/terminal attempt identities needed for the state projection,
   - applied adjustment IDs needed for idempotency markers.
4. Allocate a new Redis generation namespace that is not currently active.
5. Reconstruct the new key family in bounded batches while the gate is closed. Do not carry over stale Redis counters as authoritative values.
6. Include all `ACKED`/terminal attempt tombstones needed for the retained billing period; rebuild the `applied_adjustments` marker set from PostgreSQL.
7. Reconstruct any still-reserved attempt as a conservative expired hold unless its owning current Gateway stream is known to remain active and fenced by the current generation.
8. Verify the totals and counts in the staged generation against the PostgreSQL snapshot.
9. Atomically switch the organization-period active-generation pointer and set the local gate to `ready` using one short Lua script. The active generation changes only if the expected old generation and global recovery generation still match.
10. Release the PostgreSQL session lock.

While the organization-period gate is `recovering`, Gateway-originated `RESERVE`, `RENEW_LEASE`, `COMPLETE_STREAM`, `CANCEL_RESERVATION`, and worker `ACK_LEDGER` must not mutate the old active generation. A completion callback with known usage updates PostgreSQL directly under the organization lock; the staged generation then includes it. This prevents a concurrent stream callback from being overwritten or dropped by hydration.

## 8.5 Lazy hydration for new organizations and month rollover

A new organization or new UTC billing period has no Redis key family yet. It must not be interpreted as a zero-spend ready budget.

- `RESERVE` returns `NEEDS_HYDRATION` when the organization-period generation is missing.
- The Gateway/worker acquires the per-organization/per-period advisory lock, calculates the PostgreSQL aggregate (zero for a new period), builds the new generation, verifies it, switches the active pointer, and retries `RESERVE` once.
- Concurrent requests for the same organization-period serialize on the same lock; they do not independently rebuild the same key family.
- `billing_period` is derived once from the PostgreSQL admission timestamp in UTC and stored immutably in `gateway_requests`; each attempt inherits it. All Redis reserve/settle/adjustment operations use that stored period, even if the stream crosses midnight or month end.
- A late adjustment always targets the original attempt billing period. If old Redis keys have already expired, apply the adjustment to PostgreSQL and let historical reporting use the canonical query; do not recreate a closed live budget accidentally.

## 8.6 Maintenance organization enumeration under RLS

Global startup recovery, stale-request recovery, and retention pruning need to discover organizations. `gateway_app` must not receive broad `BYPASSRLS` or unscoped tenant-table access to make this work.

Add one restricted maintenance function (for example, `app_private.list_active_org_ids(after_id, limit)`) that:

- Is `SECURITY DEFINER`, owned by a dedicated `NOLOGIN BYPASSRLS` `gateway_ops_executor` role.
- Returns only organization UUIDs and uses bounded keyset pagination.
- Does not return names, budgets, key material, credentials, users, or prompts.
- Is revoked from `PUBLIC` and granted only to the required startup/worker role.
- Uses a fixed trusted search path with `pg_temp` last, fully-qualified object names, and no dynamic SQL.

Workers then enumerate IDs and perform all data work inside `withTenant(orgId, ...)` with the per-organization lock. Never grant `BYPASSRLS` to `gateway_app` or `gateway_worker` and never make workers owners of tenant tables.

---

# 9. Provider routing and resilience

## 9.1 Provider capability registry

Maintain a versioned capability/pricing table for each provider/model pair. Each entry contains at least:

- Provider and exact model identifier.
- Official endpoint adapter identifier.
- Supported request parameters and explicit unsupported parameters.
- Input/output limits and provider-specific output-limit field name.
- Tokenizer family or explicit estimation method.
- Whether reasoning tokens are billed as output and any required allowance.
- Streaming usage support and usage field mapping.
- Tool/function calling support.
- Input/output price per million tokens, effective date, and `last_verified` URL/date.
- Whether the model is permitted as a fallback for a given request class.

Unknown models or models without a current verified pricing/capability entry are rejected before dispatch in budget-enforced mode.

## 9.2 Adapter behavior

Each provider adapter owns:

- Fixed HTTPS endpoint and provider authentication.
- Request schema validation and model alias resolution.
- Explicit parameter allowlist/mapping.
- Usage extraction and token/cost normalization.
- SSE error and finish-reason normalization.
- Structured provider error classification.

Do not silently strip a caller-requested parameter if doing so changes request semantics. Reject unsupported non-default parameters with a structured error. Only map parameters silently when equivalence is documented and contract-tested.

## 9.3 Circuit breaker

Circuit breaker state is scoped by `(org_id, provider)` so one organization's invalid key or provider quota issue does not break another organization.

- States: `CLOSED`, `OPEN`, `HALF_OPEN`.
- Initial policy may be five consecutive eligible failures or at least 50% eligible failures in the last ten attempts; tune using tests, not intuition.
- Initial cooldown: 30 seconds, configurable.
- Half-open probe uses an atomic Redis `SET NX` lease.
- Eligible failures: transient 429, selected 5xx, connection reset/refusal, and TTFT timeout.
- Non-trip errors: invalid request/model, authentication/authorization errors such as 400/401/403/422.
- Respect a valid `Retry-After` as a lower bound on retry/cooldown timing.

## 9.4 Failover policy

- V1 allows at most one fallback attempt per logical request.
- Failover occurs only before the first downstream content token.
- Abort the primary upstream fetch before dispatching the fallback.
- Do not classify a timeout/429/5xx as free unless zero billable work is known. Otherwise, conservatively estimate primary cost.
- Keep the primary reservation held until its terminal usage/cost is persisted or the attempt is conservatively recovered.
- Reserve fallback cost independently using the fallback model's price and capability entry.
- Reject fallback if it is unsupported or the remaining organization budget is insufficient.
- Once the first content token has been emitted, no provider switch is allowed. Emit an SSE error and settle partial/estimated cost.

---

# 10. Streaming, HTTP, and runtime resource safety

## 10.1 SSE parser

Use a stateful incremental UTF-8 parser. It must handle:

- Arbitrary byte boundaries and multibyte UTF-8 split across chunks.
- CRLF, LF, and CR line endings.
- A UTF-8 BOM at stream start.
- Multiple `data:` fields in one event.
- Comment lines.
- Blank-line event dispatch.
- `[DONE]` and provider-specific usage-only final chunks.
- EOF with a partial line/event.
- Invalid UTF-8 and malformed provider events.

Limits are independent of the trace-capture cap:

- Maximum line size: 256 KiB.
- Maximum event size: 1 MiB.
- Maximum total non-streaming response body: 4 MiB by default.
- Configurable maximum total streaming bytes, upstream header bytes, connect timeout, response-header timeout, body-inactivity timeout, and total request deadline.

Exceeding a limit aborts the upstream and finalizes the attempt as an error/estimated outcome. Parser buffers must never grow without bound.

## 10.2 Fastify response lifecycle

For an SSE response written directly through `reply.raw`, call `reply.hijack()` before manual raw writes so Fastify does not also execute its normal response-sending path. Set all required status, content-type, cache-control, CORS, and security headers before hijacking.

Use the downstream response's premature-close signal (for example, `reply.raw.on('close')` with a check that the response has not finished) to detect client disconnect. Do not treat `request.raw.on('close')` as a response-disconnect signal: Node's `IncomingMessage` close semantics changed and the event can occur when request input has completed. Test normal request completion separately from a disconnected response.

For `stream:false`, use Fastify's normal response path, cap the upstream body, abort on client close, and run the same attempt settlement path.

## 10.3 Backpressure

When `reply.raw.write(chunk)` returns false:

- Stop reading upstream until the downstream `drain` event.
- Race `drain` against client close, upstream error, and request deadline.
- Do not continue buffering upstream chunks while waiting.
- Abort and settle once if the client disconnects or deadline is reached.

Use a single `AttemptFinalizer` to coordinate normal completion, abort, timeout, error, and shutdown. A local `once` latch prevents duplicate work within the process; PostgreSQL/Redis state guards provide durable idempotency.

## 10.4 Upstream trust boundary

Treat provider responses as untrusted input even when received over TLS.

- Use fixed provider HTTPS origins; do not accept user-supplied provider base URLs in v1.
- Disable redirects (`redirect: 'error'`) for provider requests.
- Never interpolate an unchecked user-supplied model/path segment into a URL. Validate model IDs against the capability table and use fixed adapter endpoints.
- Verify TLS certificates. Production boot must fail if TLS certificate verification is disabled.
- Use an outbound request-header allowlist. Never forward the client's `Authorization`, `Cookie`, `Host`, `X-Forwarded-*`, or hop-by-hop headers to a provider.
- Use a downstream response-header allowlist. Do not forward upstream `Set-Cookie`, `Transfer-Encoding`, `Connection`, or provider authentication headers.
- Bound upstream connection count per provider, connection timeout, response-header timeout, body-inactivity timeout, total deadline, header size, line/event size, and body size.
- A custom URL/connectivity-test feature is out of scope for v1. If ever added, it requires a separate SSRF design including DNS/IP resolution, private/link-local/loopback denial, redirects, and egress controls.
- Mock upstream and fault-injection endpoints are unavailable in production mode and remain on the private Compose network or loopback only.

## 10.5 Memory and concurrency limits

Configure explicit limits rather than relying only on RPM/TPM:

- Fastify body limit (initial target 512 KiB for chat completions; tune after testing).
- Maximum input tokens and output cap.
- Global maximum in-flight provider streams.
- Per-organization maximum in-flight streams.
- Per-virtual-key concurrent stream limit.
- Per-provider connection cap and bounded connection queue.
- PostgreSQL pool maximum and query timeouts.
- BullMQ worker concurrency and backlog alert threshold.
- 256 KiB trace capture cap by default; a cap on trace capture is not a cap on provider response parsing.
- Graceful shutdown drain deadline.

Initial limits are configuration values to be benchmarked on the target machine. A single tenant must not be able to consume all sockets, memory, database connections, or worker slots.

---

# 11. PostgreSQL data model

Use explicit SQL migrations for RLS, roles, functions, composite FKs, generated columns, triggers, and indexes. Drizzle may describe ordinary schema/types, but it is not the authority for security policies or critical SQL semantics.

All tenant-owned tables use UUID primary keys and composite tenant constraints. `gateway_control` is global operational state and is not tenant-owned.

## 11.1 `organizations`

Required fields:

- `id UUID PRIMARY KEY`.
- `name TEXT NOT NULL`.
- `monthly_budget_microdollars BIGINT NOT NULL CHECK (monthly_budget_microdollars BETWEEN 0 AND 1000000000000000)`.
- `kek_version INT NOT NULL`.
- `wrapped_dek BYTEA NOT NULL`, `dek_iv BYTEA NOT NULL`, `dek_auth_tag BYTEA NOT NULL`.
- `created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()`.

There is no `fail_open` policy field in v1. Budget-sensitive requests fail closed whenever Redis is unavailable or its accounting generation is untrusted.

## 11.2 `gateway_control`

Global singleton table, outside tenant RLS:

- `id SMALLINT PRIMARY KEY CHECK (id = 1)`.
- `gateway_epoch BIGINT NOT NULL`.
- `updated_at TIMESTAMPTZ NOT NULL`.

Only `gateway_startup` may update the epoch. `gateway_app` may SELECT the epoch. Admission/startup serialization uses transaction advisory locks, not `SELECT ... FOR SHARE` on a SELECT-only role.

## 11.3 `users`

- `id UUID PRIMARY KEY`.
- `org_id UUID NOT NULL REFERENCES organizations(id)`.
- `email_normalized TEXT NOT NULL UNIQUE` (global uniqueness for the v1 login model).
- `password_hash TEXT NOT NULL`.
- `role TEXT NOT NULL CHECK (role IN ('admin','member'))`.
- `created_at TIMESTAMPTZ NOT NULL`.
- `UNIQUE (id, org_id)` when referenced by tenant-aware FKs.

## 11.4 `web_sessions`

Server-side revocable sessions:

- `session_id_hash BYTEA PRIMARY KEY` (hash of a 256-bit random session secret; never store the raw cookie value).
- `user_id UUID NOT NULL`.
- `org_id UUID NOT NULL`.
- `csrf_token_hash BYTEA NOT NULL`.
- `created_at`, `last_seen_at`, `idle_expires_at`, `absolute_expires_at`, `revoked_at`.
- Composite FK `(user_id, org_id)` to users.

Logout, password change, account disable, and privilege changes revoke the applicable sessions. The implementation may use a small session table rather than introducing another session infrastructure service.

## 11.5 `provider_keys`

- `id UUID PRIMARY KEY`.
- `org_id UUID NOT NULL`.
- `provider TEXT NOT NULL` with an allowlisted provider enum/check.
- `label`, `key_hint` (last four characters only).
- `ciphertext BYTEA`, `iv BYTEA`, `auth_tag BYTEA`.
- `is_active BOOLEAN NOT NULL`.
- `created_at TIMESTAMPTZ NOT NULL`.
- `UNIQUE (id, org_id)`.
- Composite FK `(org_id)` to organizations.

Plaintext provider credentials are never returned after creation.

## 11.6 `virtual_keys`

- `id UUID PRIMARY KEY`.
- `org_id UUID NOT NULL`.
- `name`, `key_prefix`, `key_hash BYTEA UNIQUE`.
- `allowed_models TEXT[] NOT NULL` (empty array means deny all, never allow all).
- `rpm_limit`, `tpm_limit`, and concurrent-stream limit with positive-value checks.
- `exact_cache_enabled BOOLEAN NOT NULL DEFAULT FALSE`.
- `semantic_cache_enabled BOOLEAN NOT NULL DEFAULT FALSE`.
- `pii_redaction_enabled BOOLEAN NOT NULL DEFAULT FALSE`.
- `store_payloads BOOLEAN NOT NULL DEFAULT TRUE`.
- `revoked_at TIMESTAMPTZ`, `created_at TIMESTAMPTZ`.
- `UNIQUE (id, org_id)`.

No unused per-key budget column exists in v1. Organization budgets are enforced at organization level; virtual keys constrain model access and rate/concurrency/privacy policies.

## 11.7 `gateway_requests`

One row per accepted logical request, including cache hits:

- `request_id UUID PRIMARY KEY`.
- `org_id UUID NOT NULL`.
- `virtual_key_id UUID NOT NULL`.
- `gateway_instance_id UUID NOT NULL`.
- `gateway_epoch BIGINT NOT NULL`.
- `requested_model TEXT NOT NULL`.
- `billing_period TEXT NOT NULL` (`YYYY-MM`, UTC, immutable at admission).
- `status` in `in_progress`, `completed`, `failed`, `client_aborted`, `interrupted`.
- `final_provider`, `final_model` nullable.
- `attempt_count INT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0)`.
- `cache_status` in `miss`, `exact_hit`, `semantic_hit`, `bypass`.
- `http_status`, `ttft_ms`, `total_latency_ms`, `pii_redacted_count`, `error_code`.
- `admitted_at`, `deadline_at`, `created_at`, `finalized_at`.
- Composite FK `(virtual_key_id, org_id) REFERENCES virtual_keys(id, org_id) ON DELETE RESTRICT`.
- Index `(org_id, created_at DESC, request_id DESC)` for keyset pagination.

`request_id` is the primary key and pagination cursor. Do not define an index on a nonexistent `id` column.

## 11.8 `provider_attempts`

One row per upstream provider call:

- `attempt_id UUID PRIMARY KEY`.
- `request_id UUID NOT NULL`, `org_id UUID NOT NULL`, `virtual_key_id UUID NOT NULL`.
- `attempt_number INT NOT NULL CHECK (attempt_number >= 1)`.
- `gateway_instance_id UUID NOT NULL`, `gateway_epoch BIGINT NOT NULL`.
- `billing_period TEXT NOT NULL` inherited from the logical request and immutable.
- `provider`, `model`, `sanitized_fields TEXT[]`.
- `status` in `reserved`, `settled`, `interrupted`.
- `outcome` in `completed`, `client_aborted`, `pre_token_timeout`, `pre_token_error`, `mid_stream_error`, `interrupted`.
- `tokens_in`, `tokens_out`, `duration_ms`, `http_status` with nonnegative checks.
- `estimated_cost_microdollars BIGINT NOT NULL CHECK (>= 0)`.
- `actual_cost_microdollars BIGINT NULL CHECK (>= 0)`.
- `effective_cost_microdollars BIGINT GENERATED ALWAYS AS (COALESCE(actual_cost_microdollars, estimated_cost_microdollars)) STORED`.
- `cost_status` in `estimated`, `confirmed`.
- `admitted_at`, `hard_deadline_at`, `settled_at`, `created_at`.
- `UNIQUE (request_id, attempt_number)`.
- `UNIQUE (attempt_id, org_id)` for adjustment FKs.
- Composite FK `(request_id, org_id) REFERENCES gateway_requests(request_id, org_id) ON DELETE RESTRICT`.
- Composite FK `(virtual_key_id, org_id) REFERENCES virtual_keys(id, org_id) ON DELETE RESTRICT`.
- Index `(org_id, billing_period, created_at DESC)` and an index appropriate for stale `reserved` attempts, for example partial `(hard_deadline_at) WHERE status='reserved'`.

Base cost fields and billing period are immutable after terminal settlement. Enforce this through restricted column grants plus a database trigger or equivalent database-level invariant. Do not allow ordinary application routes to delete financial rows.

## 11.9 `provider_cost_adjustments`

Append-only correction history:

- `adjustment_id UUID PRIMARY KEY`.
- `attempt_id UUID NOT NULL`, `org_id UUID NOT NULL`.
- `previous_cost_microdollars BIGINT NOT NULL CHECK (>= 0)`.
- `corrected_cost_microdollars BIGINT NOT NULL CHECK (>= 0)`.
- `delta_microdollars BIGINT NOT NULL CHECK (delta_microdollars = corrected_cost_microdollars - previous_cost_microdollars)`.
- `source` in `provider_usage`, `provider_invoice`, `manual_review`.
- `source_reference TEXT` nullable; add a suitable uniqueness constraint when the provider supplies a stable invoice/usage identifier.
- `created_at TIMESTAMPTZ NOT NULL`.
- Composite FK `(attempt_id, org_id) REFERENCES provider_attempts(attempt_id, org_id) ON DELETE RESTRICT`.

Revoke DELETE and unauthorized UPDATE privileges. The same adjustment ID with different values is an invariant violation. The adjustment transaction serializes per attempt/organization and verifies the previous canonical amount.

## 11.10 `trace_payloads`

- `request_id UUID PRIMARY KEY`.
- `org_id UUID NOT NULL`.
- `request_body JSONB`, `response_text TEXT`, `truncated BOOLEAN NOT NULL DEFAULT FALSE`.
- `expires_at TIMESTAMPTZ NOT NULL`.
- Composite FK `(request_id, org_id) REFERENCES gateway_requests(request_id, org_id) ON DELETE CASCADE`.
- Seven-day default live retention; `store_payloads=false` prevents raw payload persistence and cache storage.

Trace payloads are not the financial source of truth. Metadata and financial attempt rows are retained separately.

## 11.11 Optional `semantic_cache` (Phase 5)

- `id UUID PRIMARY KEY`.
- `org_id UUID NOT NULL`.
- `context_hash TEXT NOT NULL`.
- `prompt_text TEXT NOT NULL` (redacted, only when cache policy permits).
- `embedding vector(384) NOT NULL`.
- `canonical_response JSONB NOT NULL`.
- `expires_at`, `created_at`.
- RLS required.

---

# 12. PostgreSQL roles, RLS, and authentication bootstrap

## 12.1 Roles and ownership

| Role | Login? | BYPASSRLS? | Responsibility |
|---|---:|---:|---|
| `gateway_owner` | No | No | Owns tenant tables; never used by runtime |
| `gateway_migrator` | Deployment-only | No | Applies migrations and can `SET ROLE gateway_owner`; no runtime access |
| `gateway_startup` | Yes | No | Dedicated singleton lock connection; updates `gateway_control.gateway_epoch` only |
| `gateway_app` | Yes | No | Fastify Gateway runtime; tenant-scoped queries and provider-secret access |
| `gateway_worker` | Yes | No | Background jobs; tenant-scoped attempt/trace work; no KEK and no provider-key decryption privileges |
| `gateway_auth_executor` | No | Yes | Owns only restricted authentication/bootstrap functions; not a table owner |
| `gateway_ops_executor` | No | Yes | Owns only restricted maintenance enumeration function(s); not a table owner |

No runtime role is a superuser, `BYPASSRLS`, or owner of tenant tables. Do not grant membership in either executor role to runtime principals. The executor roles are privileged because they bypass RLS; they must have only the narrow table/column privileges required by their fixed-purpose functions.

Workers do not receive `MASTER_KEK_*` environment variables and do not need access to `organizations.wrapped_dek` or `provider_keys.ciphertext`.

## 12.2 Tenant context

Every tenant-scoped query runs in an explicit transaction with transaction-local context:

```sql
SELECT pg_catalog.set_config('app.current_org_id', $1, true);
```

Use one `withTenant(orgId, callback)` helper. It must open the transaction, set context, run the callback, commit/rollback, and release the pooled connection. Do not set tenant context at session scope.

RLS expression should tolerate absent/empty settings safely, for example:

```sql
org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
```

No tenant context means no tenant rows are visible and tenant writes fail.

## 12.3 RLS policies

Enable and force RLS with both `USING` and `WITH CHECK` on:

- `organizations` (using `id = current_org_id`).
- `users`.
- `web_sessions`.
- `provider_keys`.
- `virtual_keys`.
- `gateway_requests`.
- `provider_attempts`.
- `provider_cost_adjustments`.
- `trace_payloads`.
- `semantic_cache` when created.

`gateway_control` is the only global control table and is not tenant-owned. Do not accidentally add tenant records to it.

Test SELECT, INSERT, UPDATE, DELETE, FK, and pooled-connection behavior under every runtime role with no context, Org A context, and Org B context.

## 12.4 SECURITY DEFINER functions

Pre-tenant authentication functions:

- `app_private.lookup_virtual_key_by_hash(p_key_hash)`.
- `app_private.lookup_user_for_login(p_email_normalized)`.
- `app_private.create_organization_with_admin(...)`.

Maintenance function:

- `app_private.list_active_org_ids(p_after_id, p_limit)` returning only paginated organization UUIDs.

Requirements:

1. Authentication functions are owned by `gateway_auth_executor`; the maintenance function is owned by `gateway_ops_executor`.
2. Executor roles are `NOLOGIN BYPASSRLS`, not table owners, and have minimum required column/table privileges.
3. `REVOKE ALL ... FROM PUBLIC` and grant EXECUTE only to the required runtime role(s), in the same migration transaction as function creation.
4. Use a protected schema such as `app_private`; revoke `CREATE` on it from `PUBLIC` and runtime roles.
5. Use a fixed search path with trusted schemas and `pg_temp` last, for example `pg_catalog, app_private, pg_temp`; schema-qualify application tables in function bodies.
6. No untrusted role may create objects in any schema on the function search path.
7. Validate argument length/format and avoid dynamic SQL.
8. Return only the fields the caller needs. The key lookup must not return provider credentials or unrelated tenant data.
9. The maintenance enumerator returns IDs only. All subsequent maintenance queries use `withTenant(orgId)` and the per-org advisory lock.
10. Do not grant cross-tenant SELECT to `gateway_app` or `gateway_worker` as a shortcut.

## 12.5 PostgreSQL privileges and epoch locking

- `gateway_app` has SELECT-only privilege on `gateway_control`.
- It does not use `SELECT ... FOR SHARE` on `gateway_control`; PostgreSQL requires UPDATE privilege on at least one table column for row-locking clauses such as `FOR SHARE`.
- Admission/startup serialization uses the shared/exclusive transaction advisory lock protocol in Section 8.1.
- `gateway_startup` can update only the epoch row/column and only while holding the singleton session lock and exclusive transaction advisory lock.
- No runtime role can alter the epoch.

## 12.6 RLS limitation

A custom tenant GUC is application context, not a cryptographic tenant identity. A process with arbitrary SQL execution under `gateway_app` can set `app.current_org_id` to another tenant. RLS protects against missing tenant predicates and many accidental application bugs; it does not protect against a compromised Gateway process or arbitrary SQL execution with the runtime credential. State this honestly in `docs/SECURITY.md`.

---

# 13. Authentication, authorization, and sessions

## 13.1 Virtual API keys

- Generate 32 random bytes using a cryptographically secure RNG (256 bits of entropy).
- Encode as a prefix plus base64url secret, for example `gw_live_<public-prefix>_<secret>`.
- Display raw value once at creation; never store it in plaintext.
- Store SHA-256 hash of the high-entropy secret and a non-secret public prefix. A separate pepper is not required for a uniformly random 256-bit key in v1; avoid adding pepper-rotation complexity without a concrete requirement.
- Lookup uses a parameterized query through the restricted function.
- Never log the Authorization header or raw key.
- No Redis authorization cache in v1. PostgreSQL is already on the admission path and direct lookup simplifies revocation semantics.
- Re-check that the key is active inside the durable attempt-admission transaction. Lock the virtual-key row so revocation and admission serialize.
- Revocation blocks new attempt admissions after the revocation transaction commits. Already-admitted attempts may complete within their bounded deadline; document and test this.
- Invalid/revoked keys return the same external authentication error.
- Add per-IP abuse controls before key lookup to limit random-key guessing and PostgreSQL load.

## 13.2 Browser sessions

Use opaque, random, server-side sessions rather than stateless JWT-only sessions in v1.

- Generate a 256-bit random session secret.
- Store only a SHA-256 hash/verifier in `web_sessions`.
- Cookie: `__Host-session`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain` attribute. Local-development behavior must be explicit and must not silently weaken production settings.
- Rotate session ID after login and privilege changes.
- Revoke on logout, password change, account disable, and security-sensitive role change.
- Enforce idle and absolute expiration.
- Never store session tokens in localStorage/sessionStorage.

## 13.3 CSRF and browser topology

Use a server-side synchronizer token bound to the session:

- Generate a high-entropy CSRF token per session.
- Store its hash in `web_sessions`.
- Expose the token only through an authenticated same-origin endpoint for the frontend to keep in memory.
- Require `X-CSRF-Token` on every state-changing control-plane request.
- Compare in constant time.
- Validate exact `Origin` on browser-authenticated mutations; reject missing/unexpected Origin rather than falling back to permissive wildcard behavior.
- Keep the Next.js and Fastify browser-facing API on a same-origin BFF/proxy path for v1. Any cross-origin deployment requires an explicit exact-origin CORS/cookie design and separate tests.
- `SameSite` is defense in depth, not the sole CSRF control.

## 13.4 Password handling

- Argon2id with at least the OWASP recommended baseline (`m=19456 KiB`, `t=2`, `p=1`), benchmarked on the target environment.
- Maximum password length by bytes (initial cap 128 bytes) before hashing; do not silently truncate.
- Rate-limit by IP and account identifier before expensive hashing.
- Bound concurrent Argon2 operations with a small semaphore to protect memory.
- Use generic login failure responses and perform a dummy verification for unknown users to reduce account enumeration timing differences.
- Never log passwords or password hashes.

## 13.5 RBAC matrix

Default deny. Every control-plane route must declare its principal and minimum role. The initial matrix is intentionally small:

| Operation | Anonymous | Member | Admin | Virtual API key |
|---|---:|---:|---:|---:|
| Register/login/logout/session | Allowed as appropriate | Session | Session | Denied |
| View own profile | Denied | Allowed | Allowed | Denied |
| View organization overview/usage | Denied | Read | Read | Denied |
| View trace metadata | Denied | Read within org | Read within org | Denied |
| View raw redacted trace payload | Denied | Denied by default | Allowed within org | Denied |
| Create/revoke/rotate virtual keys | Denied | Denied | Allowed | Denied |
| Change organization budget/settings | Denied | Denied | Allowed | Denied |
| Create/update/delete provider credentials | Denied | Denied | Allowed | Denied |
| Manage users/roles | Denied | Denied | Allowed | Denied |
| Use `/v1/chat/completions` | Denied | Denied | Denied | Allowed if key policy permits |

The control plane rejects virtual API keys. The data plane rejects browser session cookies. These principal types are not interchangeable. The Streaming Playground must not place a long-lived virtual key in browser JavaScript; use a short-lived server-side operation scoped to the logged-in user and organization.

Implement a route-registration helper that requires explicit principal/role metadata. New routes without an authorization declaration fail a startup assertion or type-level check.

---

# 14. Provider credential security and privacy

## 14.1 Envelope encryption

- AES-256-GCM.
- Random 256-bit DEK per organization.
- Versioned environment-backed KEKs (`MASTER_KEK_V1`, `MASTER_KEK_V2`, `ACTIVE_KEK_VERSION`).
- Fresh 96-bit IV for each encryption operation.
- Store authentication tag separately or in a documented ciphertext format.
- DEK-wrap AAD: `dek:<org_id>:v<kek_version>`.
- Provider-key AAD: `pk:<org_id>:<provider_key_id>:<provider>`.
- Plaintext provider keys and DEKs exist only in Gateway memory for the minimum time needed. Do not put plaintext into Redis, BullMQ, logs, traces, or browser responses.
- This is application-level encryption with environment-backed KEKs, not a hardware KMS.

## 14.2 KEK rotation

KEK rotation is not a blocker for the first streaming prototype, but the schema and AAD must be versioned from day one.

When the rotation command is implemented:

- It re-wraps the existing DEK only; DEK rotation is a separate operation requiring provider-key re-encryption.
- Re-wrap organization rows in small transactions with a `WHERE kek_version = old_version` compare-and-swap condition.
- Record progress and make retries idempotent.
- Verify all live rows use the active version before deprecating an old KEK.
- Retain old KEKs offline for at least the full database backup retention window. A restored pre-rotation backup must remain decryptable.
- Never delete old KEKs just because live rows have been rotated.
- Test crash/restart at each batch boundary and restoration of pre/post-rotation backups.

The `rotate-kek` CLI can be delivered after the core Gateway, not in the first scaffold.

## 14.3 Logging and trace privacy

Pino redaction must cover:

- Authorization and Cookie headers.
- Session and CSRF tokens.
- Virtual API keys.
- Provider API keys and decrypted secrets.
- KEKs and DEKs.
- Passwords/password hashes.
- Raw prompts/responses by default.

Zod validation errors must not serialize raw request values that may contain PII or secrets. Error responses must never include upstream secret-bearing headers or unfiltered provider response bodies.

## 14.4 PII redaction

- Redact supported email, phone, payment-card, and recognizable API-key patterns before cache lookup, provider dispatch, and trace persistence.
- Document false positives and false negatives. Regex is best-effort filtering, not a privacy guarantee.
- `store_payloads=false` means raw prompt/response payloads are not stored in traces or caches.
- Keep trace metadata separate from raw payloads.
- Test PII fixtures for precision and recall; do not claim complete PII removal.

---

# 15. Rate limits, token estimation, and pricing

## 15.1 Rate-limiter algorithm

Use explicit token-bucket semantics for RPM and TPM. Implement them in Redis Lua using Redis `TIME` and integer token units.

For each virtual key (and optionally organization):

- Define capacity, refill rate, and burst behavior.
- Atomically refill based on elapsed server time, clamp to capacity, and consume the requested amount.
- Keep keys bounded with TTL after inactivity.
- Return a precise retry-after estimate when insufficient tokens remain.

For TPM:

- Reserve estimated input tokens plus declared output reservation before provider dispatch.
- When authoritative usage is available, refund unused reserved output tokens through an idempotent attempt-scoped script.
- If usage is unknown, keep the conservative charge until the limiter window/refill naturally restores capacity.
- Do not let duplicate completion/refund calls refund twice.

Do not use an unbounded per-request ZSET log for high-volume token accounting.

## 15.2 Token estimation and output reservation

- Pin a tested `gpt-tokenizer` version for supported OpenAI-family encodings.
- Do not claim that OpenAI tokenizer encodings are native Gemini or Groq tokenizers.
- For providers without an available local tokenizer, use a documented conservative approximation and safety multiplier.
- Use model-specific capability entries: output-limit parameter name, maximum output, reasoning-token billing behavior/allowance, tokenizer family, streaming usage support, tools support, and price entry.
- A reservation is based on estimated input cost plus maximum declared output/reasoning allowance cost.
- Reject unsupported or unpriced models before dispatch in budget-enforced mode.
- Default output reservation may start at 1,024 tokens with a configurable hard maximum (for example 4,096); actual values must match provider/model limits and be tested.
- Record estimated and actual input/output token counts separately.

## 15.3 Pricing table

Store a versioned provider/model pricing table in `packages/shared/src/pricing.ts` with:

- Provider and model ID.
- Input/output microdollars per million tokens.
- Currency and effective date.
- Pricing source URL and `last_verified` date.
- Output cap/reasoning capability metadata.
- Fallback model mapping.

Stale or missing prices must not silently permit a budget-enforced dispatch. Re-verify live model names, parameters, and prices when the adapter is implemented and when the pricing table is updated.

---

# 16. Caching (deferred; opt-in only)

Caching stores prompt-derived and response content. It is payload storage and must follow the same privacy and retention policy as trace payloads.

## 16.1 Exact cache prerequisites

Do not implement exact cache until Phases 1–4 are passing. If enabled later:

- Disabled by default.
- Bypass entirely when `store_payloads=false`.
- Cache only complete successful responses; never partial, failed, truncated, tool-result, or unsupported multimodal responses.
- Bypass `Cache-Control: no-store`.
- Default to deterministic requests only (`temperature=0` or an explicitly supported deterministic seed policy).
- Key includes org ID, resolved provider/model, model/capability version, redaction policy, canonical request semantics, messages/system content, tools, response format, output cap, temperature/seed, and cache schema version.
- Compute an HMAC of canonical pre-redaction request content for cache identity; do not store the original pre-redaction prompt. This avoids collisions created by lossy redaction and makes low-entropy prompt guessing harder than a plain hash.
- Cache TTL cannot exceed raw-payload retention (default seven days).
- Retention pruner deletes exact-cache entries with the same policy as trace payloads.
- Streaming responses are reconstructed from canonical completion JSON; non-streaming requests receive JSON.

## 16.2 Semantic cache (Phase 5 only)

If implemented after the core Gateway is stable:

- Disabled by default per key.
- Full context hash includes provider/model, system prompt, temperature, output limit, response format, tools, and prior-turn identity.
- Bypass multi-turn unless prior context is identical; bypass tool results and multimodal input.
- ONNX embeddings run in a bounded worker_threads pool, never on the Fastify main event loop.
- pgvector 0.8+ iterative scans are evaluated against exact cosine search for small tenant/context buckets.
- Shared HNSW index filters do not imply physical per-tenant index isolation; test recall under tenant skew.
- Numeric/identifier/negation guards and a 500–1,000 pair labeled calibration dataset, including hard negatives.
- Publish precision, recall, false-positive rate, and end-to-end hit latency. Keep disabled if false-positive risk is not acceptable.

---

# 17. Observability Control Plane

## 17.1 Core views

1. **Overview:** monthly spend, budget remaining, request volume, failure rate, provider distribution, p50/p95 TTFT.
2. **Virtual Keys:** create, display once, revoke, rotate, allowed models, RPM/TPM and concurrency settings.
3. **Provider Vault:** create/update/remove BYOK credentials, masked key hints, and safe connectivity status. Never return plaintext after creation.
4. **Trace Explorer:** keyset-paginated logical requests with time/status/model/provider/key/cache filters.
5. **Attempt Detail:** all provider attempts for one logical request, including fallback path, outcome, usage, estimated/confirmed/adjusted cost, and sanitized parameter list.
6. **Streaming Playground:** controlled live request, visible token stream, TTFT, latency, provider attempt list, and usage. It must not expose long-lived keys to browser JavaScript.

## 17.2 Pagination

Use keyset pagination on `(created_at DESC, request_id DESC)` for `gateway_requests`. Every query is tenant-scoped and relies on RLS as defense in depth. Avoid large OFFSET pagination.

## 17.3 Payload retention

- Raw trace payload default retention: seven days.
- Metadata/financial attempt records have a separate longer retention policy.
- `store_payloads=false` bypasses raw payload storage and all caches.
- Pruning uses the restricted maintenance enumerator, then `withTenant(orgId)` and bounded batches.
- Payload omitted/truncated status is visible in the UI.
- Database backups may retain deleted payloads longer than live-table TTL; document backup retention honestly.

---

# 18. Deterministic mock upstream

The mock provider is essential to testing, not a decorative demo.

## 18.1 Configurable behavior

- Configurable time-to-first-token.
- Configurable token/inter-chunk delay.
- Configurable output length and usage values.
- OpenAI-compatible SSE and non-streaming JSON responses.
- 400/401/403/422 caller errors.
- 429 with `Retry-After`.
- 500/502/503/504 failures.
- Connection refusal/reset.
- TTFT hang.
- Mid-stream drop.
- Client-abort observation endpoint.
- Usage-only final chunk.
- Malformed SSE and fragmented UTF-8 test cases.
- Oversized line/event and non-SSE body tests.
- Provider-specific capability/usage fixtures.

## 18.2 Determinism

- Test fixtures specify the exact response and delays.
- Fault injection is controllable by test configuration, not arbitrary public endpoints.
- No test relies on real provider availability or paid tokens.
- Mock endpoints and control routes refuse to register in production configuration.
- Mock service is not exposed publicly in a production profile.

---

# 19. Operational configuration and Docker Compose

## 19.1 Redis

- Enable AOF with `appendfsync everysec` for local deployment.
- Set `maxmemory` based on tested peak usage and `maxmemory-policy noeviction`.
- Configure ACL/password authentication and bind Redis only to the private Compose network or loopback.
- Runtime ACLs deny destructive/admin commands (`FLUSHALL`, `FLUSHDB`, `CONFIG`, `DEBUG`, `SHUTDOWN`, `REPLICAOF`, unrestricted `KEYS`, etc.).
- Verify `noeviction` and required ACL behavior at startup; fail closed if financial-state configuration is unsafe.
- Monitor memory headroom and OOM errors.

AOF `everysec` can lose approximately one second of recent writes in a disaster. That is a persistence window, not a guaranteed one-second monetary-loss bound. The financial impact depends on active reservations, provider usage, and whether the Gateway/Redis failure is detected and recovered safely.

## 19.2 PostgreSQL

- Separate migration, startup, app, worker, auth-executor, and ops-executor credentials.
- Use persistent local volumes.
- Health checks must verify database readiness, not only process liveness.
- Apply migrations before runtime admission.
- Test migrations from an empty database and from the prior schema version.
- Do not expose the database port publicly; local development binding should be loopback-only.

## 19.3 Application configuration

Use one Zod-validated configuration module. Fail fast on missing/invalid security-sensitive settings.

Production assertions:

- Mock provider disabled.
- Demo seeding disabled.
- TLS verification enabled.
- Redis auth/ACL enabled and `noeviction` verified.
- No `fail_open` mode exists.
- Cookies secure and correct host scope.
- No default demo credentials.
- Provider origins fixed/allowlisted.
- No raw secret in logs.

## 19.4 Worker separation

Use a separate worker process/container from the HTTP Gateway, built from the same monorepo/image if convenient. The worker has its own DB role, Redis ACL, bounded concurrency, and no KEKs/provider-secret decryption privileges. It does not acquire the Gateway singleton lock or dispatch providers.

## 19.5 Graceful shutdown

On SIGTERM:

1. Stop accepting new requests.
2. Stop new provider-attempt admission.
3. Allow active streams a bounded drain period.
4. Abort remaining upstream requests and finalize or leave durable attempts for conservative recovery.
5. Complete/rollback active DB transactions and release session advisory locks.
6. Stop workers after current jobs reach a safe boundary.
7. Exit before container stop grace expires.

On SIGKILL, process crash, or machine loss, recovery relies on durable PostgreSQL rows and conservative holds.

---

# 20. Repository layout and code hygiene

```text
ai-gateway/
├── apps/
│   ├── gateway/
│   │   ├── src/
│   │   │   ├── config/
│   │   │   ├── auth/
│   │   │   ├── db/                 # SQL migrations, withTenant, repositories
│   │   │   ├── crypto/             # AES-GCM, KEK provider
│   │   │   ├── budget/             # BudgetEngine and Redis state machine
│   │   │   ├── redis/              # Redis client/ACL adapter
│   │   │   ├── lua/                # reserve, renew, expire, complete, ack, hydrate
│   │   │   ├── providers/          # OpenAI, later Gemini/Groq, mock client contract
│   │   │   ├── proxy/              # SSE parser, writer, abort and size limits
│   │   │   ├── resilience/         # Circuit breaker and failover policy
│   │   │   ├── privacy/            # PII redaction and payload policy
│   │   │   ├── services/           # Use cases / orchestration
│   │   │   ├── workers/            # persistence, sweeper, reconciler, pruner
│   │   │   ├── routes/             # thin Fastify routes
│   │   │   └── main.ts / worker-main.ts
│   │   └── test/                   # unit, integration, security, chaos
│   ├── web/                        # Next.js Control Plane
│   └── mock-upstream/              # deterministic local SSE/JSON provider
├── packages/
│   └── shared/                     # Zod schemas, errors, money, pricing/capabilities
├── bench/                          # streaming and concurrency harness
├── docker-compose.yml
├── pnpm-workspace.yaml
├── pnpm-lock.yaml
├── README.md
└── docs/
    ├── ARCHITECTURE.md
    ├── SECURITY.md
    └── BENCHMARKS.md
```

## 20.1 Code-quality standards

- TypeScript `strict: true`; enable `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes` where compatible.
- Use `unknown` at untrusted boundaries and narrow with Zod/type guards. Avoid `any`.
- Use discriminated unions for Redis/BudgetEngine results so every caller handles `FENCED`, `NEEDS_HYDRATION`, `RECOVERY_REQUIRED`, `DUPLICATE`, and `REJECTED_BUDGET`.
- Share validated state enums; do not scatter magic strings.
- Define a structured `GatewayError` taxonomy with code, HTTP status, retryability, breaker eligibility, and billability.
- Never serialize raw database/provider errors to clients.
- Each use case owns a clear PostgreSQL transaction boundary.
- Do not hold a PostgreSQL transaction open across a provider stream or long queue wait.
- All money-mutating Redis calls go through `budget/`.
- Each provider attempt has one finalization owner.
- Split modules by responsibility and dependency boundary, not arbitrary line count. No module should own more than one of HTTP transport, SQL transaction orchestration, Redis accounting mutation, or provider I/O.
- Add CI for format, lint, typecheck, tests, build, migration checks, dependency audit, and secret scanning.

---

# 21. Required verification suite

Every guarantee in the public README must map to a runnable test or benchmark command. Tests must use real PostgreSQL and Redis for locking, RLS, Lua, and queue behavior. Mocked unit tests alone are insufficient for distributed invariants.

## 21.1 Admission and state-machine tests

| Test | Setup / injected condition | Expected invariant |
|---|---|---|
| Durable admission before dispatch | Force PG insert failure | No provider request is sent |
| Duplicate reservation | Call `RESERVE` twice with same attempt ID | One reservation only |
| Duplicate completion | Call `COMPLETE_STREAM` twice | No duplicate pending cost |
| Completion after ACK | Call `COMPLETE_STREAM` after `ACKED` | Strict no-op; no resurrection |
| ACK on active reservation | PG recovery marks attempt terminal while Redis is `RESERVED_ACTIVE` | ACK removes active amount before adding settled spend |
| ACK on expired hold | Attempt terminal while Redis is `LEASE_EXPIRED_HOLD` | ACK removes hold once and settles once |
| ACK replay | Deliver settlement job repeatedly | Zero duplicate PostgreSQL rows and zero Redis drift |
| Same-epoch sweeper race | Pause after Redis reserve before PG insert; run sweeper | Current-epoch reservation is not cancelled |
| Old-epoch orphan | Advance epoch, confirm old process stopped, query PG no-row | Safe cancellation only after all conditions pass |
| Ambiguous PG commit | Simulate connection loss during commit | Reservation remains held until DB resolution |
| Lease expiry | Stop renewal | Amount moves to expired hold; never silently freed |
| Lease expiry vs completion | Barrier both operations | Exactly one valid terminal transition |

## 21.2 Recovery and reconciliation tests

| Test | Setup / injected condition | Expected invariant |
|---|---|---|
| New organization | Create org after Gateway startup; first request | Lazy organization-period hydration succeeds |
| UTC month rollover | Fake clock across month boundary | First request for new period hydrates and admits |
| Midnight-crossing request | Admit before UTC month boundary, settle after | Attempt remains in admission-time billing period |
| Redis process restart | Restart Redis with prior AOF | New run ID closes gate and forces hydration |
| Redis FLUSHALL in isolated test | Remove all keys without changing process run ID | Missing global gate fails closed and recovery rebuilds |
| Redis memory pressure | Force OOM/noeviction write error | No new provider dispatch; gate/recovery path runs |
| Wrong Redis key type | Replace accounting key with wrong type | Script preflight catches before mutation or gate is closed and rebuilt |
| Script partial failure | Inject command error after planned writes | Application does not retry blindly; gate closes and PostgreSQL rebuild restores state |
| Hydration vs completion | Pause staged rebuild and complete a stream | Gateway Redis mutation is refused; PG settlement is durable; staged generation includes it |
| Hydration vs ACK | Pause rebuild and retry worker ACK | ACK is refused during recovery; PG is authoritative; new generation contains terminal row |
| Adjustment replay after restart | Apply adjustment, restart Redis, replay same adjustment | Rebuilt marker prevents duplicate delta |
| Late provider usage | Interrupted estimate then late actual usage | Append adjustment; do not mutate base cost |
| Reconciliation drift | Corrupt one derived counter in test | Gate closes and rebuild converges to PG canonical totals |

## 21.3 Security tests

- RLS SELECT/INSERT/UPDATE/DELETE for unset, empty, invalid, Org A, and Org B contexts.
- Cross-tenant composite FK insert fails.
- Runtime roles cannot alter schema or assume executor roles.
- `gateway_app` and `gateway_worker` cannot invoke maintenance/auth functions beyond their grants.
- Security-definer function cannot be shadowed by `pg_temp` objects.
- `PUBLIC` cannot execute restricted functions.
- Member cannot call admin routes.
- Virtual key cannot call control-plane routes; browser session cannot call data-plane routes.
- Logout/password change revokes sessions.
- Forged/missing CSRF token and wrong Origin return 403.
- Virtual key revocation races with admission; no attempt can be admitted after revocation wins the row-lock ordering.
- Virtual key invalid/revoked failures are externally indistinguishable.
- Provider keys, tokens, cookies, passwords, prompts and authorization headers are absent from logs.
- DEK ciphertext transplanted across orgs fails GCM authentication due to AAD.
- Old KEK restoration and rotation recovery runbook tests pass before a rotation tool is considered complete.
- Redis ACL cannot run `FLUSHALL`, `FLUSHDB`, `CONFIG`, `DEBUG`, or unrelated administrative commands.
- Production config rejects mock provider, test controls, and demo seeding.

## 21.4 Streaming and provider tests

- UTF-8 multibyte characters split across chunks.
- CRLF/LF/CR, BOM, comments, multiline data, blank event dispatch, EOF partial frame.
- Oversized line/event and excessive total response bytes.
- Non-streaming response body > cap.
- Upstream redirect is rejected.
- Provider response headers are allowlisted.
- Client Authorization/Cookie/Host headers are not forwarded upstream.
- Normal request completion does not trigger a false abort.
- Premature downstream response close aborts upstream.
- Fastify `reply.hijack()` produces no double-send/after-end error.
- Slow downstream readers keep RSS bounded.
- `stream:false` has the same attempt, timeout, size, and abort semantics.
- Primary pre-token failure aborts primary before fallback.
- Fallback receives its own attempt ID, budget reservation, model price, and capability validation.
- No failover after first downstream content token.

## 21.5 Resource and rate tests

- Per-IP limiter blocks unauthenticated random-key floods before PostgreSQL lookup.
- Per-key RPM and TPM token buckets are atomic under concurrent requests.
- TPM reservation/refund is idempotent and cannot refund twice.
- Per-org and global active-stream caps reject excess load before provider dispatch.
- Redis expiry reaper processes bounded batches; a large expired ZSET does not block `RESERVE` indefinitely.
- PostgreSQL pool and worker concurrency remain within configured limits.

## 21.6 Property/model-based testing

Use property-based or model-based tests for:

- Attempt state transitions.
- Budget conservation equation after every operation.
- Reservation + expiry + completion + ACK interleavings.
- Duplicate and reordered job deliveries.
- Reconciliation and cost-adjustment idempotency.
- Pagination cursors with equal timestamps.
- Tenant-isolation properties.

Use deterministic barriers/fault hooks rather than relying only on flaky sleep-based race tests. A test must be able to pause at a named point, inject the competing operation, and assert the result.

---

# 22. Benchmark strategy

Do not fabricate results. Publish exact commands, machine specs, Docker image versions, Node/PostgreSQL/Redis versions, dataset sizes, and raw output.

## 22.1 Streaming overhead

Measure direct mock upstream vs through Gateway:

- p50/p95/p99 TTFT.
- p50/p95/p99 total latency.
- Inter-token interval distribution.
- Gateway overhead.

Use a TypeScript streaming client that records the first content token; do not use a client that buffers the entire response before returning.

## 22.2 Budget concurrency

Run 10, 50, and 100 concurrent requests against a small organization budget. Verify the budget equation after each admission and at terminal settlement, not only at test completion. Record maximum observed estimate error/overspend and the exact failure model.

## 22.3 Memory and backpressure

Run bounded fast-upstream/slow-client scenarios. Record RSS, event-loop delay, active sockets, queue depth, and abort behavior. Use 500 concurrent streams only as a later stress scenario if the local machine can support it; do not make it a v1 delivery gate.

## 22.4 Database and Redis

Measure admission latency, lock contention, Lua p95/p99 duration, hydration time as number of attempts grows, and Redis memory per active/terminal attempt. Confirm that large lease cleanup is batched.

## 22.5 Reproducibility

Every benchmark includes:

- Commit hash.
- Runtime/container versions.
- CPU/RAM/OS.
- Test configuration.
- Warmup and duration.
- Concurrency model.
- Raw result file.
- Known limitations.

---

# 23. Implementation roadmap and gates

The project is designed for one developer. An aggressive prototype may take 6–8 weeks; a stronger implementation with security tests, failure injection, benchmarks, and polish may take longer. The schedule is not a promise. Do not sacrifice correctness to hit a date.

## Phase 1 — Foundation, auth, RLS, and mock provider

Deliver:

- pnpm monorepo and strict TypeScript configuration.
- Docker Compose with PostgreSQL, Redis, Gateway, worker, web, and mock upstream.
- Explicit SQL migrations, roles, RLS policies, composite FKs, auth functions, and maintenance enumeration function.
- Opaque server-side sessions, CSRF synchronizer token, admin/member RBAC, login rate limits.
- Virtual API key generation/lookup/revocation with no Redis auth cache.
- AES-GCM provider vault schema and AAD binding.
- Mock upstream with deterministic streaming and fault controls.
- Health/readiness and production configuration assertions.

Exit gate:

- Clean-clone `docker compose up` succeeds without paid provider keys.
- Demo account is local-only and non-default outside development.
- RLS and function privilege matrix passes.
- Session/CSRF/RBAC tests pass.
- No secrets appear in logs.

## Phase 2 — Request lifecycle and distributed budgeting

Deliver:

- Durable logical request and provider-attempt admission.
- PostgreSQL advisory-lock epoch fencing.
- Redis budget Lua scripts and full state matrix.
- Lease renewal/expiry/hold/cancel/complete/ACK.
- Integer microdollar accounting and bounds.
- Period anchoring and lazy hydration.
- BullMQ persistence worker, orphan recovery, stale attempt recovery, staged Redis generation rebuild.
- Cost adjustment table and idempotency.

Exit gate:

- All state-machine and budget-conservation tests pass.
- Same-epoch cancellation race is closed.
- New-organization and month-rollover hydration pass.
- Redis restart/flush/noeviction/partial-error tests pass.
- No unresolved accounting drift after recovery.

## Phase 3 — Streaming reliability and OpenAI adapter

Deliver:

- `reply.hijack()` SSE path and non-streaming path.
- Incremental parser and bounded frame/body sizes.
- Backpressure and abort handling.
- Primary provider adapter (OpenAI) behind capability registry.
- Pre-first-token circuit breaker/failover with one fallback attempt.
- PII redaction and payload privacy controls.

Exit gate:

- Streaming, disconnect, slow-reader, malformed-upstream, and provider contract tests pass.
- Primary attempt is aborted before fallback.
- No failover after first content token.
- Partial usage and estimated-cost paths are correct.

## Phase 4 — Control Plane, observability, additional providers, and benchmarks

Deliver:

- Dashboard, virtual-key manager, provider vault, usage/budget views, trace explorer, and streaming playground.
- Gemini and Groq adapters only after official capability/pricing verification and contract tests.
- RPM/TPM and concurrency limits.
- KEK rotation command if time remains.
- Reproducible TTFT, memory, and budget concurrency benchmarks.
- `README.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, and `docs/BENCHMARKS.md`.

Exit gate:

- Clean demo works using mock provider.
- Real provider integration is optional/configurable and secrets are not required for CI.
- Benchmark results are honest and reproducible.
- All core security and recovery tests pass.

## Phase 5 — Optional exact/semantic caching

Only after Phases 1–4 are stable. Keep caching disabled by default. Implement exact cache policy first; semantic cache only if there is time and meaningful precision evidence.

---

# 24. Operational failure policy

| Failure | Required behavior |
|---|---|
| PostgreSQL unavailable before admission | Reject; no provider dispatch |
| Redis unavailable | Fail closed for budget-sensitive requests; no provider dispatch |
| Redis run ID/generation changes | Close global gate, abort/drain streams, rebuild from PostgreSQL, then reopen |
| Redis write/script error with uncertain outcome | Stop affected admission, mark recovery required, rebuild; do not blind retry a money mutation |
| BullMQ unavailable before completion enqueue | Keep durable PostgreSQL attempt/reservation; allow sweeper/recovery to repair; no claim of completed settlement until durable row terminal |
| Worker delayed | Keep pending/expired holds counted; retry safely |
| Provider timeout before first token | Abort primary, record estimated cost unless known zero, then evaluate one fallback |
| Provider mid-stream failure | Emit SSE error, persist partial/estimated cost; no fallback |
| Client disconnect | Abort upstream, settle partial/estimated attempt exactly once |
| Gateway lock connection lost | Self-fence, reject all new requests, abort active streams, terminate process |
| Gateway crash with `reserved` attempts | Retain original estimates; after hard deadline + teardown grace, recover as interrupted unless better usage is available |
| Late usage after interruption | Append adjustment; do not mutate settled base fields |
| Redis memory limit reached (`noeviction`) | Writes fail; fail closed and recover; do not evict financial state |
| Upstream oversized/malformed response | Abort and finalize with bounded error; never allow unbounded parser memory |
| Unknown model/pricing | Reject before dispatch in budget-enforced mode |
| Security-definer/RLS function failure | Fail closed; never grant BYPASSRLS to application or worker to work around it |

---

# 25. Definition of done

The core project is complete when:

1. The local stack starts reliably from a clean clone.
2. A reviewer can use the mock provider without paid credentials.
3. A virtual-key-authenticated client can issue a streaming request through the Gateway.
4. Each provider attempt has durable pre-dispatch admission and one terminal financial record.
5. Budget reservations, expiry holds, completion, ACK, duplicate delivery, and recovery preserve the documented equation.
6. New tenants and UTC month rollover hydrate correctly.
7. Redis restart or uncertain accounting state fails closed and rebuilds from PostgreSQL.
8. RLS, composite FKs, role separation, sessions, CSRF, RBAC, and secret redaction tests pass.
9. Upstream redirects, oversized events, malformed SSE, slow clients, and client disconnects are handled safely.
10. Provider failover uses a separate attempt and does not occur after the first content token.
11. README claims map to runnable tests or measured benchmark outputs.
12. Limitations and remaining residual risks are documented honestly.

---

# 26. Security assumptions and residual risks

The final implementation must state these plainly:

1. A fully compromised Gateway process can access provider plaintext credentials during use and can set the tenant GUC. RLS is not a defense against arbitrary SQL execution under the runtime credential.
2. A compromised Redis credential can alter derived accounting state. Restrict network access and ACLs; rebuild from PostgreSQL when trust is lost.
3. Redis AOF `everysec` can lose recent writes after a disaster. PostgreSQL admission records and conservative recovery reduce risk, but provider-side usage can remain uncertain.
4. Aborting an HTTP request does not prove the provider stopped generating or billing.
5. Token estimates for non-native tokenizers and hidden reasoning usage are approximations.
6. Regex PII redaction is incomplete.
7. The single-active-Gateway process contract is not a multi-region or active-active fencing protocol.
8. A malicious administrator of an organization can exercise the authority intentionally granted to that organization's admin role; this project does not implement multi-party approval.
9. Backups may retain deleted raw trace data longer than live-table TTL. Backup encryption, access, and retention must be documented.
10. The mock provider validates Gateway behavior, not real provider uptime, pricing, or undocumented API compatibility.

---

# 27. Official documentation to verify during implementation

The design has been cross-checked against the following official references. Re-check version-specific details when implementing, especially Node/Fastify behavior and provider API capabilities.

## PostgreSQL

- SELECT locking clauses and required privileges: https://www.postgresql.org/docs/16/sql-select.html
- Privileges (`SELECT ... FOR SHARE` requires UPDATE privilege on at least one column): https://www.postgresql.org/docs/16/ddl-priv.html
- `SECURITY DEFINER` safety, `search_path`, `pg_temp`, and default PUBLIC execute grants: https://www.postgresql.org/docs/16/sql-createfunction.html
- Row-level security and FORCE RLS: https://www.postgresql.org/docs/16/ddl-rowsecurity.html
- Advisory locks: https://www.postgresql.org/docs/16/explicit-locking.html#ADVISORY-LOCKS

## Redis

- Lua scripting and execution semantics: https://redis.io/docs/latest/develop/programmability/eval-intro/
- `TIME`: https://redis.io/docs/latest/commands/time/
- `INCRBY` integer range: https://redis.io/docs/latest/commands/incrby/
- Memory optimization and `noeviction`: https://redis.io/docs/latest/management/optimization/memory-optimization/
- ACLs and dangerous command categories: https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/
- Persistence/AOF: https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/

## BullMQ

- Job IDs and duplicate-add behavior: https://docs.bullmq.io/guide/jobs/job-ids
- Retry behavior: https://docs.bullmq.io/guide/retrying-failing-jobs

## Node.js and Fastify

- Node HTTP request/response events: https://nodejs.org/api/http.html
- Fastify `reply.hijack()`: https://fastify.dev/docs/latest/Reference/Reply/
- Undici: https://undici.nodejs.org/

## OWASP

- Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Providers and caching

- OpenAI API documentation: https://platform.openai.com/docs/api-reference
- Gemini API documentation: https://ai.google.dev/gemini-api/docs
- Groq API documentation: https://console.groq.com/docs
- pgvector: https://github.com/pgvector/pgvector

---

# 28. Final implementation decision

This specification incorporates the independently substantiated findings from the three supplied audit reports while rejecting or deferring recommendations that are false positives, already covered, conditional, or disproportionate to a fresher portfolio project.

**Approved as the v1.2 implementation baseline, subject to the Definition of Done and test gates above.**

Do not run another broad architecture-review cycle. When implementation reveals a concrete contradiction or a reproducible failure, update the relevant section and test. Otherwise, proceed with the phases in order and spend the effort on working code, deterministic verification, documentation, and measured results.
