# Switchyard — Phase 2 Admission-Locking & Virtual-Key Revocation Recheck Contract

**Document Status:** NORMATIVE ARCHITECTURE HANDOFF  
**Authority:** Final Architecture & Engineering Plan v1.2 (§5.3, §6.1–6.3, §8.1–8.2, §11.6–11.8, §12.5, §13.1, §21)  
**Task Anchor:** SW-1.6.4 (Foundation Exit & Phase 2 Integration Seam)  
**Target Subphase:** Phase 2, Subphase 2.2 (Task SW-2.2.3)

---

## 1. Purpose & Threat Model

During Phase 1, pre-tenant virtual API key authentication (`VirtualKeyAuthenticatorService`, SW-1.6.2) verifies key syntax, computes the SHA-256 verifier, enforces per-IP Redis abuse limits, and executes the restricted hash lookup `app_private.lookup_virtual_key_by_hash(BYTEA)` to resolve tenant identity and initial key policy.

However, pre-tenant authentication resolves identity and policy only at request ingestion. It **does not** establish perpetual key validity:

> **Time-of-Check to Time-of-Use (TOCTOU) Window:** An administrative user or automated security control may logically revoke a virtual API key (`DELETE /api/keys/:id`, SW-1.6.3) *after* initial HTTP authentication succeeds but *before* the Gateway commits provider-attempt admission and dispatches upstream to an external model provider.

Without an admission-time database recheck, an in-flight request authenticated against a subsequently revoked credential could consume tenant budget and invoke external providers unauthorized.

**Phase 2 must eliminate this TOCTOU window by serializing provider-attempt admission against virtual-key revocation in PostgreSQL.**

---

## 2. Admission Authority & Inputs

The future provider-attempt admission service (Phase 2, Task SW-2.2.3) receives the following verified inputs:

1. **Trusted Authenticated Principal:** Immutable `VirtualKeyPrincipal` (`type: 'virtual_key'`) attached by the Gateway authorization boundary (`req.principal`).
2. **Verified Organization UUID:** `principal.orgId`, established by restricted pre-tenant lookup.
3. **Verified Virtual-Key UUID:** `principal.keyId`, established by restricted pre-tenant lookup.
4. **Logical Request Identity:** `requestId` (UUID v7 / PostgreSQL `public.gateway_requests.request_id` primary key).
5. **Validated Provider/Model Target:** Resolved against verified capability metadata (`SW-2.1.2`) and key allowlist (`principal.keyPolicy.allowedModels`, `SW-2.5.3`).
6. **Current Gateway Epoch:** Active gateway epoch integer held in trusted Gateway process memory and verified against `public.gateway_control.gateway_epoch` where `id = 1` (`0002-org-tables.sql`).
7. **Durable Billing Period:** UTC calendar month string (`YYYY-MM`) established at logical request admission (`SW-2.1.3`, `0007-financial-observability-tables.sql`, `0008-financial-integrity.sql`).
8. **Estimated Maximum Cost:** Microdollar ceiling for the pending provider attempt (`SW-2.1.1`).

### Explicit Security Prohibition
Under no circumstances may the admission engine accept a client-supplied `keyId`, `orgId`, or `gateway_epoch` as an authority substitute. The database check and epoch verification must bind strictly to verified Gateway process state and `req.principal`.

---

## 3. Mandatory Provider-Attempt Admission Sequence (Architecture §6.3)

Every upstream provider attempt dispatched in Phase 2 must adhere strictly to the following serial transactional protocol:

```
[Incoming Request]
       │
       ▼
1. Pre-admission Validation & Rate/Concurrency Guards
   ├── Pre-key IP abuse throttling (SW-2.5.1)
   ├── Per-key RPM/TPM token bucket check (SW-2.5.2)
   ├── Model allowlist & in-flight concurrency bound check (SW-2.5.3)
   └── Capability resolution & pricing verification (SW-2.1.2)
       │
       ▼
2. Cost Estimation (Microdollars) (SW-2.1.1)
   └── Compute maximum microdollar estimate for requested model/tokens
       │
       ▼
3. Atomic Redis Budget Reservation (`RESERVE` Lua Script) (SW-2.4.1)
   ├── Denied / Insufficient Budget ──► Reject (402 Payment Required / 429)
   └── Approved ──► Proceed to PostgreSQL Durable Admission
       │
       ▼
4. PostgreSQL Attempt-Admission Transaction (SW-2.2.3)
   │  BEGIN (within withTenant(pool, principal.orgId))
   │
   ├──► 4a. Acquire shared Gateway epoch transaction advisory lock:
   │        SELECT pg_catalog.pg_advisory_xact_lock_shared(epoch_lock_key);
   │        (Lock key defined in SW-2.2.1 registry)
   │
   ├──► 4b. Re-read and verify Gateway epoch:
   │        SELECT gateway_epoch FROM public.gateway_control WHERE id = 1;
   │        (Assert gateway_epoch === expectedProcessEpoch; fail closed on mismatch,
   │         missing singleton row, or query error)
   │
   ├──► 4c. Row-lock virtual-key record & recheck revocation status:
   │        SELECT id, org_id, revoked_at
   │        FROM public.virtual_keys
   │        WHERE id = $1
   │        FOR UPDATE;
   │
   ├──► 4d. Evaluate Key Validity:
   │        ├── Row missing or org_id != principal.orgId ──► DENY (fail closed)
   │        └── revoked_at IS NOT NULL ──► DENY (KEY_REVOKED)
   │
   ├──► 4e. Insert durable attempt record in reserved status:
   │        INSERT INTO public.provider_attempts (
   │          attempt_id, request_id, org_id, virtual_key_id, attempt_number,
   │          gateway_instance_id, gateway_epoch, billing_period, provider,
   │          model, status, estimated_cost_microdollars, cost_status, hard_deadline_at
   │        ) VALUES (..., 'reserved', ..., 'estimated', ...);
   │
   └──► 4f. COMMIT transaction (Releases advisory lock & virtual-key row lock)
       │
       ▼
5. Pre-Dispatch Verification & Upstream Dispatch (SW-2.6.2)
   └── Dispatch to provider adapter only after COMMIT confirmed and pre-dispatch eligibility recheck succeeds
```

### Schema Contract: `public.gateway_control` (Migration `0002`)
The epoch check queries the singleton control table:
```sql
SELECT gateway_epoch FROM public.gateway_control WHERE id = 1;
```
- **Fail-Closed Verification:** If `id = 1` is missing, if `gateway_epoch` does not match the active Gateway process epoch, if the query fails, or if process fencing authority is lost, the transaction must immediately roll back and deny admission.

### Schema Contract: `public.provider_attempts` (Migrations `0007` & `0008`)
The normative attempt-admission insert populates the exact migrated database schema:

```sql
-- Pseudocode illustration of durable attempt reservation (SW-2.2.3)
INSERT INTO public.provider_attempts (
  attempt_id,
  request_id,
  org_id,
  virtual_key_id,
  attempt_number,
  gateway_instance_id,
  gateway_epoch,
  billing_period,
  provider,
  model,
  status,
  estimated_cost_microdollars,
  cost_status,
  hard_deadline_at
) VALUES (
  $1,                  -- attempt_id: UUID PRIMARY KEY
  $2,                  -- request_id: UUID (foreign key to gateway_requests)
  $3,                  -- org_id: UUID (tenant isolation)
  $4,                  -- virtual_key_id: UUID (foreign key to virtual_keys)
  $5,                  -- attempt_number: INT (CHECK >= 1)
  $6,                  -- gateway_instance_id: UUID
  $7,                  -- gateway_epoch: BIGINT (matches gateway_control.gateway_epoch)
  $8,                  -- billing_period: TEXT ('YYYY-MM' matching admitted_at UTC)
  $9,                  -- provider: TEXT (e.g. 'openai')
  $10,                 -- model: TEXT (e.g. 'gpt-4o')
  'reserved',          -- status: TEXT ('reserved')
  $11,                 -- estimated_cost_microdollars: BIGINT (CHECK >= 0)
  'estimated',         -- cost_status: TEXT ('estimated' when actual_cost is NULL)
  $12                  -- hard_deadline_at: TIMESTAMPTZ
);
```

### Invariant: Lock Confinement
The row-level lock (`SELECT ... FOR UPDATE`) on `public.virtual_keys` must be acquired inside the attempt-admission transaction and held until `COMMIT` or `ROLLBACK`. The revocation check cannot be performed outside or prior to this transaction.

---

## 4. Concurrency Ordering & Serialization Guarantees

PostgreSQL row-level locking enforces deterministic serialization between administrative revocation transactions and admission transactions:

### Scenario A — Revocation Precedes Admission Lock
1. Admin transaction R executes `SELECT id FROM public.virtual_keys WHERE id = $1 FOR UPDATE`.
2. Admin transaction R updates `revoked_at = clock_timestamp()`.
3. In-flight admission transaction A executes `SELECT id, revoked_at FROM public.virtual_keys WHERE id = $1 FOR UPDATE`.
4. Transaction A blocks waiting for Transaction R's exclusive lock.
5. Transaction R commits.
6. Transaction A unblocks, observes `revoked_at IS NOT NULL`, and rejects admission fail-closed.
7. No attempt row is inserted, and no upstream dispatch occurs.

### Scenario B — Admission Lock Precedes Revocation
1. In-flight admission transaction A executes `SELECT id, revoked_at FROM public.virtual_keys WHERE id = $1 FOR UPDATE`.
2. Transaction A observes `revoked_at IS NULL` (key is active).
3. Admin transaction R initiates `DELETE /api/keys/:id` and attempts `SELECT ... FOR UPDATE`.
4. Transaction R blocks waiting for Transaction A's lock.
5. Transaction A inserts the reserved `provider_attempts` row and commits.
6. Transaction R unblocks, observes `revoked_at IS NULL`, updates `revoked_at = clock_timestamp()`, and commits.
7. Transaction A's already-committed attempt completes within its bounded deadline; all subsequent admission transactions observe the revoked state and reject.

---

## 5. Failure and Commit-Uncertainty Rules

To maintain absolute accounting and ledger integrity, failures during admission are partitioned into four distinct categories:

### Case A — Confirmed Failure Before Commit
- **Trigger Conditions:** Pre-admission policy rejection, epoch mismatch in `gateway_control`, key revoked (`revoked_at IS NOT NULL`), key missing, tenant mismatch, or SQL execution/constraint error with confirmed transaction rollback.
- **System Behavior:**
  - Do not dispatch upstream.
  - Release the associated Redis reservation via the approved `CANCEL_RESERVATION` protocol (`SW-2.4.4`).
  - Return the appropriate structured error to the caller without leaking internal state.

### Case B — Confirmed Commit Success
- **Trigger Conditions:** Transaction `COMMIT` completion tag is confirmed by PostgreSQL.
- **System Behavior:**
  - Durable `public.provider_attempts` record exists with `status = 'reserved'` and `cost_status = 'estimated'`.
  - Preserve the Redis reservation hold.
  - Proceed to upstream dispatch under `SW-2.6.2` once final pre-dispatch eligibility checks pass.

### Case C — Commit Outcome Uncertain
- **Trigger Conditions:** Client-server connection drops during `COMMIT`, database connection resets while commit acknowledgment is pending, or network/statement timeout occurs before the command completion tag is received.
- **System Behavior:**
  - **Do not dispatch** upstream merely because commit was attempted.
  - **Do not assume rollback.**
  - **Do NOT cancel** the Redis reservation speculatively (never cancel based on uncertainty).
  - Preserve the reservation hold in Redis.
  - Leave recovery to the background persist-and-repair worker (`SW-2.7.2`) and accounting reconciler (`SW-2.8.3`), which determine the canonical PostgreSQL state and converge without unaccounted spend.

### Case D — Unexpected Redis or Script Failure
- **Trigger Conditions:** Redis unreachable, command timeout, or Lua script runtime error during reservation.
- **System Behavior:**
  - Fail closed immediately.
  - Do not guess whether reservation succeeded.
  - Do not manually adjust accounting counters.
  - Follow accepted recovery rules (`SW-2.8.4`).

### Policy on In-Flight Admitted Attempts
An attempt whose admission transaction durably committed before a subsequent revocation committed is permitted to complete its execution within its bounded deadline (`hard_deadline_at`). Administrative revocation forbids new attempt admissions; it does not retroactively invalidate or corrupt durable ledger history.

---

## 6. Phase 2 Implementation Dependencies

The capabilities specified in this contract are owned by the following authoritative roadmap tasks:

| Roadmap Task | Subphase | Capability Owned |
| :--- | :--- | :--- |
| **`SW-2.1.1`** | 2.1 | Bigint microdollar types, decimal JSON codec, and price arithmetic |
| **`SW-2.1.2`** | 2.1 | Capability/pricing contracts and verified model metadata |
| **`SW-2.1.3`** | 2.1 | Logical request admission and immutable billing period |
| **`SW-2.2.1`** | 2.2 | Advisory-lock key registry for singleton gateway and epoch locks |
| **`SW-2.2.2`** | 2.2 | Gateway startup epoch increment and exclusive epoch transaction lock |
| **`SW-2.2.3`** | 2.2 | **Shared epoch lock, virtual-key row lock, and revocation recheck inside attempt admission** |
| **`SW-2.3.1`** | 2.3 | Redis client ACL, startup checks, and global recovering/ready gate |
| **`SW-2.4.1`** | 2.4 | Redis `RESERVE` financial transition Lua script |
| **`SW-2.4.4`** | 2.4 | Redis `CANCEL_RESERVATION` and `ACK_LEDGER` financial transitions |
| **`SW-2.5.1`** | 2.5 | Pre-key IP abuse throttling and trusted-proxy controls |
| **`SW-2.5.2`** | 2.5 | Per-key RPM/TPM token buckets |
| **`SW-2.5.3`** | 2.5 | Model allowlists and concurrency/in-flight admission limits |
| **`SW-2.6.2`** | 2.6 | End-to-end Redis reserve → durable SQL admission → safe dispatch integration |
| **`SW-2.7.2`** | 2.7 | Persist-and-repair worker handling commit uncertainty & orphan cleanup |
| **`SW-2.8.3`** | 2.8 | Canonical PostgreSQL/Redis accounting reconciliation |

---

## 7. Cross-References

- `docs/architecture/architecture-v1.2.md`: §5.3 (Security Invariants), §6.1–6.3 (Request Admission & Dispatch Sequence), §7.1–7.9 (Financial Transitions & Uncertainty), §8.1–8.2 (Epoch Fencing), §11.6–11.8 (Schema Contracts), §12.5 (Advisory Locks).
- `docs/SECURITY.md`: §11 (Virtual Key Architecture), §12.6 & §13.8 (Phase 2 Admission Notices), §14 (Revocation & Admission Seam).
- `docs/DEVELOPMENT.md`: §7.7 (Virtual Key Verification & Known Limitations).
- `docs/roadmap/implementation-roadmap-v1.md`: Phase 2 Roadmap Tasks.
