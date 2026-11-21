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
4. **Logical Request Identity:** `requestId` (UUID v7 / PostgreSQL `gateway_requests` primary key).
5. **Validated Provider/Model Target:** Resolved against the verified capability registry and key allowlist (`principal.keyPolicy.allowedModels`).
6. **Current Gateway Epoch:** Active gateway epoch integer held in memory and verified against `public.gateway_epoch`.
7. **Durable Billing Period:** UTC calendar month string (`YYYY-MM`) established at logical request admission.
8. **Estimated Maximum Cost:** Microdollar ceiling for the pending provider attempt.

### Explicit Security Prohibition
Under no circumstances may the admission engine accept a client-supplied `keyId`, `orgId`, or policy parameter as an authority substitute. The database check must bind strictly to the verified properties of `req.principal`.

---

## 3. Mandatory Provider-Attempt Admission Sequence (Architecture §6.3)

Every upstream provider attempt dispatched in Phase 2 must adhere strictly to the following serial transactional protocol:

```
[Incoming Request]
       │
       ▼
1. Pre-admission Validation & Capability Resolution (SW-2.1.2)
       │
       ▼
2. Cost Estimation (Microdollars) (SW-2.1.1)
       │
       ▼
3. Atomic Redis Budget Reservation (`RESERVE` Lua Script) (SW-2.3.1)
   ├── Denied / Insufficient Budget ──► Reject (402 Payment Required / 429)
   └── Approved ──► Proceed to PostgreSQL Durable Admission
       │
       ▼
4. PostgreSQL Attempt-Admission Transaction (SW-2.2.3)
   │  BEGIN (within withTenant(pool, principal.orgId))
   │
   ├──► 4a. Acquire shared Gateway epoch transaction advisory lock:
   │        SELECT pg_catalog.pg_advisory_xact_lock_shared(epoch_lock_key);
   │
   ├──► 4b. Re-read and verify Gateway epoch:
   │        SELECT epoch FROM public.gateway_epoch WHERE id = 1;
   │        (Assert epoch === expectedGatewayEpoch; abort on mismatch)
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
   ├──► 4e. Insert durable attempt record:
   │        INSERT INTO public.provider_attempts (
   │          id, request_id, org_id, virtual_key_id, provider_id, model_id,
   │          status, reserved_cost_microdollars, ...
   │        ) VALUES (..., 'reserved', ...);
   │
   └──► 4f. COMMIT transaction (Releases advisory lock & virtual-key row lock)
       │
       ▼
5. Final Pre-Dispatch Verification & Upstream Dispatch (SW-2.5.1)
   └── Dispatch to provider adapter only after COMMIT confirmed
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

1. **Key Revoked at Admission:** Attempt admission fails immediately. The associated Redis reservation is released via the approved Redis cancellation script (`CANCEL`).
2. **Missing Key or Tenant Mismatch:** Fails closed. The associated Redis reservation is cancelled.
3. **PostgreSQL Network or Storage Failure:** Transaction rolls back. Redis reservation is cancelled.
4. **Gateway Epoch Mismatch:** A newer Gateway has been elected. Transaction rolls back; fail closed.
5. **Commit Uncertainty:** If a network failure occurs during `COMMIT` such that outcome is ambiguous, the Gateway must **never** cancel the Redis reservation speculatively. The reservation is retained until the Phase 2 reconciler (`SW-2.8.3`) verifies the canonical PostgreSQL state.
6. **Already Admitted Attempts:** An attempt whose admission transaction durably committed before revocation commits is permitted to finish streaming within its bounded attempt deadline. Revocation does not retroactively corrupt durable ledger history.

---

## 6. Phase 2 Implementation Dependencies

The following Phase 2 tasks are normative owners of this contract:

| Roadmap Task | Subphase | Capability Owned |
| :--- | :--- | :--- |
| **`SW-2.1.3`** | 2.1 | Logical request admission & immutable `billing_period` assignment |
| **`SW-2.2.1`** | 2.2 | Advisory lock key registry for singleton gateway and epoch locks |
| **`SW-2.2.2`** | 2.2 | Dedicated startup connection, exclusive epoch transaction lock & epoch bump |
| **`SW-2.2.3`** | 2.2 | **Shared epoch lock, virtual-key row lock, and revocation recheck in attempt admission** |
| **`SW-2.3.1`** | 2.3 | Atomic Redis `RESERVE` Lua script and microdollar reservation |
| **`SW-2.5.1`** | 2.5 | Minimal pre-dispatch rate/concurrency guard and pre-dispatch eligibility check |
| **`SW-2.7.2`** | 2.7 | Persist-and-repair worker handling commit uncertainty & orphan cleanup |
| **`SW-2.8.3`** | 2.8 | Accounting reconciler verifying Redis budget against PostgreSQL canonical ledger |

---

## 7. Cross-References

- `docs/architecture/architecture-v1.2.md`: §5.3 (Security Invariants), §6.1–6.3 (Request Admission & Dispatch Sequence), §8.1–8.2 (Epoch Fencing), §12.5 (Advisory Locks).
- `docs/SECURITY.md`: §11 (Virtual Key Architecture), §12.6 & §13.8 (Phase 2 Admission Notices).
- `docs/roadmap/implementation-roadmap-v1.md`: Phase 2 Milestones and Subphases 2.1–2.8.
