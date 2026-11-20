# Switchyard — Security Architecture & Threat Model

This document outlines the security architecture, threat model, and defense-in-depth boundaries of Switchyard as established in Architecture v1.2 §§5.3, 12.1–12.6, 19.2, and 21.3.

---

## 1. Overview & Threat Model

Switchyard is a multi-tenant AI Inference Gateway and Observability Control Plane. Multiple organizations (tenants) share the same underlying database and infrastructure. The primary security objective is complete tenant isolation, least privilege, and cryptographic protection of sensitive credentials.

### 1.1 In-Scope Threats

1. **Accidental Cross-Tenant Data Leakage:** Application developers omitting `WHERE org_id = ...` clauses or joins in queries.
2. **Cross-Tenant Mutation Attacks:** Tenant A forging requests attempting to read, update, insert, or delete data belonging to Tenant B.
3. **Cross-Tenant Foreign Key Transplant:** Tenant A creating a resource (e.g., attempt or request) referencing Tenant B's credentials or virtual keys.
4. **Privilege Escalation:** Runtime accounts attempting DDL, altering permissions, assuming table owner, or reading migration metadata.
5. **Credential Exfiltration by Background Workers:** Observability or cleanup workers accessing raw provider API keys or data encryption keys.
6. **Session-Scope Context Bleed:** Connections in a connection pool retaining a prior tenant's identity into subsequent unrelated transactions.

---

## 2. Row-Level Security (RLS) Model

All nine tenant-owned tables enforce PostgreSQL Row-Level Security:

1. `organizations` (predicate: `id = current_org_id`)
2. `users` (predicate: `org_id = current_org_id`)
3. `web_sessions` (predicate: `org_id = current_org_id`)
4. `provider_keys` (predicate: `org_id = current_org_id`)
5. `virtual_keys` (predicate: `org_id = current_org_id`)
6. `gateway_requests` (predicate: `org_id = current_org_id`)
7. `provider_attempts` (predicate: `org_id = current_org_id`)
8. `provider_cost_adjustments` (predicate: `org_id = current_org_id`)
9. `trace_payloads` (predicate: `org_id = current_org_id`)

### 2.1 Unified Permissive Policies (DB-04 Guard)

PostgreSQL combines multiple permissive policies with logical `OR`. In earlier iterations (0002), separate permissive policies for `USING` and `WITH CHECK` created a vulnerability where `USING (true)` was implicitly evaluated, bypassing `SELECT` isolation.

Migration `0009-tenant-rls-policies.sql` establishes exactly **one** unified permissive policy per table:

```sql
CREATE POLICY <table_name>_tenant_isolation ON <table_name>
  AS PERMISSIVE
  FOR ALL
  TO PUBLIC
  USING (<org_col> = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
  WITH CHECK (<org_col> = NULLIF(current_setting('app.current_org_id', true), '')::uuid);
```

- **`USING`:** Filters existing rows on `SELECT`, `UPDATE`, and `DELETE`. Invisible rows return empty sets or affect zero rows.
- **`WITH CHECK`:** Enforces tenant consistency on `INSERT` and `UPDATE`. Violations immediately fail with SQLSTATE `42501`.

### 2.2 Why `FORCE ROW LEVEL SECURITY` Is Mandatory

By default, PostgreSQL bypasses RLS for table owners. Switchyard enforces `ALTER TABLE ... FORCE ROW LEVEL SECURITY` on all tenant tables. This guarantees that policies apply unconditionally, even if a query runs under table owner `gateway_owner`.

### 2.3 Why Runtime Roles Never Receive `BYPASSRLS`

Neither `gateway_app`, `gateway_worker`, nor `gateway_startup` possesses the `BYPASSRLS` attribute. They cannot bypass RLS under any circumstance. Even if an application query omits tenant filters entirely, PostgreSQL's query rewriter injects the RLS security qual.

---

## 3. Trusted Application Boundary & GUC Spoofing Limitation (§12.6)

Architecture §12.6 defines an essential trust boundary:

> **PostgreSQL's custom tenant GUC (`app.current_org_id`) is application context, not a cryptographic identity.**

- The `withTenant(orgId, callback)` helper validates UUID syntax and sets `app.current_org_id` transaction-locally via:
  ```sql
  SELECT pg_catalog.set_config('app.current_org_id', $1, true);
  ```
- **What RLS Protects Against:** Missing `WHERE` clauses, subtle join bugs, accidental cross-tenant queries, and application-level routing slips.
- **What RLS Does NOT Protect Against:** A compromised Gateway process capable of executing arbitrary SQL under the `gateway_app` database credential. Such an attacker could execute `set_config('app.current_org_id', victim_org_id, true)`.
- **Mitigation:** The application process itself must be protected through memory safety, strict input validation, principle of least privilege, absence of raw SQL interpolation, and network isolation.

### 3.1 Transaction Integrity, Lifetime, and Callback Confinement (DB-26, DB-27, DB-29, DB-30, DB-31)

To ensure the transaction boundary cannot be corrupted by application code:

1. **Confirmed COMMIT Verification (DB-26):** In PostgreSQL, if a statement error inside a transaction block is caught and swallowed by application code, a subsequent `COMMIT` command resolves without throwing, but PostgreSQL rolls back the transaction and returns the command completion tag `ROLLBACK`. `withTenant` inspects this completion tag and rejects any completion other than `COMMIT`, guaranteeing that silent rollbacks are never reported as successful operations.
2. **Protocol-Enforced Single Statement & Transaction Control Guards (DB-27, DB-30):**
   - In `tenantClient.query()`, `withTenant` unconditionally forces PostgreSQL's extended query protocol (`queryMode: 'extended'`). Under extended query protocol, PostgreSQL natively rejects any multi-statement command string with SQLSTATE `42601` (`cannot insert multiple commands into a prepared statement`). Caller-supplied `queryMode` cannot override this.
   - Transaction control statements (`BEGIN`, `COMMIT`, `ROLLBACK`, `START TRANSACTION`, `END`, `ABORT`, `SAVEPOINT`, `RELEASE`, `PREPARE TRANSACTION`) are stripped of leading whitespace and comments (supporting nested block comments) and rejected prior to dispatch. The lexical pre-check adheres to PostgreSQL 16 `standard_conforming_strings = on`, preventing quote-escaping evasion.
   - Direct calls to `client.release()` are intercepted and rejected with `TenantTransactionError`.
3. **Session-Level Context Sanitation Invariant (DB-31, DB-33, DB-34):** No reusable pooled connection may retain tenant identity from a completed transaction. Outside of an active transaction upon completion, `withTenant` issues `RESET ALL` and `DISCARD TEMP` to purge session GUCs and temporary tables while preserving server-side prepared statements cached on client connections by `node-postgres` (avoiding SQLSTATE `26000`). It verifies `current_setting('app.current_org_id', true)` is empty; if residual context exists or cleanup fails, the connection is invalidated via `client.release(true)`. Furthermore, once PostgreSQL confirms `COMMIT`, post-commit cleanup failures do not report the transaction as failed (DB-33); the connection is destroyed and the error is diagnosed without compromising durable writes.
4. **Async Continuation Isolation (DB-29):** `AsyncLocalStorage` context tracks active transaction state. When a transaction completes, the context is marked inactive. Detached asynchronous continuations running after transaction completion cannot execute queries on released pooled connections and cannot access stale tenant context.
5. **Residual Trust Assumptions:** The JavaScript runtime boundary protects against accidental misuse and standard application bugs. It assumes the Node.js process itself is uncompromised; an attacker with arbitrary code execution inside the Node runtime could inspect process memory or access native socket handles directly. Defense-in-depth requires strict input parameterization, non-root container sandboxing, and absence of raw SQL interpolation.

---

## 4. Role & Credential Separation

Switchyard segregates database responsibilities across distinct roles (Architecture §12.1):

| Role | Login? | BYPASSRLS? | Scope & Responsibilities |
| :--- | :---: | :---: | :--- |
| `gateway_owner` | No | No | Owns all tenant tables and trigger functions. Never used by runtime services. |
| `gateway_migrator` | Deployment-only | No | Applies forward-only migrations. Can `SET ROLE gateway_owner`. No runtime access. |
| `gateway_startup` | Yes | No | Dedicated singleton connection. Updates `gateway_control.gateway_epoch` only. Zero tenant table access. |
| `gateway_app` | Yes | No | Fastify Gateway runtime. Tenant-scoped data plane and control plane. Access to provider keys for upstream dispatch. No financial `DELETE`. |
| `gateway_worker` | Yes | No | Background worker (recovery, adjustments, trace pruning). Column-level grants strictly deny provider secrets and encryption keys. |
| `gateway_auth_executor` | No | Yes | Future (SW-1.4.3) owner of pre-tenant authentication functions. Not a table owner. |
| `gateway_ops_executor` | No | Yes | Future (SW-1.4.4) owner of maintenance enumeration functions. Not a table owner. |

### 4.1 Worker Secret Isolation

To prevent worker compromise from exposing provider credentials:
- `organizations.wrapped_dek`, `dek_iv`, and `dek_auth_tag` are revoked from `gateway_worker`.
- `provider_keys.ciphertext`, `iv`, and `auth_tag` are revoked from `gateway_worker`.
- `users` and `web_sessions` tables have zero grants for `gateway_worker`.
- Workers receive non-secret metadata only (`id`, `name`, `monthly_budget_microdollars`, `provider`, `label`, `key_hint`, `is_active`).

---

## 5. Privileged Pre-Tenant Authentication & Maintenance Functions (SW-1.4.3 & SW-1.4.4)

Operations that occur before tenant identity is established (e.g., virtual API key lookup by hash, user login by normalized email, organization/admin bootstrap) or during tenant discovery (worker maintenance enumeration) cannot rely on `app.current_org_id`.

To fulfill these requirements without granting broad cross-tenant `SELECT` permissions to `gateway_app` or `gateway_worker`, Switchyard implements isolated, hardened `SECURITY DEFINER` functions in the `app_private` schema (Architecture §12.4).

### 5.1 Dedicated Executor Roles and Bounded BYPASSRLS

- **`gateway_auth_executor` (`NOLOGIN BYPASSRLS`):**
  - Owns authentication functions: `app_private.lookup_virtual_key_by_hash`, `app_private.lookup_user_for_login`, and `app_private.create_organization_with_admin`.
  - Holds narrow column-level `SELECT` on `virtual_keys` (12 fields) and `users` (4 login fields), plus column-level `INSERT` on `organizations` and `users` for bootstrap.
  - Zero `UPDATE`, `DELETE`, or `TRUNCATE` privileges on any table.
  - Does NOT own any tenant tables.
- **`gateway_ops_executor` (`NOLOGIN BYPASSRLS`):**
  - Owns maintenance enumerator: `app_private.list_active_org_ids`.
  - Holds column-level `SELECT (id)` on `public.organizations` only.
  - Zero privileges on any other column, tenant table, credential, or key.
  - Does NOT own any tenant tables.
- **BYPASSRLS Confinement:** `BYPASSRLS` is restricted exclusively to these non-login executor roles. Neither `gateway_app`, `gateway_worker`, `gateway_startup`, nor `gateway_migrator` holds `BYPASSRLS`.

### 5.2 Deployment Provisioning & Assumption Model

To allow deployment role `gateway_migrator` to install executor-owned functions without violating least privilege:
- `provision-roles.sql` grants `gateway_auth_executor` and `gateway_ops_executor` to `gateway_migrator` with explicit `WITH INHERIT FALSE, SET TRUE, ADMIN FALSE`.
- `gateway_migrator` does not automatically inherit executor privileges (`INHERIT FALSE`), cannot grant them to others (`ADMIN FALSE`), and may only assume them via explicit `SET ROLE` within migration transactions.
- Runtime principals (`gateway_app`, `gateway_worker`, `gateway_startup`) are strictly prohibited from assuming or administering either executor role.
- `app_private` schema creation privileges are granted only to `gateway_owner`, `gateway_migrator`, `gateway_auth_executor`, and `gateway_ops_executor`. Runtime roles receive `USAGE` only.

### 5.3 Function Hardening & Attack Mitigations

1. **Hardened Fixed Search Path:**
   - Every privileged function declares:
     ```sql
     SET search_path = pg_catalog, app_private, pg_temp
     ```
   - Schema references inside function bodies are explicitly qualified (`public.virtual_keys`, `public.users`, `public.organizations`).
   - `pg_temp` is placed last, completely thwarting search-path poisoning and malicious temporary table/function shadowing attacks.
2. **Default EXECUTE Revocation:**
   - `REVOKE ALL ON FUNCTION ... FROM PUBLIC` is executed within the same migration transaction as function creation.
   - `GRANT EXECUTE` is issued strictly to the authorized runtime role (`gateway_app` for authentication functions, `gateway_worker` for maintenance enumeration).
   - `gateway_startup` and `PUBLIC` have zero execution privileges.
3. **Fail-Closed Input Contracts:**
   - `lookup_virtual_key_by_hash`: Fails closed and returns 0 rows on NULL, empty, or wrong-length hash (!= 32 bytes).
   - `lookup_user_for_login`: Fails closed and returns 0 rows on NULL, empty, oversized email (> 255 chars), or noncanonical email (mixed-case, leading/trailing whitespace, missing '@'; DB-36). Exact matching on canonical `email_normalized` avoids identity ambiguity. Returns `password_hash` strictly for verification by the trusted authentication handler in SW-1.5.1.
   - `create_organization_with_admin`: Strict validation fails closed with SQLSTATE `22004` (nulls) and `22023` (invalid parameters, bounded budget $\le 10^{15}$, non-empty DEKs). Enforces strict canonical email normalization (DB-36) and complete Argon2id PHC verifier representation structure (algorithm `argon2id`, version `v=19`, required positive integer parameters `m, t, p`, and non-empty separate salt and derived-hash tokens; DB-37, DB-39), rejecting plaintext passwords, non-Argon2 algorithms, missing/empty salt, missing/empty derived hash, and malformed structures. Atomic rollback on any constraint violation (`23505`) prevents orphan organizations or orphaned admin users.
   - `list_active_org_ids`: Bounded limits (1..100). Invalid limits fail closed with SQLSTATE `22023`. Keyset pagination ensures deterministic, duplicate-free enumeration.
4. **Maintenance Enumeration Privacy Boundary:**
   - `list_active_org_ids` returns only `org_id UUID`. It never returns organization names, budgets, wrapped DEKs, or created timestamps.
   - Background workers must execute all subsequent maintenance operations inside `withTenant(orgId, callback)`.

### 5.4 What SECURITY DEFINER Does and Does Not Protect Against

- **What It Protects Against:** It allows unauthenticated Gateway processes to look up virtual keys and user credentials by exact hash/email without granting `gateway_app` global `SELECT` on `virtual_keys` or `users`. It prevents accidental cross-tenant data leaks and SQL injection attacks from accessing arbitrary rows.
- **What It Does NOT Protect Against:**
  - A compromised Gateway process can still invoke `lookup_virtual_key_by_hash` or `lookup_user_for_login`.
  - Database functions do not implement application-level brute-force abuse rate limiting, IP rate limiting, or Argon2id password verification.
  - **Required Mitigations:** Strict Fastify pre-admission IP rate limiting (Architecture §6.1), dummy timing verification on unknown emails to prevent timing enumeration (SW-1.5.1), and Argon2id hashing bounds.

---

## 6. Subphase 1.4 Architecture Tracking & Verification

| Requirement / Task | Status | Reference | Verified Evidence |
| :--- | :---: | :--- | :--- |
| **Batch A: Transaction Context (SW-1.4.1)** | ACCEPTED | PR #9 (merge commit `21ae53c5b28e4eaeda33ad2658c47297fe653e49`) | `tenant.ts`, `tenant.test.ts`, `tenant-rls.db.test.ts` (32 tests) |
| **Batch A: Tenant RLS Policies (SW-1.4.2)** | ACCEPTED | PR #9, Migration `0009-tenant-rls-policies.sql` | 9 tenant tables FORCE RLS, unified permissive policies |
| **Batch B: Auth Functions (SW-1.4.3)** | IMPLEMENTED | Migration `0010-privileged-bootstrap-functions.sql` | Owned by `gateway_auth_executor`, hardened `search_path`, 0 rows on invalid inputs, atomic bootstrap |
| **Batch B: Maintenance Enumerator (SW-1.4.4)**| IMPLEMENTED | Migration `0010-privileged-bootstrap-functions.sql` | Owned by `gateway_ops_executor`, UUID-only return, bounded keyset pagination |
| **Batch B: Executor Provisioning Decision** | APPROVED | Owner-approved Option 1 (`provision-roles.sql`) | `gateway_migrator` granted `INHERIT FALSE, SET TRUE, ADMIN FALSE` |
| **Batch B: v1 Active Org Interpretation** | APPROVED | Owner-approved v1 decision | All existing rows in `public.organizations` enumerated via keyset pagination; no column added |
