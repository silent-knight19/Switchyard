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
| **Batch B: Auth Functions (SW-1.4.3)** | ACCEPTED | PR #10 (merge commit `4a85c7e913291e01e6d72a4b4367b37449d1ec6e`) | Owned by `gateway_auth_executor`, hardened `search_path`, 0 rows on invalid inputs, atomic bootstrap |
| **Batch B: Maintenance Enumerator (SW-1.4.4)**| ACCEPTED | PR #10 (merge commit `4a85c7e913291e01e6d72a4b4367b37449d1ec6e`) | Owned by `gateway_ops_executor`, UUID-only return, bounded keyset pagination |
| **Batch B: Executor Provisioning Decision** | ACCEPTED | Owner-approved Option 1 (`provision-roles.sql`) | `gateway_migrator` granted `INHERIT FALSE, SET TRUE, ADMIN FALSE` |
| **Batch B: v1 Active Org Interpretation** | ACCEPTED | Owner-approved v1 decision | All existing rows in `public.organizations` enumerated via keyset pagination; no column added |

---

## 7. Subphase 1.5 Architecture Tracking & Verification

| Requirement / Task | Status | Reference | Verified Evidence |
| :--- | :---: | :--- | :--- |
| **Batch A: Secure Authentication (SW-1.5.1)** | ACCEPTED | PR #11 (merge commit `2fbe6080919e20dee18af2a94da7f046e6fff20c`) | 128-byte password cap, real Argon2id hashing (`m=19456, t=2, p=1`), dummy verify on unknown accounts, canonical email normalization, Redis IP/account rate limits |
| **Batch A: Server-Side Web Sessions (SW-1.5.2)** | ACCEPTED | PR #11 (merge commit `2fbe6080919e20dee18af2a94da7f046e6fff20c`) | 256-bit opaque secret (`__Host-session`), SHA-256 verifier persistence, atomic rotation, idle/absolute expiry, revocation, RLS cross-tenant isolation |
| **Batch A: Pre-Tenant Session Lookup (ADR 0001)** | ACCEPTED | PR #11 (merge commit `2fbe6080919e20dee18af2a94da7f046e6fff20c`) | `app_private.lookup_session_org_by_hash(BYTEA)` owned by `gateway_auth_executor`, UUID-only return, granted strictly to `gateway_app` |
| **Batch B: Session-Bound CSRF & Strict Origin (SW-1.5.3)** | ACCEPTED | PR #12 (merge commit `639e0d276a72be0f52b239bda5b69e68080d0565`) | 256-bit synchronizer token, constant-time `timingSafeEqual`, exact `Origin` matching against `BROWSER_ORIGIN`, atomic row serialization under RLS, Fastify preHandler boundary |
| **Batch B: Default-Deny Route Authorization, Principal Separation & RBAC (SW-1.5.4)** | ACCEPTED | PR #13 (merge commit `05eae92341a023f0eeca3deca7da7171b7a50eb6`) | Default-deny Fastify `onRoute` registration guard (`AUTHZ_ROUTE_POLICY_INVALID`), request-time principal separation (`browser`, `virtual_key`, `anonymous`), admin/member RBAC hierarchy, CSRF/RBAC composition on mutations |

---

## 8. Subphase 1.6 Architecture Tracking & Verification

| Requirement / Task | Status | Reference | Verified Evidence |
| :--- | :---: | :--- | :--- |
| **Virtual API Key Issuance (SW-1.6.1)** | IMPLEMENTED | `src/auth/virtual-key.ts`, `src/auth/virtual-key.test.ts`, `src/auth/virtual-key.db.test.ts` | 256-bit cryptographically secure generation, canonical `gw_live_<11>_<43>` format, SHA-256 verifier persistence (`key_hash BYTEA UNIQUE`), public hint (`gw_live_<11>`), one-time raw key disclosure, deny-all model policy (`allowed_models = '{}'`), bounded collision retry (max 3), RLS isolation, worker denial |

---

## 9. CSRF & Strict Origin Verification Architecture (SW-1.5.3)

Switchyard implements the server-side synchronizer token pattern bound to authenticated server-side sessions (Architecture v1.2 §13.3) combined with strict browser Origin verification.

### 8.1 Cryptographic Token Representation & Verifiers
- **Generation:** 256 bits of cryptographically secure entropy (`crypto.randomBytes(32)`).
- **Encoding:** Canonical unpadded `base64url` (exactly 43 characters, 32 decoded bytes).
- **Canonical Validation:** Round-trip assertion `buf.toString('base64url') === rawToken` strictly rejects noncanonical trailing pad bits, whitespace, standard base64 characters (`+`, `/`), and padding (`=`).
- **Storage:** Only the SHA-256 digest (`csrf_token_hash BYTEA`) is stored in `public.web_sessions`. Plaintext tokens are never persisted in PostgreSQL, Redis, or logging systems.
- **Verification:** Digested using SHA-256 and compared in constant time with `crypto.timingSafeEqual(computedHash, storedHash)` after verifying exact 32-byte digest lengths.

### 8.2 Strict Origin Verification Boundary
- State-changing browser methods (`POST`, `PUT`, `PATCH`, `DELETE`) require an exact match against configured `BROWSER_ORIGIN`.
- Rejects missing, empty, `"null"`, array, comma-separated, malformed, or cross-site origins.
- Rejects trailing slashes, paths, query parameters, URL fragments, and embedded credentials in Origin headers.
- Protection against subdomain prefix and suffix attacks via exact canonical URL origin comparison (`url.origin === allowedOrigin`).
- Untrusted request headers (`Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `Referer`) are never used to derive allowed origins.

### 8.3 Concurrency & Reissuance Semantics
- Only one active CSRF verifier exists per server-side session.
- `reissueCsrfToken` acquires a row lock (`FOR UPDATE OF ws`) under tenant RLS.
- Reissuance follows last-committed-wins: committed reissuance immediately invalidates prior tokens for that session.
- Concurrent issuance operations serialize on the row lock; older tokens fail validation with `CSRF_TOKEN_MISMATCH`.
- Revoked, idle-expired, or absolute-expired sessions cannot issue or verify tokens.
- Transaction rollback on token issuance leaves prior committed verifiers intact.

### 9.4 Integration with Default-Deny Authorization (SW-1.5.4)
- SW-1.5.3 CSRF and Origin verification is unified directly into the central authorization boundary in `apps/gateway/src/auth/authorization.ts`.
- Browser state-changing mutations (`POST`, `PUT`, `PATCH`, `DELETE`) compose strict Origin checking, CSRF validation, session validation, and RBAC enforcement into a single atomic preHandler gate.

---

## 10. Default-Deny Route Authorization, Principal Separation & RBAC (SW-1.5.4)

Switchyard enforces default-deny route authorization across all HTTP entry points (Architecture v1.2 §13.5).

### 10.1 Default-Deny Route Registration Assertion
- Every application route must explicitly declare its authorized principal metadata under `config.authz`.
- Fastify `onRoute` assertion executes at route registration time, before application startup completes.
- Any undeclared route, malformed policy, empty object, unknown principal, or invalid browser role immediately throws `AuthorizationError` with code `AUTHZ_ROUTE_POLICY_INVALID` and prevents application startup.
- Applies to all route registration mechanisms: direct methods (`app.get`, `app.post`, `app.route`), nested plugins, prefixed plugins, and typed helper `registerAuthorizedRoute`.
- Fastify automatically exposed `HEAD` routes inherit their corresponding `GET` route's policy; `HEAD` requests never bypass authorization.

### 10.2 Route Metadata Contract
The accepted shapes of `config.authz` are:
1. **Anonymous route:** `{ principal: 'anonymous' }` (no `minRole` permitted).
2. **Browser route:** `{ principal: 'browser', minRole: 'member' | 'admin' }`.
3. **Virtual-key route:** `{ principal: 'virtual_key' }` (no `minRole` permitted).

Additional undeclared properties on `config.authz` are rejected at runtime.

### 10.3 Strict Principal Separation
- **Browser Routes:** Accept only valid browser sessions (via configured session cookie). Bearer credentials, API keys, and mixed credentials fail closed with 401 Unauthorized.
- **Virtual-Key Routes:** Reserved for data-plane API requests. Require an approved verified-key authenticator dependency. Registration fails closed if no verified authenticator is installed. Session cookies on virtual-key routes fail closed with 401 Unauthorized.
- **Anonymous Routes:** Accessible without credentials. Handlers receive `{ type: 'anonymous' }` principal context. Session cookies or Authorization headers never upgrade an anonymous route.

### 10.4 Role-Based Access Control (RBAC)
- Only two browser roles are supported: `admin` and `member`.
- `admin` satisfies routes requiring `member` or `admin`.
- `member` is rejected (403 Forbidden) on routes requiring `admin`.
- Roles are evaluated fresh from PostgreSQL user state on every request via `public.web_sessions JOIN public.users`; no stale roles are cached in JWTs, Redis, or process memory.
- Privilege changes and session revocations immediately invalidate prior active sessions.

### 10.5 Production Route Inventory (SW-1.5.4)
The production Gateway exposes only:
- `/health/live`: Explicitly authorized with `{ principal: 'anonymous' }`.
- `/health/ready`: Explicitly authorized with `{ principal: 'anonymous' }`.

No production business or management endpoints are exposed in SW-1.5.4. Test endpoints exist strictly inside isolated test harnesses.

---

## 11. Virtual API Key Issuance Architecture (SW-1.6.1)

Switchyard implements cryptographic virtual API key issuance as an internal Gateway service (`VirtualKeyService`), enforcing SHA-256 verifier persistence, tenant isolation, restrictive initial policy, and one-time plaintext disclosure (Architecture v1.2 §13.1, §14.3).

### 11.1 Key Representation & Cryptographic Entropy
- **Entropy Sources:** Generated using Node.js built-in `crypto.randomBytes()`, which draws from system CSPRNG entropy (`/dev/urandom` / `getrandom(2)` on Unix/Linux). While empirical test suites confirm non-collision across sample runs, formal randomness independence and unpredictability rely on the underlying OS kernel entropy pool and CSPRNG design rather than finite statistical sampling. No deterministic PRNG, predictable seeds, timestamps, user IDs, or organization IDs are used.
- **Public Prefix:** 8 random bytes encoded as unpadded base64url (exactly 11 characters). Stored in `virtual_keys.key_prefix` as `gw_live_<11>`. The prefix is public metadata for listings, disambiguated by row UUID; it is never treated as authentication evidence.
- **Secret Material:** 32 random bytes (256-bit entropy) encoded as unpadded base64url (exactly 43 characters).
- **Canonical Envelope:** `gw_live_<11-char-public-prefix>_<43-char-secret>` (exactly 63 ASCII characters).
- **Canonical Base64url Parsing (VK-01):** Key envelopes are strictly validated using `parseRawKey()`. Keys must be exactly 63 ASCII characters matching `^gw_live_([A-Za-z0-9_-]{11})_([A-Za-z0-9_-]{43})$`. The parser decodes both segments and immediately re-encodes them to verify that the original strings match canonical unpadded base64url representations, fail-closed against noncanonical trailing padding bits (such as 42 `A`s followed by `B`).
- **Verifier Computation:** Computed as `SHA-256(secretBytes)` over the 32 raw secret bytes. The resulting 32-byte digest is stored in `virtual_keys.key_hash` as binary `BYTEA UNIQUE`. The printable key string, prefix, and base64url secret are never hashed or stored.

### 11.2 One-Time Disclosure & Secrecy Invariants
- **Transient Plaintext:** The plaintext raw key exists only in memory during creation and is returned once from `createKey()`.
- **Zero Raw Key Persistence:** Raw keys and secret bytes are never stored in PostgreSQL, Redis, cookies, browser storage, background queues, or application caches.
- **Zero Logging:** Raw keys, secrets, hashes, SQL parameters, and connection strings are excluded from Pino logs, error messages, and exception serialization.
- **No Recovery Mechanism:** No `getRawKey()` or secret retrieval method exists. Plaintext cannot be recovered from the 32-byte SHA-256 verifier.
- **Memory Hygiene:** Mutable byte buffers (`Buffer`) allocated for prefix and secret generation or parsing are explicitly cleared using `.fill(0)`. However, zeroization is strictly best-effort for mutable buffers; immutable V8 JavaScript strings (`rawKey`, `secret`, `publicPrefix`) retain representations in process heap memory until garbage collected.

### 11.3 Database Integrity & Deny-All Initial Policy
- **Transaction Scope:** All insertions execute within `withTenant(pool, orgId)` using the runtime role `gateway_app`. Direct insertion without tenant context and cross-tenant insertion are strictly denied by RLS (`FORCE ROW LEVEL SECURITY`).
- **Initial Deny-All Policy:**
  - `allowed_models = '{}'` (empty array): Denies all model invocation.
  - `rpm_limit = 1`, `tpm_limit = 1`, `concurrent_stream_limit = 1`: Deliberately restrictive positive values satisfying migration `0005`'s `NOT NULL` and `CHECK (> 0)` constraints (Principal Architect Decision 2).
  - `exact_cache_enabled = false`, `semantic_cache_enabled = false`.
  - `pii_redaction_enabled = true`, `store_payloads = false`.
  - `revoked_at = NULL`.
- **Commit Confirmation:** The raw key is returned to the caller only after PostgreSQL confirms durable transaction commit (`COMMIT`). Failed or rolled-back transactions never return a key.
- **Bounded Collision Handling (VK-02):** Retry is strictly limited to SQLSTATE `23505` (`unique_violation`) matching explicitly confirmed unique constraints on `public.virtual_keys`: `virtual_keys_key_hash_key`, `virtual_keys_pkey`, and `virtual_keys_id_org_id_key`. If the constraint name is missing or unrecognized, or if any other database error occurs (foreign-key, check constraint, RLS, permission, connection), the service fails closed immediately without retry. A maximum of 3 attempts are permitted before raising `KEY_COLLISION_EXHAUSTED`.
- **Role Isolation:** `gateway_worker` is strictly denied `INSERT` and `UPDATE` on `virtual_keys` (42501).

### 11.4 Future Integration Contracts
- **SW-1.6.2 (Authentication):** Will parse `gw_live_<11>_<43>`, decode the 43-character base64url secret into 32 raw bytes, compute SHA-256, and look up the key via `app_private.lookup_virtual_key_by_hash(BYTEA)`. The public prefix is ignored during authentication.
- **SW-1.6.3 (Management & Policy):** Will introduce administrator-only API routes (`POST /api/keys`, `GET /api/keys`, `DELETE /api/keys/:id`). Model access enablement will require explicit validation and updating of model allowlists and operational rate/concurrency limits together.
