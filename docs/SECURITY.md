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
| **Virtual API Key Issuance (SW-1.6.1)** | ACCEPTED | `src/auth/virtual-key.ts`, `src/auth/virtual-key.test.ts`, `src/auth/virtual-key.db.test.ts` | 256-bit cryptographically secure generation, canonical `gw_live_<11>_<43>` format, SHA-256 verifier persistence (`key_hash BYTEA UNIQUE`), public hint (`gw_live_<11>`), one-time raw key disclosure, deny-all model policy (`allowed_models = '{}'`), bounded collision retry (max 3), RLS isolation, worker denial |
| **Virtual API Key Authentication & Abuse Limiting (SW-1.6.2)** | IMPLEMENTED | `src/auth/virtual-key-authenticator.ts`, `src/auth/virtual-key-rate-limiter.ts`, `src/auth/virtual-key-authenticator.db.test.ts`, `src/auth/virtual-key-authenticator.http.db.test.ts` | Canonical parsing via `parseRawKey()`, 32-byte secret SHA-256 verifier derivation, Redis per-IP abuse rate limiting (30 attempts / 15-min fixed window before DB lookup, `auth:ratelimit:vk:ip:<ip>`), restricted pre-tenant DB lookup via `app_private.lookup_virtual_key_by_hash(BYTEA)` owned by `gateway_auth_executor`, uniform HTTP 401 response for all invalid/missing/malformed/unknown/revoked credentials, fail-closed 503 on Redis/PG outages, 429 on abuse limit, typed immutable `VirtualKeyPrincipal` with `keyPolicy`, strict zero secret leakage |

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

### 11.4 Future Integration Contracts & Status
- **SW-1.6.2 (Authentication):** ACCEPTED (PR #15, merge commit `c5cde0aac18ddc288d6c1d85a7f6e9c5bea36880`). Implemented in `src/auth/virtual-key-authenticator.ts` and `src/auth/virtual-key-rate-limiter.ts`.
- **SW-1.6.3 (Management & Policy):** ACCEPTED (PR #16, merge commit `061a3b86aa9091569f7a84863fa8acc90b8e16b1`, CI `44908260283`). Implemented in `src/auth/virtual-key-management.ts` and `src/routes/virtual-keys.ts`.
- **SW-1.6.4 (Revocation & Security Gates):** IMPLEMENTED. Implemented in `src/auth/virtual-key-revocation.db.test.ts`, `src/auth/virtual-key-security.http.db.test.ts`, and `docs/architecture/phase2-admission-key-recheck.md`.

---

## 12. Virtual API Key Authentication & Hash Lookup Architecture (SW-1.6.2)

Switchyard implements secure virtual API key authentication and restricted hash lookup as a Gateway service (`VirtualKeyAuthenticatorService`), integrating per-IP abuse rate limiting, canonical format parsing, restricted database lookup, and uniform HTTP 401 error responses (Architecture v1.2 §5.3, §11.6, §12.4, §13.1, §13.5, §14.3).

### 12.1 Authentication Sequence & Canonical Parsing
- **Transport Extraction:** Incoming HTTP `Authorization: Bearer <rawKey>` credentials are extracted without silent whitespace normalization or repair. If the header is missing, empty, or does not begin with `Bearer `, authentication immediately rejects with generic HTTP 401.
- **Client IP Abuse Limiter Before Database:** Every bearer-key attempt reaching the authenticator first asserts per-IP rate limits against Redis. Malformed or unknown keys consume the same IP allowance. If the threshold is exceeded, a generic HTTP 429 is returned without querying PostgreSQL.
- **Envelope Validation:** Incoming keys are parsed using `parseRawKey()`, enforcing:
  - Exact 63 ASCII character length.
  - Strict regex matching `^gw_live_([A-Za-z0-9_-]{11})_([A-Za-z0-9_-]{43})$`.
  - Canonical base64url re-encoding verification, fail-closed against noncanonical trailing padding bits.
- **Verifier Derivation:** Decodes the 43-character base64url secret into exactly 32 raw bytes, computes `SHA-256(secretBytes)` as a 32-byte binary Buffer, and zeroizes mutable byte buffers (`.fill(0)`) on a best-effort basis. The public prefix is public hint metadata and is excluded from hash computation.
- **Restricted Database Function:** Parameterized query invokes `app_private.lookup_virtual_key_by_hash($1::bytea)` with the 32-byte binary verifier bound to `$1`.

### 12.2 Per-IP Abuse Rate Limiting (Architecture §13.1)
- **Namespace:** `auth:ratelimit:vk:ip:<ip>`, strictly separated from browser login rate limit keys (`auth:ratelimit:ip:<ip>`).
- **Privacy:** Limiter keys contain only normalized, validated client IP addresses (via `sanitizeClientIp()`). Raw keys, secrets, hashes, and authorization headers are strictly excluded from Redis keys.
- **Threshold Policy:** Fixed-window threshold of 30 attempts per 15-minute window (`ipLimit: 30`, `ipWindowSeconds: 900`).
- **Atomic Enforcement:** Evaluated using an atomic Redis Lua script (`INCR` with conditional `EXPIRE`).
- **Fail-Closed Outage Handling:** If Redis encounters network errors or is unavailable, authentication fails closed immediately with generic HTTP 503 (`SERVICE_UNAVAILABLE`).

### 12.3 Restricted Pre-Tenant Hash Lookup (`app_private.lookup_virtual_key_by_hash`)
- **Pre-Tenant Execution:** Because the tenant identity is unknown prior to authentication, the lookup executes via the restricted `SECURITY DEFINER` function `app_private.lookup_virtual_key_by_hash(BYTEA)` owned by `gateway_auth_executor` (fixed search path `pg_catalog, app_private, pg_temp`).
- **Least Privilege:** Granted strictly to `gateway_app`. Denied to `gateway_worker` and revoked from `PUBLIC` (42501).
- **Exact Verifier Contract:** The function accepts only valid 32-byte binary hashes (`pg_catalog.octet_length(p_key_hash) = 32`). NULL, empty, or wrong-length inputs return zero rows.
- **Field Whitelisting:** Returns only approved identity and policy columns (`id`, `org_id`, `revoked_at`, `allowed_models`, `rpm_limit`, `tpm_limit`, `concurrent_stream_limit`, `exact_cache_enabled`, `semantic_cache_enabled`, `pii_redaction_enabled`, `store_payloads`). Zero secret or verifier data is returned.
- **Policy Integrity Assertion:** Returned row fields are strictly validated fail-closed. Missing or malformed UUIDs, non-array model lists, non-positive integer limits, or invalid booleans raise `INTEGRITY_ERROR` (resulting in controlled HTTP 503) rather than permissive defaults.

### 12.4 Uniform HTTP Error Responses & Observability
- **Uniform 401 Identity:** The exact same external HTTP status code (401) and JSON response body:
  ```json
  {
    "statusCode": 401,
    "error": "Unauthorized",
    "message": "Authentication required"
  }
  ```
  is returned for every invalid credential scenario:
  - Missing Authorization header
  - Empty Authorization header
  - Unsupported scheme
  - Missing bearer token
  - Malformed token envelope
  - Incorrect token length
  - Noncanonical base64url padding bits
  - Well-formed unknown key
  - Revoked virtual key
  - Browser cookie on virtual-key route
  - Conflicting cookie and bearer token
- **Controlled Outage Responses:**
  - Database outage / query failure: Generic HTTP 503 (`Service Unavailable`).
  - Redis limiter outage: Generic HTTP 503 (`Service Unavailable`).
  - IP abuse threshold exceeded: Generic HTTP 429 (`Too Many Requests`).

### 12.5 Principal Separation & Immutability
- **Request Principal:** Successful authentication attaches a frozen `VirtualKeyPrincipal` (`type: 'virtual_key'`) containing only `keyId`, `orgId`, and frozen `VirtualKeyPolicy` (`allowedModels`, `rpmLimit`, `tpmLimit`, `concurrentStreamLimit`, `exactCacheEnabled`, `semanticCacheEnabled`, `piiRedactionEnabled`, `storePayloads`).
- **Principal Isolation:** Virtual keys cannot authenticate as browser sessions or browser administrators. Browser session cookies are rejected on virtual-key routes.
- **Deny-All Semantics:** An empty `allowed_models` array (`[]`) is preserved and frozen; it indicates all models are denied by policy.

### 12.6 Architectural Limitation Notice (Phase 2 Admission Recheck)
- **Notice:** This pre-tenant authentication lookup resolves identity and initial policy only. It does **NOT** replace the Phase 2 requirement to execute durable row-locking (`SELECT ... FOR UPDATE`) and re-check the virtual-key record during transactional provider-attempt admission.
- **Revocation Window:** A virtual API key revoked after initial authentication lookup must be caught and rejected by the Phase 2 admission row lock before dispatching upstream provider attempts.

---

## 13. Admin-Only Virtual API Key Management & Policy Administration (SW-1.6.3)

Switchyard implements the control-plane administration layer for virtual API keys, enforcing browser-session admin authorization, tenant isolation, full-replacement policy safety, one-time plaintext key disclosure, and idempotent permanent revocation (Architecture v1.2 §4.1, §5.3, §11.6, §12.1–12.6, §13.1, §13.2–13.3, §13.5, §14.3, §16, §17.1, §21).

### 13.1 HTTP Management API Contracts

All management routes require a verified browser session and an administrative tenant role (`config.authz = { principal: 'browser', minRole: 'admin' }`). Mutations require a valid Origin and CSRF token.

| Method | Endpoint | Purpose | CSRF & Origin Required? | Success Status |
| :--- | :--- | :--- | :---: | :---: |
| `POST` | `/api/keys` | Create virtual API key and disclose plaintext raw key once | Yes | `201 Created` |
| `GET` | `/api/keys` | List organization-owned key metadata via keyset pagination | No (safe read) | `200 OK` |
| `PUT` | `/api/keys/:id/policy` | Atomically replace full mutable policy under row lock | Yes | `200 OK` |
| `DELETE` | `/api/keys/:id` | Logically revoke key permanently and idempotently | Yes | `204 No Content` |

### 13.2 Administrative Authorization & Principal Separation
- **Admin Only:** Organization members lacking the `admin` role are rejected with HTTP 403 (`Forbidden`).
- **Anonymous Access Denied:** Requests without a valid browser session cookie are rejected with HTTP 401 (`Unauthorized`).
- **Principal Separation:** Bearer-token credentials (e.g. `Authorization: Bearer <key>`) and conflicting browser credentials on management routes are rejected with HTTP 401. Data-plane virtual keys cannot manage keys.
- **Tenant Context Authority:** The organization ID is derived strictly from the authenticated browser principal (`req.principal.orgId`). User-provided `orgId` parameters in bodies, queries, or headers are prohibited and rejected.

### 13.3 CSRF & Canonical Origin Enforcement
- Mutating endpoints (`POST`, `PUT`, `DELETE`) require:
  - Exact match of the `Origin` header against the canonical gateway origin (`BROWSER_ORIGIN`).
  - Valid, unexpired browser session cookie: `__Host-session` in production (`Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`), or `switchyard_session` in development/test.
  - Valid `x-csrf-token` header containing a cryptographically random session-bound synchronizer token whose SHA-256 digest is stored server-side in `web_sessions` and compared in constant time.
- CSRF tokens from other sessions or organizations are rejected with HTTP 403.
- Mutating handlers never execute if CSRF or origin validation fails.

### 13.4 One-Time Key Disclosure & Browser Secret Boundary
- **Plaintext Disclosure:** The raw API key (`gw_live_<11>_<43>`) is disclosed exactly once in the `POST /api/keys` response body upon confirmed PostgreSQL transaction commit.
- **Cache Prevention:** All sensitive virtual-key management endpoints (`POST /api/keys`, `GET /api/keys`, `PUT /api/keys/:id/policy`, `DELETE /api/keys/:id`) return mandatory non-cacheable headers:
  - `Cache-Control: no-store` on all management responses
  - `Pragma: no-cache` additionally on key creation responses
- **Zero Raw Key Recovery:** Raw keys and verifier hashes (`key_hash`) are never stored in plaintext, never returned in list/update/revoke responses, and cannot be retrieved or recovered by administrators. If a key is lost, it must be revoked and replaced.
- **Browser-JavaScript Secret Exposure Constraint:** Browser JavaScript consuming the gateway API must not retain virtual keys long-term, and keys must never be stored in `localStorage`, `sessionStorage`, browser cookies, SSR hydration bundles, or analytics payloads.

### 13.5 Keyset Pagination & Tenant Isolation
- **Tenant Filter:** All database operations run inside `withTenant(pool, authenticatedOrgId)`. PostgreSQL's `FORCE ROW LEVEL SECURITY` policy on `virtual_keys` guarantees Tenant A cannot read, update, or revoke Tenant B keys. Cross-tenant lookups return generic external HTTP 404 responses identical to nonexistent keys, preserving tenant confidentiality.
- **Deterministic Ordering:** Keys are ordered by `created_at DESC, id DESC`.
- **Keyset Pagination:** Next pages are requested via an opaque base64url cursor containing `{ createdAt, id }`, where `createdAt` preserves exact microsecond UTC precision (`YYYY-MM-DDTHH:mm:ss.ffffffZ`). Keyset comparison `(created_at, id) < ($1::timestamptz, $2::uuid)` alongside composite tie-breaker `id DESC` guarantees stable pagination with zero duplicate or skipped keys across identical milliseconds or timestamps.
- **Bounded Page Size:** Query limit defaults to 20, with a strict maximum of 100. Arbitrary `OFFSET` queries and unbounded scans are prohibited.
- **Fail-Closed Cursors:** Malformed, tampered, non-canonical, or non-microsecond cursors return HTTP 400 validation errors rather than falling back to unbounded table scans.

### 13.6 Full-Replacement Policy Validation
The `PUT /api/keys/:id/policy` endpoint implements strict full-replacement semantics to prevent partial policy inheritance:
- **Model Allowlist (`allowedModels`):** Must be an array of non-empty strings (maximum 100 entries, maximum 128 characters per ID). Leading/trailing whitespace, control characters, duplicates, and wildcards (`*`) are rejected with HTTP 400. An empty array (`[]`) represents deny-all.
- **Numeric Limits (`rpmLimit`, `tpmLimit`, `concurrentStreamLimit`):** Must be positive, finite JavaScript safe integers between 1 and PostgreSQL's maximum 32-bit signed integer (`2147483647`). Zero, negative values, fractional values, numeric strings, and `NaN`/`Infinity` are rejected.
- **Privacy & Cache Flags:** `piiRedactionEnabled` and `storePayloads` must be explicit booleans.
- **Deferred Caching Guards:** Because caching is deferred (Architecture §16), setting `exactCacheEnabled: true` or `semanticCacheEnabled: true` is rejected with HTTP 400 until the respective features pass their own acceptance gates.

### 13.7 Logical Revocation & Row Locking Protocol
- **Logical Deletion:** `DELETE /api/keys/:id` sets `revoked_at = clock_timestamp()` under a row lock (`SELECT ... FOR UPDATE`). Rows and verifier hashes are preserved for auditing and attribution.
- **Idempotency:** Revoking an already-revoked key succeeds with HTTP 204 without modifying the original revocation timestamp.
- **Revocation Precedence:** A revoked key cannot receive policy updates (HTTP 409 Conflict).
- **Authentication Invalidation:** Once revoked, the key immediately fails SW-1.6.2 authentication with generic HTTP 401 (`KEY_REVOKED`).
- **Concurrency Serialization:** Competing revocation and policy update transactions serialize under PostgreSQL row locking. Once revocation commits, subsequent policy updates fail closed and cannot reactivate the key.

### 13.8 Architectural Limitation Notices
- **Deferred Model Capability Verification:** Syntactic validation of model identifiers does not verify that a model exists in provider pricing tables or is eligible for dispatch. Request admission in Phase 2 independently validates requested models against the capability registry.
- **Phase 2 Admission Recheck:** Revocation marks the database record. Phase 2 provider-attempt admission must acquire a row lock on `public.virtual_keys` and re-verify the key's revocation status at request dispatch time.

---

## 14. Virtual Key Revocation, Secret Secrecy & Phase 2 Integration Seam (SW-1.6.4)

Switchyard establishes comprehensive regression test suites, secret containment verification, and the normative Phase 2 provider-attempt admission integration seam (Architecture v1.2 §5.3, §6.1–6.3, §8.1–8.2, §11.6–11.8, §12.5, §13.1, §13.5, §14.3, §21).

### 14.1 Uniform External 401 Authentication Error Equivalence
Across twelve distinct invalid or revoked credential cases (missing header, empty header, unsupported schemes, missing bearer value, incorrect prefix, incorrect length, invalid base64url characters, noncanonical padding bits, well-formed unknown key, revoked key, browser session cookie on virtual-key route, conflicting cookie and bearer token), the Gateway returns the exact same external HTTP 401 response:
```json
{
  "statusCode": 401,
  "error": "Unauthorized",
  "message": "Authentication required"
}
```
- **Zero Protected Handler Executions:** Protected handlers never execute on invalid credentials.
- **No Principal Attaching:** Requests are terminated immediately at the preHandler stage without attaching a principal.
- **Zero Detail Leakage:** Internal failure causes (`KEY_REVOKED`, `KEY_NOT_FOUND`, `MALFORMED_KEY`, UUIDs, hints, or verifiers) are never exposed to external callers.

### 14.2 Permanent, Idempotent Revocation & Tenant Isolation
- **Logical Deletion:** Revocation updates `revoked_at` under an exclusive PostgreSQL row lock. Keys are never physically deleted, preserving audit and financial attribution.
- **Idempotency:** Repeated revocation succeeds (HTTP 204) without altering the original timestamp.
- **Immutability of Revocation:** Revoked keys reject policy replacement (HTTP 409) and cannot be reactivated through the public API.
- **Tenant Isolation:** Cross-tenant revocation returns generic HTTP 404 identical to nonexistent keys, and zero rows are affected.
- **Worker Isolation:** The runtime `gateway_worker` role is strictly denied `INSERT`, `UPDATE`, `REVOKE`, `DELETE`, and `lookup_virtual_key_by_hash` (SQLSTATE 42501).

### 14.3 Concurrency Serialization & Admission-Locking Protocol
Real PostgreSQL 16 row-locking (`SELECT ... FOR UPDATE`) tests verify serialization between revocation and simulated provider-attempt admission:
- **Scenario A (Revocation wins):** Transaction R locks and updates `revoked_at`. In-flight admission Transaction A blocks on the row lock, unblocks after commit, observes non-null `revoked_at`, and rejects admission fail-closed.
- **Scenario B (Admission wins):** Admission Transaction A acquires the row lock, verifies active key state, and blocks Transaction R until admission commits. Subsequent admissions reject.
- **Scenario C (Stale Principal):** An in-memory `VirtualKeyPrincipal` retained from a prior valid authentication fails admission once revocation commits, proving that authentication-time principals cannot substitute for admission-time PostgreSQL row checks.

### 14.4 Secret Secrecy Matrix & Canary Verification
Capturing structured application logs (Pino), HTTP response bodies, Redis keys, and PostgreSQL rows across 14 lifecycle operations within a single unified test stream confirms:
1. **Key Creation (Op 1):** Discloses `rawKey` once, sets `Cache-Control: no-store` and `Pragma: no-cache`, and discloses neither `key_hash` nor verifier bytes.
2. **Key Listing (Op 2):** Discloses non-secret metadata only.
3. **Policy Replacement (Op 3):** Modifies policy without disclosing secret credentials.
4. **Key Revocation (Op 4):** Revokes key logically (HTTP 204) without sensitive disclosure.
5. **Repeat Revocation (Op 5):** Idempotent repeat returns HTTP 204 without leaking state.
6. **Active Key Authentication (Op 6):** Authenticates data plane route (HTTP 200) cleanly.
7. **Unknown Key Authentication (Op 7):** Returns uniform HTTP 401 without detail leakage.
8. **Malformed Key Authentication (Op 8):** Returns uniform HTTP 401 without detail leakage.
9. **Revoked Key Authentication (Op 9):** Returns uniform HTTP 401 without detail leakage.
10. **Unauthorized Member Management (Op 10):** Enforces RBAC (HTTP 403) with zero secret leakage.
11. **Cross-Tenant Management (Op 11):** Enforces tenant isolation (HTTP 404) with zero leakage.
12. **Database Failure Canary (Op 12):** Deterministic database lookup failure routed through real authenticator returns controlled HTTP 503 with zero protected handler executions and zero driver error/connection leaks.
13. **Redis Limiter Failure Canary (Op 13):** Deterministic limiter failure routed through real authenticator returns controlled HTTP 503 with zero protected handler executions and zero connection leaks.
14. **Authentication Abuse Rejection (Op 14):** 31st request triggers rate limiting (HTTP 429) with zero handler executions.

All 13 post-creation response bodies and the comprehensive application log stream are verified to contain zero raw keys, zero secrets, zero session secrets, zero CSRF tokens, zero database credentials, zero connection URIs, and zero synthetic error canaries. Redis contains only normalized IP rate limiter keys (`auth:ratelimit:vk:ip:<ip>`), and PostgreSQL persists only the 32-byte SHA-256 verifier (`key_hash BYTEA UNIQUE`).

### 14.5 Normative Phase 2 Handoff Reference
The full architectural handoff document is committed at:
[`docs/architecture/phase2-admission-key-recheck.md`](./architecture/phase2-admission-key-recheck.md)
tracking the mandatory implementation dependencies across Phase 2:
- **SW-2.1.1 & SW-2.1.2:** Single-pass streaming proxy & request-dispatch state machine.
- **SW-2.2.3:** Gateway-instance epoch validation & provider-attempt pre-dispatch admission checks (`SELECT ... FOR UPDATE` with `gateway_control` epoch fence).
- **SW-2.4.1:** Multi-tier rate limiting & speculative Redis reservation (`RESERVE`).
- **SW-2.4.4:** Two-phase financial settlement, fail-closed reconciliation, and reservation cancellation (`CANCEL_RESERVATION`).
- **SW-2.5.1 – SW-2.5.3:** Upstream dispatch guards & hard deadline enforcement.
- **SW-2.6.2:** Upstream dispatch pipeline integration.
- **SW-2.8.3:** Reconciliation worker for unsettled reservations under commit uncertainty.

## 15. Provider Credential Envelope Encryption (SW-1.7.1 & SW-1.7.2)

Status: **IMPLEMENTED** — cryptographic baseline.

### 15.1 Cryptographic Contract
- **Algorithms:** AES-256-GCM for both DEK wrapping and provider-credential encryption. Key length is exactly 32 bytes, IV length exactly 12 bytes, authentication tag length exactly 16 bytes.
- **Organization DEKs:** Every organization receives an independent 32-byte DEK from `crypto.randomBytes()`. DEKs are never derived from organization UUIDs, names, passwords, virtual keys, or provider credentials.
- **Versioned KEKs:** `MASTER_KEK_V1`, `MASTER_KEK_V2`, and `ACTIVE_KEK_VERSION` are validated by the central Zod configuration module. KEKs are canonical unpadded base64url strings encoding exactly 32 bytes (43 characters). Padded, noncanonical, malformed, all-zero, duplicate-across-versions, and active-version-missing configurations fail closed.
- **Blob format:** `organizations.wrapped_dek` and `provider_keys.ciphertext` begin with the one-byte format marker `0x01`; the IV and authentication tag remain in their dedicated columns. `organizations.kek_version` is the authoritative KEK selector.
- **Exact AAD:** DEK wrapping uses `dek:<org_id>:v<kek_version>`; provider encryption uses `pk:<org_id>:<provider_key_id>:<provider>`. Organization labels, provider hints, and display names are never authenticated metadata.
- **Supported provider:** Only `openai` is accepted in this work package. The existing database CHECK constraint is unchanged.

### 15.2 Configuration and Failure Behavior
- No KEK configuration leaves the vault uninitialised so existing Gateway startup and non-vault tests remain compatible.
- Supplying any KEK value requires a valid `ACTIVE_KEK_VERSION` and a valid key for that version. Construction without valid material throws `VaultError(CONFIGURATION_ERROR)`.
- No default, development, placeholder, or arbitrary fallback KEK is ever selected. Missing historical KEKs cause `UNKNOWN_KEK_VERSION`; they are never replaced by another configured version.
- SW-1.7.3 requires valid KEK configuration before provider-credential management routes are enabled. There is no unencrypted or vault-disabled credential fallback.

### 15.3 Tenant, Tamper and Substitution Resistance
- Authenticated decryption fails when ciphertext is moved across organizations, provider-key record IDs, providers, IVs, tags, or wrapped-DEK envelopes.
- Organization envelope AAD binds the canonical lowercase organization UUID and stored KEK version. Provider AAD binds the organization UUID, provider-key UUID, and provider identifier.
- Malformed lengths, unknown format markers, truncated ciphertext, and invalid stored KEK versions are rejected as `UNSUPPORTED_FORMAT` before authentication is attempted.
- Cross-tenant reads remain denied by FORCE RLS under `withTenant()`. `gateway_worker` retains only non-secret metadata grants; selecting `wrapped_dek`, `dek_iv`, `dek_auth_tag`, `ciphertext`, `iv`, or `auth_tag` fails with SQLSTATE `42501`.

### 15.4 Memory and Privacy Limitations
- The keyring never returns a mutable reference to its process-lifetime KEK material. `KekKeyring.resolve()` returns an independent copy, and the vault performs cryptographic operations through `withKey()`, which clears that copy in a `finally` block on success and every exception path. Callers of `resolve()` directly must clear the returned copy after use.
- Temporary mutable DEK buffers and intermediate decryption chunks are cleared with `.fill(0)` after successful operations and on authentication failure. The final plaintext Buffer returned to the caller is a separate allocation and remains intact until the caller clears it.
- Callers own plaintext input Buffers and returned decrypted Buffers and must clear them after authorised use.
- JavaScript strings and runtime copies cannot be deterministically zeroized. Best-effort buffer clearing does not protect against heap snapshots, process compromise, copied buffers, or a compromised Node.js runtime.
- Plaintext provider credentials, KEKs, and DEKs are never persisted in PostgreSQL, Redis, BullMQ, traces, Pino logs, error messages, or browser responses. Pino redaction explicitly covers `MASTER_KEK_*`, `wrapped_dek`, `dek_iv`, and `dek_auth_tag` naming variants.

---

## 16. Provider Credential Vault Completion, Administration & Security Hardening (SW-1.7.3 & SW-1.7.4)

Status: **IMPLEMENTED** — complete provider credential management APIs, decrypt-path memory scrubbing verification, log privacy probes, and backup/rotation compatibility specifications.

### 16.1 Admin-Only Provider Credential Management APIs (SW-1.7.3)

Switchyard exposes administrative REST endpoints under `/api/provider-keys` for organization-owned provider credential lifecycle management:

```text
POST   /api/provider-keys        # Create encrypted provider credential
GET    /api/provider-keys        # List safe metadata with keyset pagination
PUT    /api/provider-keys/:id    # Atomically replace credential
DELETE /api/provider-keys/:id    # Disable credential (soft delete)
```

#### 16.1.1 Authorization & Principal Separation
- **Admin-Only Requirement:** Declares `config: { authz: { principal: 'browser', minRole: 'admin' } }`. Non-admin members receive HTTP 403 (`Forbidden`); anonymous callers receive HTTP 401 (`Unauthorized`).
- **Principal Separation:** Data-plane virtual API keys (`Bearer sw_vk_...`) cannot access management endpoints. Requests bearing virtual key authorization headers receive HTTP 401.
- **Tenant Context Authority:** The tenant identity is derived strictly from the authenticated browser session (`req.principal.orgId`). Client-supplied organization IDs in request bodies, URL paths, query parameters, or headers are prohibited and rejected.

#### 16.1.2 Origin & CSRF Protection
- Mutating operations (`POST`, `PUT`, `DELETE`) strictly enforce canonical `Origin` matching `BROWSER_ORIGIN` and constant-time verification of session-bound synchronizer tokens in `x-csrf-token`.
- Requests with mismatched, missing, or forged CSRF tokens or untrusted origins are terminated before handler execution with HTTP 403.

#### 16.1.3 Strict Request Validation, Unicode Well-Formedness & Diagnostic Safety
- Request bodies require strict JSON object formatting. Unexpected properties, duplicate headers, or query parameters on `POST`, `PUT`, and `DELETE` trigger immediate HTTP 400 (`Bad Request`) validation failures.
- **Supported Providers:** Restricted strictly to `openai`. Unrecognized providers are rejected with a static HTTP 400 message (`Unsupported provider: only "openai" is currently supported`). Untrusted provider values are never reflected in error messages.
- **Key ID Validation:** Canonical UUID validation (`validateKeyId`) rejects malformed UUIDs with a static HTTP 400 message (`Invalid key ID: malformed UUID`) without reflecting untrusted input.
- **Label Validation:** 1 to 255 UTF-8 bytes; non-empty, non-whitespace, with prohibited control characters rejected.
- **Unicode Well-Formedness & Credential Limits:** 1 to 4096 UTF-8 bytes. Validated via `isWellFormedUnicode()` to ensure only well-formed Unicode scalar sequences are accepted before conversion to a Buffer; isolated high surrogates, isolated low surrogates, and malformed surrogate ordering are rejected fail-closed with HTTP 400 (`Invalid credential: malformed Unicode sequence`). Exact credential content is preserved without trimming or normalization.
- **Error Secrecy:** Malformed, invalid, or oversized credentials and untrusted input values are never echoed in HTTP error responses or logs.

#### 16.1.4 Safe Key Hint Derivation (§11.5)
- For credentials exceeding 4 characters, the service derives a hint consisting of fixed prefix `****` followed by at most the last 4 sanitized display characters (e.g. `****3456`). Control characters (C0 controls U+0000..U+001F, DEL U+007F, and C1 controls U+0080..U+009F) are globally stripped from the hint via `CONTROL_CHARS_GLOBAL_REGEX`, ensuring multiple control characters and embedded NUL bytes cannot survive or cause PostgreSQL text column persistence errors (PVAULT-07).
- For short credentials (4 or fewer characters), the hint returns entirely masked `****` to prevent disclosing key length or secret values.
- Key hints are computed in-memory; plaintext credential prefixes are never stored. The exact opaque credential bytes remain encryptable and decryptable without modification or normalization.

#### 16.1.5 Bounded Keyset Pagination & Safe Metadata
- `GET /api/provider-keys` queries keys inside `withTenant(pool, orgId)` ordered by `created_at DESC, id DESC`.
- Keyset pagination uses opaque canonical base64url cursors `{ createdAt, id }` with microsecond UTC precision (`YYYY-MM-DDTHH:mm:ss.ffffffZ`).
- Limit is bounded between 1 and 100 (default 20).
- **Zero Decryption & Zero Secret Selection:** The SQL query selects non-secret columns only (`id`, `provider`, `label`, `key_hint`, `is_active`, `created_at`). `ciphertext`, `iv`, `auth_tag`, `wrapped_dek`, `dek_iv`, `dek_auth_tag`, and `kek_version` are never selected or exposed.
- **Route-Scoped Cache-Control Headers (PVAULT-09 Part A):** Encapsulated via an `onSend` lifecycle hook on the `/api/provider-keys` plugin scope, all responses from provider-key management routes unconditionally include `Cache-Control: no-store` and `Pragma: no-cache`. This header guarantee covers 200, 201, 204, 400, pre-handler 401 Unauthorized, pre-handler 403 Forbidden (both non-admin member role and CSRF/Origin rejections), 404, 409, and 503, without polluting unrelated Gateway routes.

#### 16.1.6 Atomic Replacement, Concurrency & Rollback Guarantees
- `PUT /api/provider-keys/:id` acquires a row lock (`SELECT ... FOR UPDATE`) inside the tenant transaction.
- Attempting to replace a disabled credential (`is_active = false`) fails closed with HTTP 409 (`Conflict`).
- Organization ownership and provider identity cannot be modified.
- Generates a fresh random 12-byte IV and fresh 16-byte authentication tag through `EnvelopeVault.encryptProviderCredential`, updates the row atomically, and returns safe metadata only.
- **Deterministic Concurrency Serialization (Real PostgreSQL 16 Suite):**
  - **C1 (Replace vs Replace):** Two competing replacements serialize deterministically under row locking without mixed fields; the winning replacement commits atomically and decrypts byte-identically.
  - **C2 (Disable before Replace):** When a disable transaction holds the row lock, a competing replacement blocks until disable commits, re-evaluates `is_active = false`, and rejects with HTTP 409 Conflict without reactivating the credential.
  - **C3 (Replace before Disable):** When a replacement transaction holds the row lock, a competing disable blocks until replacement commits, then proceeds to deactivate the updated record.
  - **C4 (Failed Replacement Rollback):** An aborted/rolled-back replacement transaction leaves the previous ciphertext, IV, authentication tag, label, hint, and decryptability completely intact.
  - **C5 (Cross-Tenant Concurrency Resistance):** Tenant B cannot exploit concurrent mutation timing to replace or disable Tenant A's credential; PostgreSQL FORCE RLS isolates tenant rows unconditionally.
  - **C6 (Service-Level Replacement Rollback - PVAULT-08):** Exercises the production `ProviderKeyManagementService.replaceKey()` transaction path under `withTenant(pool, orgId)`. Injects a controlled PostgreSQL failure during the replacement `UPDATE` before commit; proves that `replaceKey` reports failure, the previous database row (label, hint, ciphertext, IV, authentication tag, is_active) remains completely unchanged, the previous credential still decrypts byte-identically, and tenant connection context cleans up so subsequent valid service operations succeed normally.

#### 16.1.7 Logical Disabling & Idempotency
- `DELETE /api/provider-keys/:id` acquires a row lock and sets `is_active = false`.
- Encrypted ciphertext and tags are preserved; credentials are not decrypted or deleted from disk.
- Repeated disable requests succeed idempotently with HTTP 204 (`No Content`).
- Cross-tenant and nonexistent IDs return HTTP 404 with zero modified rows.

#### 16.1.8 Startup & Consistent KEK Configuration Gating (PVAULT-01)
- Provider-key routes are registered at startup. Non-vault Gateway operations (health checks, virtual keys, gateway proxy) start and run cleanly when all KEK environment variables are absent.
- When the vault is uninitialized or unavailable, all four provider-credential management operations (`POST`, `PUT`, `GET`, `DELETE`) fail safely and consistently with HTTP 503 (`Service Unavailable`: "Provider credential vault is unavailable").
- Authentication, RBAC, and CSRF gates are evaluated prior to route handler execution: anonymous callers receive HTTP 401 (`Unauthorized`) and member-role callers receive HTTP 403 (`Forbidden`), preventing configuration disclosure to unauthenticated or unauthorized callers.
- Invalid KEK configuration continues to fail closed during central Zod configuration parsing at startup.

### 16.2 Decrypt-Path Scrubbing & Privacy Verification (SW-1.7.4)

#### 16.2.1 Memory Scrubbing & Buffer Hygiene
- In `ProviderKeyManagementService`, caller credentials are converted into temporary Node.js `Buffer` instances and wiped in a `finally` block via `.fill(0)` on both successful creation/replacement and all exception paths. Unit test instrumentation tracking allocated Buffer instances independently verifies that every allocated temporary buffer is zeroized (`every(byte === 0)`).
- In `EnvelopeVault`, intermediate AES-GCM decipher chunks and unwrap buffers are zeroized in `finally` blocks upon both successful completion and authentication failures (comprehensively verified with chunk capture spies in `apps/gateway/src/vault/envelope.test.ts`).
- The returned plaintext Buffer from internal gateway decryption is caller-owned and must be zeroized by the caller immediately after authorized upstream dispatch.
- **Node.js Runtime Limitation Disclosure:** While mutable Buffers are zeroized, immutable V8 JavaScript strings (instantiated during JSON body parsing) cannot be deterministically cleared by application code and persist until garbage collected. This architectural boundary is mitigated by bounded body limits, absence of request-body logging, and non-root process sandboxing.

#### 16.2.2 Real Request / Log Privacy & Canary Probes (PVAULT-04 Part C, PVAULT-09 Part B)
- Route-level privacy tests (`apps/gateway/src/routes/provider-keys.test.ts`) exercise the Fastify request pipeline for `/api/provider-keys` across success (201), service failure (503), and payload validation error (400) under real Fastify `onRequest` and `onResponse` lifecycle logging hooks with captured Pino structured log output.
- The test actively asserts that structured log events are captured (`capturedLogLines.length >= 6`), proving the logger was genuinely exercised and preventing vacuous test passes.
- Synthetic canary credentials (`CANARY_SECRET_*`) are verified to be completely absent from captured application log lines, structured metadata fields, serialized HTTP responses, and safe error objects.
- In addition, real PostgreSQL database integration privacy tests (`provider-key-management.db.test.ts` test B5) verify that service-level execution and error pathways never leak canary strings.
- Pino redaction explicitly covers `credential`, `credentials`, `providerkey`, `key`, `password`, `token`, `secret`, `kek`, `dek`.

#### 16.2.3 Worker Role Isolation Proven
- Real PostgreSQL role tests confirm that `gateway_worker` is denied `SELECT` privileges on:
  - `provider_keys.ciphertext`, `provider_keys.iv`, `provider_keys.auth_tag` (SQLSTATE `42501`)
  - `organizations.wrapped_dek`, `organizations.dek_iv`, `organizations.dek_auth_tag` (SQLSTATE `42501`)
- Background worker processes possess neither KEKs nor DEKs and can never read or decrypt provider secrets.

### 16.3 Backup, Retention & Future KEK Rotation Compatibility (SW-1.7.4)

#### 16.3.1 Database Backup Compatibility Constraints
1. **Coupled Backup Requirement:** PostgreSQL database backups contain only wrapped DEKs and encrypted provider credentials. Restoring a database backup without the corresponding historical KEKs makes provider credentials permanently undecryptable.
2. **Version Metadata Consistency:** Restored rows in `organizations` reference specific `kek_version` values. The KEK configuration in the target environment must include the historical KEK corresponding to each restored tenant record.
3. **Identity Binding & AAD Immutability:** Ciphertext authentication tags depend on authenticated associated data:
   - Organization DEK: `dek:<org_id>:v<kek_version>`
   - Provider credential: `pk:<org_id>:<provider_key_id>:<provider>`
   Restoring records under different organization IDs, provider-key IDs, or provider identifiers causes AES-GCM authentication failure. Records cannot be copied or transplanted between tenants.
4. **Coordinated Retention:** Database backup retention schedules must be synchronized with KEK retention schedules.

#### 16.3.2 Historical KEK Retention Requirements
- Architecture v1.2 §14.2 requires historical KEKs to remain recoverable offline for at least the full database backup retention window (e.g. 30, 90, or 365 days depending on deployment policy).
- Deleting an old KEK while database backups referencing that version still exist renders those backups permanently irrecoverable.
- Loss of all secure copies of a KEK version causes total, irreversible loss of all credentials encrypted under that version.
- Historical KEKs must be archived in secure, access-controlled offline storage and never committed to source control.
- Environment-variable backed KEKs provide envelope confidentiality at rest; they are not equivalent to hardware security modules (HSM) or cloud KMS key policies.

#### 16.3.3 Future KEK Rotation Compatibility & Operational Constraints
Architecture v1.2 §14.2 specifies two-tier envelope encryption specifically to enable zero-downtime KEK rotation without re-encrypting provider credentials:
1. **DEK Rewrapping (Target Implementation):**
   - KEK rotation rewraps the 32-byte organization DEK only. Individual `provider_keys` rows remain unchanged.
   - For each organization, unwrap `wrapped_dek` using historical KEK version `v_old`, generate a fresh 12-byte IV, re-encrypt the DEK with active KEK version `v_new`, and generate a fresh authentication tag.
   - Persist update atomically using compare-and-swap:
     ```sql
     UPDATE organizations
     SET wrapped_dek = $1, dek_iv = $2, dek_auth_tag = $3, kek_version = $4
     WHERE id = $5 AND kek_version = $6;
     ```
2. **Batching & Idempotency:** The rotation migration must process organizations in bounded, configurable batches with deterministic transaction boundaries and retry safety.
3. **Verification Before Deprecation:** An old KEK version must not be retired until a full-table query confirms zero rows in `organizations` remain at the old `kek_version`.
4. **Distinction Between Implemented vs Future Work:**
   - **Current Implementation:** Versioned KEK environment parsing, multi-version keyring coexistence (`MASTER_KEK_V1` and `MASTER_KEK_V2`), version-directed decryption, and historical compatibility verification.
   - **Not Implemented in Current Release:** Automated KEK rotation CLI, background rewrapping workers, automated backup restoration tooling, and DEK rotation.
5. **DEK Rotation Distinction:**
   - KEK rotation changes the wrapping key of the organization DEK (metadata update on `organizations`).
   - DEK rotation replaces the organization DEK itself, requiring every provider credential of that organization to be decrypted and re-encrypted with fresh IVs. DEK rotation is not authorized or implemented.

---

## 17. Worker and Web Runtime Security Boundaries (SW-P1-B01)

Switchyard establishes strict security boundaries between the Gateway, Worker, and Web services (Architecture v1.2 §§12.1, 12.5, 19.1, 19.4, 20.1, 23.1).

### 17.1 Worker Runtime Least Privilege & Isolation

1. **Process Separation:**
   - The worker runs as an independent daemon (`node apps/gateway/dist/worker-main.js`) separated from the Gateway API process.
   - It exposes zero network ports (`ports: []`), published host ports, or HTTP listeners.
   - Liveness/readiness is monitored via unprivileged local CLI probe (`node apps/gateway/dist/worker-main.js --health`) checking heartbeat age (<15s) and process liveness via PID signal probing (`process.kill(pid, 0)`).

2. **PostgreSQL Role Boundary (`gateway_worker`):**
   - Must connect strictly as `gateway_worker` (rejects superuser, `usesuper = false`, `rolbypassrls = false`).
   - Strictly denied access to singleton control state: `SELECT 1 FROM gateway_control` throws SQLSTATE `42501` (permission denied).
   - Denied access to sensitive vault columns: `provider_keys.ciphertext`, `provider_keys.iv`, `provider_keys.auth_tag`, `organizations.wrapped_dek`, `organizations.dek_iv`, and `organizations.dek_auth_tag` all throw SQLSTATE `42501`.
   - Denied `INSERT` / `UPDATE` on `virtual_keys` and direct execution of privileged auth functions.

3. **Redis ACL Identity (`switchyard_worker`):**
   - Enforces a restricted Redis identity `switchyard_worker` configured with `-@all +ping +info +acl|whoami`.
   - Prohibited from destructive, operational, and data commands (`FLUSHALL`, `FLUSHDB`, `CONFIG`, `KEYS`, `DEBUG`, `SHUTDOWN`, `REPLICAOF`, `ACL LIST`).
   - Startup fails closed if connected as the unrestricted `default` user or if prohibited commands are permitted.

4. **Credential Isolation:**
   - Worker configuration validator (`workerConfigSchema`) rejects all vault key variables (`MASTER_KEK_*`, `ACTIVE_KEK_VERSION`).
   - Security bypass flags (`BYPASS_RLS`, etc.) are unconditionally rejected.

### 17.2 Web Frontend Runtime Security Boundary

1. **Unprivileged Container Runtime:**
   - Runs as unprivileged `USER node` in a hardened multi-stage container (`docker/web/Dockerfile`).
   - Explicitly disables `x-powered-by` header.
   - Bound strictly to host loopback (`127.0.0.1:${WEB_PORT:-3001}:3001`), never wildcard `0.0.0.0`.

2. **No Data-Plane or Secret Exposure:**
   - Web container possesses zero database credentials (`POSTGRES_*`), zero Redis credentials (`REDIS_*`), and zero vault keys (`MASTER_KEK_*`).
   - Does not connect directly to PostgreSQL or Redis.
   - Health endpoint `/health/ready` reports static machine-readable readiness without fabricating unauthenticated dependencies.
