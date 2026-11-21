# ADR 0001: Restricted Pre-Tenant Session Lookup Function

- **Status:** ACCEPTED
- **Date:** 2026-11-21
- **Deciders:** Project Owner, Principal Architect
- **Consulted:** Antigravity IDE (Implementation Agent)
- **Informed:** Core Engineering Team

---

## 1. Context

Architecture v1.2 §12.3 and §12.4 establish tenant isolation using PostgreSQL Row-Level Security (RLS) with `FORCE ROW LEVEL SECURITY` on all tenant-owned tables, including `public.web_sessions`. The table policy restricts rows to the active tenant context:

```sql
USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
```

In the browser control plane, incoming HTTP requests supply an opaque session cookie (`__Host-session=<secret>`). Before authentication and session validation, the Gateway does not know which organization (`org_id`) the session belongs to. Because `gateway_app` does not hold `BYPASSRLS`, querying `web_sessions` without an active `app.current_org_id` returns zero rows.

Architecture v1.2 §12.4 defined three pre-tenant authentication functions:
1. `app_private.lookup_virtual_key_by_hash(p_key_hash)`
2. `app_private.lookup_user_for_login(p_email_normalized)`
3. `app_private.create_organization_with_admin(...)`

However, no function was established for pre-tenant browser session resolution.

---

## 2. Decision

Introduce a forward-only migration `0011-session-tenant-lookup.sql` defining exactly one privileged `SECURITY DEFINER` function:

```sql
app_private.lookup_session_org_by_hash(p_session_id_hash BYTEA)
RETURNS TABLE (org_id UUID)
```

### Privileged Contract & Invariants

1. **Ownership:** Owned strictly by `gateway_auth_executor` (`NOLOGIN BYPASSRLS`).
2. **Execution Privilege:** Granted strictly to `gateway_app`. Denied to `gateway_worker`, `gateway_startup`, and `PUBLIC`.
3. **Least Privilege Schema Access:** `gateway_auth_executor` receives column-level SELECT access only on `public.web_sessions(session_id_hash, org_id)`.
4. **Input Constraints:** Accepts exactly a 32-byte SHA-256 session hash. Rejects NULL, empty, or wrong-length byte sequences fail-closed by returning zero rows.
5. **Output Minimization:** Projects **only** `org_id UUID`. Does not return `user_id`, `csrf_token_hash`, `idle_expires_at`, `revoked_at`, or any session metadata.
6. **Hardened Execution Environment:** Executes with `SECURITY DEFINER` and a fixed, trusted search path:
   ```sql
   SET search_path = pg_catalog, app_private, pg_temp
   ```
7. **Routing Context Only:** The resolved `org_id` provides routing context to enter `withTenant(org_id, ...)`. It does **not** grant authorization. Full validation (user status, expiry, revocation, CSRF token) is executed within the tenant-isolated transaction.

---

## 3. Alternatives Considered

1. **Client-Supplied Tenant Header or Multi-Part Cookie (`<org_id>.<secret>`):**
   *Rejected.* Trusting client-supplied tenant claims to initialize `withTenant` introduces identity ambiguity and potential cross-tenant confusion prior to credential verification.
2. **Granting `BYPASSRLS` or Cross-Tenant SELECT to `gateway_app`:**
   *Rejected.* Breaches the non-negotiable architectural invariant that `gateway_app` must never bypass RLS.
3. **Redis-Backed Session Index (`session_hash -> { orgId, userId }`):**
   *Rejected.* Breaches Architecture v1.2 §13.1 and §13.2 specifying PostgreSQL as the authoritative single source of truth for sessions, and introduces cache-invalidation and revocation desynchronization risks.

---

## 4. Consequences

- **Positive:**
  - Maintains strict `FORCE ROW LEVEL SECURITY` on `public.web_sessions`.
  - Prevents untrusted client input from choosing tenant boundaries.
  - Consistent with the established `lookup_virtual_key_by_hash` pattern in SW-1.4.3.
  - Restricts privileged data leakage to the single tenant identifier needed for context routing.
- **Negative / Operational Requirements:**
  - Requires migration `0011-session-tenant-lookup.sql`.
  - Requires two-stage session validation (pre-tenant organization resolution followed by in-tenant full session validation).
