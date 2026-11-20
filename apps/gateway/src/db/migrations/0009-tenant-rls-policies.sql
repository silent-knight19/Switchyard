-- 0009-tenant-rls-policies.sql
-- Enforces row-level security (RLS) tenant isolation policies and restricted role grants
-- across all nine tenant-owned tables (Architecture v1.2 §§5.3, 11.1–11.10, 12.1–12.6, 19.2).
--
-- This forward-only migration resolves review finding DB-04 permanently by defining exactly one
-- unified permissive policy per table with both USING and WITH CHECK, eliminating permissive
-- OR-composition bypass risks.
--
-- Runtime privileges follow the principle of least privilege:
--   * gateway_app:    Fastify Gateway runtime; tenant-scoped queries and provider-secret access.
--   * gateway_worker: Background jobs; attempt/trace work; no KEK/DEK or provider credential access.
--   * gateway_startup: No tenant-table privileges (maintains gateway_control access only).
--   * PUBLIC:         No privileges on any tenant-owned table.

SET ROLE gateway_owner;

-- 1. Ensure ENABLE + FORCE RLS is set on all nine tenant tables (§12.3)
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

ALTER TABLE web_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE web_sessions FORCE ROW LEVEL SECURITY;

ALTER TABLE provider_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_keys FORCE ROW LEVEL SECURITY;

ALTER TABLE virtual_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE virtual_keys FORCE ROW LEVEL SECURITY;

ALTER TABLE gateway_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_requests FORCE ROW LEVEL SECURITY;

ALTER TABLE provider_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_attempts FORCE ROW LEVEL SECURITY;

ALTER TABLE provider_cost_adjustments ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_cost_adjustments FORCE ROW LEVEL SECURITY;

ALTER TABLE trace_payloads ENABLE ROW LEVEL SECURITY;
ALTER TABLE trace_payloads FORCE ROW LEVEL SECURITY;

-- 2. Clean up any prior tenant policies
DROP POLICY IF EXISTS organizations_tenant_isolation ON organizations;
DROP POLICY IF EXISTS users_tenant_isolation ON users;
DROP POLICY IF EXISTS web_sessions_tenant_isolation ON web_sessions;
DROP POLICY IF EXISTS provider_keys_tenant_isolation ON provider_keys;
DROP POLICY IF EXISTS virtual_keys_tenant_isolation ON virtual_keys;
DROP POLICY IF EXISTS gateway_requests_tenant_isolation ON gateway_requests;
DROP POLICY IF EXISTS provider_attempts_tenant_isolation ON provider_attempts;
DROP POLICY IF EXISTS provider_cost_adjustments_tenant_isolation ON provider_cost_adjustments;
DROP POLICY IF EXISTS trace_payloads_tenant_isolation ON trace_payloads;

-- 3. Unified tenant isolation policies (one policy per table; avoids permissive OR bypass)
CREATE POLICY organizations_tenant_isolation ON organizations
  AS PERMISSIVE
  FOR ALL
  TO PUBLIC
  USING (id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
  WITH CHECK (id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);

CREATE POLICY users_tenant_isolation ON users
  AS PERMISSIVE
  FOR ALL
  TO PUBLIC
  USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);

CREATE POLICY web_sessions_tenant_isolation ON web_sessions
  AS PERMISSIVE
  FOR ALL
  TO PUBLIC
  USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);

CREATE POLICY provider_keys_tenant_isolation ON provider_keys
  AS PERMISSIVE
  FOR ALL
  TO PUBLIC
  USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);

CREATE POLICY virtual_keys_tenant_isolation ON virtual_keys
  AS PERMISSIVE
  FOR ALL
  TO PUBLIC
  USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);

CREATE POLICY gateway_requests_tenant_isolation ON gateway_requests
  AS PERMISSIVE
  FOR ALL
  TO PUBLIC
  USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);

CREATE POLICY provider_attempts_tenant_isolation ON provider_attempts
  AS PERMISSIVE
  FOR ALL
  TO PUBLIC
  USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);

CREATE POLICY provider_cost_adjustments_tenant_isolation ON provider_cost_adjustments
  AS PERMISSIVE
  FOR ALL
  TO PUBLIC
  USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);

CREATE POLICY trace_payloads_tenant_isolation ON trace_payloads
  AS PERMISSIVE
  FOR ALL
  TO PUBLIC
  USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);

-- 4. Revoke all privileges on tenant tables from PUBLIC, startup, app, and worker roles
REVOKE ALL ON organizations, users, web_sessions, provider_keys, virtual_keys,
  gateway_requests, provider_attempts, provider_cost_adjustments, trace_payloads
  FROM PUBLIC, gateway_startup, gateway_app, gateway_worker;

-- 5. Least-privilege role grants (§12.1, §12.3, §19.4)

-- gateway_app: full tenant data-plane and control-plane operation
GRANT SELECT, INSERT, UPDATE ON organizations TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON web_sessions TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON provider_keys TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON virtual_keys TO gateway_app;
GRANT SELECT, INSERT, UPDATE ON gateway_requests TO gateway_app;
GRANT SELECT, INSERT, UPDATE ON provider_attempts TO gateway_app;
GRANT SELECT, INSERT ON provider_cost_adjustments TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON trace_payloads TO gateway_app;

-- gateway_worker: background maintenance, attempt recovery, and trace pruning
-- Non-secret organization metadata only (wrapped_dek, dek_iv, dek_auth_tag STRICTLY EXCLUDED)
GRANT SELECT (id, name, monthly_budget_microdollars, kek_version, created_at) ON organizations TO gateway_worker;

-- Non-secret provider key metadata only (ciphertext, iv, auth_tag STRICTLY EXCLUDED)
GRANT SELECT (id, org_id, provider, label, key_hint, is_active, created_at) ON provider_keys TO gateway_worker;

-- Virtual keys read-only access for attribution
GRANT SELECT ON virtual_keys TO gateway_worker;

-- Request recovery and finalization updates (no DELETE on financial records)
GRANT SELECT, UPDATE (status, http_status, error_code, finalized_at) ON gateway_requests TO gateway_worker;

-- Attempt settlement and recovery updates (no DELETE on financial records)
GRANT SELECT, UPDATE (status, outcome, tokens_in, tokens_out, duration_ms, http_status, actual_cost_microdollars, cost_status, settled_at) ON provider_attempts TO gateway_worker;

-- Cost adjustments insertion (append-only, no UPDATE, no DELETE)
GRANT SELECT, INSERT ON provider_cost_adjustments TO gateway_worker;

-- Trace payloads observability and retention pruning
GRANT SELECT, INSERT, UPDATE, DELETE ON trace_payloads TO gateway_worker;

RESET ROLE;
