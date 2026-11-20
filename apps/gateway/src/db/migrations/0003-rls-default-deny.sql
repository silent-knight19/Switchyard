-- 0003-rls-default-deny.sql
-- Corrects the Batch A RLS posture (review finding DB-04).
--
-- 0002-org-tables.sql created two separate permissive policies per tenant table (one carrying
-- USING, one carrying WITH CHECK). PostgreSQL combines permissive policies with OR, so that
-- arrangement was not a validated tenant-isolation guarantee. Migration 0002 is already applied
-- in existing installations and is immutable, so this forward migration removes those policies
-- and leaves the tenant tables in a deliberate default-deny posture:
--
--   * RLS stays ENABLEd and FORCEd (FORCE also applies to the table owner).
--   * Zero policies exist, so every non-bypassing role sees no rows and can write none.
--   * No tenant-table privileges are granted to runtime roles in Batch A.
--
-- Comprehensive tenant policies, the tenant GUC helper, and per-role grants belong to
-- Subphase 1.4 (SW-1.4.1 RLS policies, SW-1.4.2 tenant context). Batch A does NOT claim tenant
-- isolation. Until 1.4 lands, the database is default-deny rather than permissive.

SET ROLE gateway_owner;

DROP POLICY IF EXISTS organizations_tenant_using ON organizations;
DROP POLICY IF EXISTS organizations_tenant_with_check ON organizations;
DROP POLICY IF EXISTS users_tenant_using ON users;
DROP POLICY IF EXISTS users_tenant_with_check ON users;
DROP POLICY IF EXISTS web_sessions_tenant_using ON web_sessions;
DROP POLICY IF EXISTS web_sessions_tenant_with_check ON web_sessions;
DROP POLICY IF EXISTS provider_keys_tenant_using ON provider_keys;
DROP POLICY IF EXISTS provider_keys_tenant_with_check ON provider_keys;
DROP POLICY IF EXISTS virtual_keys_tenant_using ON virtual_keys;
DROP POLICY IF EXISTS virtual_keys_tenant_with_check ON virtual_keys;

-- Re-assert the enforced posture (idempotent; also corrects a drifted upgraded installation).
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

-- No broad PUBLIC privileges on tenant data.
REVOKE ALL ON organizations, users, web_sessions, provider_keys, virtual_keys FROM PUBLIC;

RESET ROLE;
