-- 0006-schema-privilege-hardening.sql
-- Schema and table privilege hardening (review finding DB-09).
--
-- The privileged, superuser-only parts (REVOKE CREATE ON SCHEMA public FROM PUBLIC, schema
-- USAGE grants, and creation/ownership of app_private) live in
-- src/db/bootstrap/provision-roles.sql because gateway_migrator is not the owner of `public`
-- and must not be a superuser. This migration hardens what the tenant-table owner can harden:
--
--   * app_private is a protected namespace for future SECURITY DEFINER functions (§12.4).
--     PUBLIC has no privilege; runtime roles have USAGE only, never CREATE, so no runtime
--     principal can plant a shadow object on a future function search path.
--   * PUBLIC holds no privilege on any core table.

SET ROLE gateway_owner;

REVOKE ALL ON SCHEMA app_private FROM PUBLIC;
REVOKE CREATE ON SCHEMA app_private FROM PUBLIC;
GRANT USAGE ON SCHEMA app_private TO gateway_startup, gateway_app, gateway_worker,
  gateway_auth_executor, gateway_ops_executor;

REVOKE ALL ON organizations, users, web_sessions, provider_keys, virtual_keys, gateway_control
  FROM PUBLIC;

RESET ROLE;
