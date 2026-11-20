-- provision-roles.sql
-- One-time privileged PostgreSQL role provisioning for Switchyard (Architecture v1.2 §12.1).
--
-- Run as a PostgreSQL superuser (or a role with CREATEROLE plus ownership of the `public`
-- schema) exactly once per cluster/database, BEFORE the first `migrate` run. Ordinary schema
-- migrations never create roles: `gateway_migrator` has no CREATEROLE privilege and must not
-- receive one. This script is idempotent and re-asserts the security attributes of each role,
-- so it is also the reconciliation path if a role drifted.
--
-- Role passwords are NOT set here. The operator sets deployment credentials separately
-- (`ALTER ROLE ... PASSWORD ...` or the platform secret manager) per §19.2.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_owner') THEN
    CREATE ROLE gateway_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_migrator') THEN
    CREATE ROLE gateway_migrator LOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_startup') THEN
    CREATE ROLE gateway_startup LOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_app') THEN
    CREATE ROLE gateway_app LOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_worker') THEN
    CREATE ROLE gateway_worker LOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_auth_executor') THEN
    CREATE ROLE gateway_auth_executor NOLOGIN BYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_ops_executor') THEN
    CREATE ROLE gateway_ops_executor NOLOGIN BYPASSRLS;
  END IF;
END $$;

-- Re-assert least privilege (idempotent; corrects a drifted role instead of trusting it).
ALTER ROLE gateway_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE gateway_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE gateway_startup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE gateway_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE gateway_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE gateway_auth_executor NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
ALTER ROLE gateway_ops_executor NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;

-- The deployment role owns schema migrations and may assume the tenant-table owner (§12.1).
GRANT gateway_owner TO gateway_migrator;

-- Schema privileges: no CREATE for PUBLIC, migration roles only.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO gateway_owner, gateway_migrator;
GRANT USAGE ON SCHEMA public TO gateway_startup, gateway_app, gateway_worker;

-- Protected namespace reserved for future SECURITY DEFINER functions (§12.4). No runtime role
-- receives CREATE here; the owning role is gateway_owner until executor-owned functions exist.
CREATE SCHEMA IF NOT EXISTS app_private AUTHORIZATION gateway_owner;
ALTER SCHEMA app_private OWNER TO gateway_owner;
REVOKE ALL ON SCHEMA app_private FROM PUBLIC;
GRANT USAGE ON SCHEMA app_private TO gateway_startup, gateway_app, gateway_worker,
  gateway_auth_executor, gateway_ops_executor;
