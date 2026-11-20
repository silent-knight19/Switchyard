-- 0001-roles.sql
-- Distinct least-privilege PostgreSQL roles (Architecture v1.2 §12.1, §12.5).
-- Idempotent: re-running this migration is a no-op, including after a failed run.
-- All roles are NOLOGIN unless noted. Executor roles own only restricted functions
-- (none exist yet in SW-1.3.1); they bypass RLS.

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
