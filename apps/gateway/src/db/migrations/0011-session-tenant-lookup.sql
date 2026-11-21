-- 0011-session-tenant-lookup.sql — Restricted pre-tenant session organization lookup (Architecture v1.2 §12.4, ADR 0001).
-- Runs as the connecting role (gateway_migrator in deployment).
-- gateway_migrator holds SET ROLE on gateway_owner and gateway_auth_executor (INHERIT FALSE, ADMIN FALSE).

DO $$
BEGIN
  IF NOT (
    pg_has_role(CURRENT_USER, 'gateway_owner', 'SET') AND
    pg_has_role(CURRENT_USER, 'gateway_auth_executor', 'SET')
  ) THEN
    RAISE EXCEPTION 'Current role "%" cannot assume gateway_owner and gateway_auth_executor. Reconcile role privileges via provision-roles.sql as superuser before applying migration 0011.', CURRENT_USER
      USING ERRCODE = '42501';
  END IF;
END $$;

-- 1. Grant minimal column privileges on public.web_sessions from table owner (gateway_owner) to gateway_auth_executor.
SET ROLE gateway_owner;

GRANT SELECT (
  session_id_hash,
  org_id
) ON public.web_sessions TO gateway_auth_executor;

RESET ROLE;

-- 2. Create restricted pre-tenant session organization lookup function owned by gateway_auth_executor (ADR 0001 / SW-1.5.2).
SET ROLE gateway_auth_executor;

CREATE OR REPLACE FUNCTION app_private.lookup_session_org_by_hash(p_session_id_hash BYTEA)
RETURNS TABLE (
  org_id UUID
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, app_private, pg_temp
AS $$
BEGIN
  -- Fail closed: accept only valid 32-byte SHA-256 hash. Invalid, NULL, or malformed input returns no rows.
  IF p_session_id_hash IS NULL OR pg_catalog.octet_length(p_session_id_hash) != 32 THEN
    RETURN;
  END IF;

  RETURN QUERY
  SELECT ws.org_id
  FROM public.web_sessions ws
  WHERE ws.session_id_hash = p_session_id_hash;
END;
$$;

REVOKE ALL ON FUNCTION app_private.lookup_session_org_by_hash(BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_private.lookup_session_org_by_hash(BYTEA) TO gateway_app;

RESET ROLE;
