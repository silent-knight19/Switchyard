-- 0010-privileged-bootstrap-functions.sql — Privileged authentication & maintenance functions (Architecture v1.2 §12.4).
-- Runs as the connecting role (gateway_migrator in deployment).
-- Roles and schema app_private are created by provision-roles.sql.
-- gateway_migrator holds SET ROLE on gateway_owner, gateway_auth_executor, and gateway_ops_executor
-- (INHERIT FALSE, ADMIN FALSE).

DO $$
BEGIN
  IF NOT (
    pg_has_role(CURRENT_USER, 'gateway_auth_executor', 'SET') AND
    pg_has_role(CURRENT_USER, 'gateway_ops_executor', 'SET')
  ) THEN
    RAISE EXCEPTION 'Current role "%" cannot assume gateway_auth_executor and gateway_ops_executor. Reconcile role privileges via provision-roles.sql as superuser before applying migration 0010.', CURRENT_USER
      USING ERRCODE = '42501';
  END IF;
END $$;

-- 1. Table and column-level grants from table owner (gateway_owner) to executor roles.
SET ROLE gateway_owner;

-- Column privileges for gateway_auth_executor (Architecture §12.4 least privilege)
GRANT SELECT (
  id,
  org_id,
  revoked_at,
  allowed_models,
  rpm_limit,
  tpm_limit,
  concurrent_stream_limit,
  exact_cache_enabled,
  semantic_cache_enabled,
  pii_redaction_enabled,
  store_payloads,
  key_hash
) ON public.virtual_keys TO gateway_auth_executor;

GRANT SELECT (
  id,
  org_id,
  role,
  password_hash,
  email_normalized
) ON public.users TO gateway_auth_executor;

GRANT INSERT (
  id,
  name,
  monthly_budget_microdollars,
  kek_version,
  wrapped_dek,
  dek_iv,
  dek_auth_tag
), SELECT (id) ON public.organizations TO gateway_auth_executor;

GRANT INSERT (
  id,
  org_id,
  email_normalized,
  password_hash,
  role,
  created_at
), SELECT (id) ON public.users TO gateway_auth_executor;

-- Column privileges for gateway_ops_executor (Architecture §12.4 IDs only)
GRANT SELECT (id) ON public.organizations TO gateway_ops_executor;

RESET ROLE;

-- 2. Create authentication functions owned by gateway_auth_executor (SW-1.4.3).
SET ROLE gateway_auth_executor;

-- SW-1.4.3: Virtual API key lookup by 32-byte SHA-256 hash.
CREATE OR REPLACE FUNCTION app_private.lookup_virtual_key_by_hash(p_key_hash BYTEA)
RETURNS TABLE (
  id UUID,
  org_id UUID,
  revoked_at TIMESTAMPTZ,
  allowed_models TEXT[],
  rpm_limit INT,
  tpm_limit INT,
  concurrent_stream_limit INT,
  exact_cache_enabled BOOLEAN,
  semantic_cache_enabled BOOLEAN,
  pii_redaction_enabled BOOLEAN,
  store_payloads BOOLEAN
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, app_private, pg_temp
AS $$
BEGIN
  -- Fail closed: accept only valid 32-byte SHA-256 hash. Invalid input returns no rows.
  IF p_key_hash IS NULL OR pg_catalog.octet_length(p_key_hash) != 32 THEN
    RETURN;
  END IF;

  RETURN QUERY
  SELECT
    vk.id,
    vk.org_id,
    vk.revoked_at,
    vk.allowed_models,
    vk.rpm_limit,
    vk.tpm_limit,
    vk.concurrent_stream_limit,
    vk.exact_cache_enabled,
    vk.semantic_cache_enabled,
    vk.pii_redaction_enabled,
    vk.store_payloads
  FROM public.virtual_keys vk
  WHERE vk.key_hash = p_key_hash;
END;
$$;

REVOKE ALL ON FUNCTION app_private.lookup_virtual_key_by_hash(BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_private.lookup_virtual_key_by_hash(BYTEA) TO gateway_app;

-- SW-1.4.3: Pre-tenant user lookup for login by normalized email.
CREATE OR REPLACE FUNCTION app_private.lookup_user_for_login(p_email_normalized TEXT)
RETURNS TABLE (
  id UUID,
  org_id UUID,
  role TEXT,
  password_hash TEXT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, app_private, pg_temp
AS $$
BEGIN
  -- Fail closed: reject NULL, empty, or oversized input (> 255 chars). Invalid/unknown returns no rows.
  IF p_email_normalized IS NULL OR p_email_normalized = '' OR pg_catalog.length(p_email_normalized) > 255 THEN
    RETURN;
  END IF;

  RETURN QUERY
  SELECT
    u.id,
    u.org_id,
    u.role,
    u.password_hash
  FROM public.users u
  WHERE u.email_normalized = p_email_normalized;
END;
$$;

REVOKE ALL ON FUNCTION app_private.lookup_user_for_login(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_private.lookup_user_for_login(TEXT) TO gateway_app;

-- SW-1.4.3: Atomic organization and initial admin user bootstrap.
CREATE OR REPLACE FUNCTION app_private.create_organization_with_admin(
  p_org_id UUID,
  p_org_name TEXT,
  p_monthly_budget_microdollars BIGINT,
  p_kek_version INT,
  p_wrapped_dek BYTEA,
  p_dek_iv BYTEA,
  p_dek_auth_tag BYTEA,
  p_admin_user_id UUID,
  p_admin_email_normalized TEXT,
  p_admin_password_hash TEXT
)
RETURNS TABLE (
  org_id UUID,
  admin_user_id UUID
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, app_private, pg_temp
AS $$
BEGIN
  -- Strict validation of all inputs
  IF p_org_id IS NULL OR p_admin_user_id IS NULL THEN
    RAISE EXCEPTION 'Organization ID and Admin User ID must not be null'
      USING ERRCODE = '22004';
  END IF;

  IF p_org_name IS NULL OR pg_catalog.btrim(p_org_name) = '' OR pg_catalog.length(p_org_name) > 255 THEN
    RAISE EXCEPTION 'Invalid organization name'
      USING ERRCODE = '22023';
  END IF;

  IF p_monthly_budget_microdollars IS NULL OR p_monthly_budget_microdollars < 0 OR p_monthly_budget_microdollars > 1000000000000000 THEN
    RAISE EXCEPTION 'Invalid monthly budget microdollars'
      USING ERRCODE = '22023';
  END IF;

  IF p_kek_version IS NULL OR p_kek_version <= 0 THEN
    RAISE EXCEPTION 'Invalid KEK version'
      USING ERRCODE = '22023';
  END IF;

  IF p_wrapped_dek IS NULL OR pg_catalog.octet_length(p_wrapped_dek) = 0
     OR p_dek_iv IS NULL OR pg_catalog.octet_length(p_dek_iv) = 0
     OR p_dek_auth_tag IS NULL OR pg_catalog.octet_length(p_dek_auth_tag) = 0 THEN
    RAISE EXCEPTION 'DEK parameters must not be empty'
      USING ERRCODE = '22023';
  END IF;

  IF p_admin_email_normalized IS NULL OR p_admin_email_normalized = '' OR pg_catalog.length(p_admin_email_normalized) > 255 THEN
    RAISE EXCEPTION 'Invalid admin email'
      USING ERRCODE = '22023';
  END IF;

  IF p_admin_password_hash IS NULL OR p_admin_password_hash = '' OR pg_catalog.length(p_admin_password_hash) > 255 THEN
    RAISE EXCEPTION 'Invalid admin password hash'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.organizations (
    id,
    name,
    monthly_budget_microdollars,
    kek_version,
    wrapped_dek,
    dek_iv,
    dek_auth_tag
  ) VALUES (
    p_org_id,
    p_org_name,
    p_monthly_budget_microdollars,
    p_kek_version,
    p_wrapped_dek,
    p_dek_iv,
    p_dek_auth_tag
  );

  INSERT INTO public.users (
    id,
    org_id,
    email_normalized,
    password_hash,
    role,
    created_at
  ) VALUES (
    p_admin_user_id,
    p_org_id,
    p_admin_email_normalized,
    p_admin_password_hash,
    'admin',
    pg_catalog.clock_timestamp()
  );

  RETURN QUERY SELECT p_org_id, p_admin_user_id;
END;
$$;

REVOKE ALL ON FUNCTION app_private.create_organization_with_admin(UUID, TEXT, BIGINT, INT, BYTEA, BYTEA, BYTEA, UUID, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_private.create_organization_with_admin(UUID, TEXT, BIGINT, INT, BYTEA, BYTEA, BYTEA, UUID, TEXT, TEXT) TO gateway_app;

RESET ROLE;

-- 3. Create maintenance function owned by gateway_ops_executor (SW-1.4.4).
SET ROLE gateway_ops_executor;

-- SW-1.4.4: Bounded keyset organization enumerator for background maintenance.
CREATE OR REPLACE FUNCTION app_private.list_active_org_ids(
  p_after_id UUID DEFAULT NULL,
  p_limit INT DEFAULT 100
)
RETURNS TABLE (
  org_id UUID
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, app_private, pg_temp
AS $$
BEGIN
  IF p_limit IS NULL OR p_limit <= 0 OR p_limit > 100 THEN
    RAISE EXCEPTION 'Invalid limit: must be between 1 and 100'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT o.id AS org_id
  FROM public.organizations o
  WHERE (p_after_id IS NULL OR o.id > p_after_id)
  ORDER BY o.id ASC
  LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION app_private.list_active_org_ids(UUID, INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_private.list_active_org_ids(UUID, INT) TO gateway_worker;

RESET ROLE;
