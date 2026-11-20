-- 0002-org-tables.sql — Tenant/control-plane core tables (Architecture v1.2 §§11–12.5).
-- Runs as the connecting role (gateway_migrator in production); tenant tables are owned by
-- gateway_owner (§12.1). Deployment bootstrap grants: CREATE on the schema to gateway_owner
-- and gateway_migrator membership in gateway_owner.

-- Migrations run as the connecting role; gateway_migrator can SET ROLE into gateway_owner
-- per §12.1. The bootstrap grant before the first production run makes this a no-op there.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_auth_members am
    JOIN pg_roles m ON m.oid = am.roleid
    JOIN pg_roles mem ON mem.oid = am.member
    WHERE m.rolname = 'gateway_owner' AND mem.rolname = 'gateway_migrator'
  ) THEN
    GRANT gateway_owner TO gateway_migrator;
  END IF;
END $$;

SET ROLE gateway_owner;

CREATE TABLE organizations (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  monthly_budget_microdollars BIGINT NOT NULL
    CHECK (monthly_budget_microdollars BETWEEN 0 AND 1000000000000000),
  kek_version INT NOT NULL,
  wrapped_dek BYTEA NOT NULL,
  dek_iv BYTEA NOT NULL,
  dek_auth_tag BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE gateway_control (
  id SMALLINT PRIMARY KEY CHECK (id = 1),
  gateway_epoch BIGINT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE users (
  id UUID PRIMARY KEY,
  org_id UUID NOT NULL REFERENCES organizations(id),
  email_normalized TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (id, org_id)
);

CREATE TABLE web_sessions (
  session_id_hash BYTEA PRIMARY KEY,
  user_id UUID NOT NULL,
  org_id UUID NOT NULL,
  csrf_token_hash BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  last_seen_at TIMESTAMPTZ NOT NULL,
  idle_expires_at TIMESTAMPTZ NOT NULL,
  absolute_expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  FOREIGN KEY (user_id, org_id) REFERENCES users(id, org_id)
);

CREATE TABLE provider_keys (
  id UUID PRIMARY KEY,
  org_id UUID NOT NULL,
  provider TEXT NOT NULL CHECK (provider IN ('openai')),
  label TEXT NOT NULL,
  key_hint TEXT NOT NULL,
  ciphertext BYTEA NOT NULL,
  iv BYTEA NOT NULL,
  auth_tag BYTEA NOT NULL,
  is_active BOOLEAN NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (id, org_id),
  FOREIGN KEY (org_id) REFERENCES organizations(id)
);

CREATE TABLE virtual_keys (
  id UUID PRIMARY KEY,
  org_id UUID NOT NULL,
  name TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  key_hash BYTEA UNIQUE,
  allowed_models TEXT[] NOT NULL,
  rpm_limit INTEGER CHECK (rpm_limit > 0),
  tpm_limit INTEGER CHECK (tpm_limit > 0),
  concurrent_stream_limit INTEGER CHECK (concurrent_stream_limit > 0),
  exact_cache_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  semantic_cache_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  pii_redaction_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  store_payloads BOOLEAN NOT NULL DEFAULT TRUE,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (id, org_id),
  FOREIGN KEY (org_id) REFERENCES organizations(id)
);

-- RLS (§12.3): ENABLE + FORCE RLS with explicit USING and WITH CHECK policies on tenant
-- tables. gateway_control is the global control table and stays without RLS.
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY organizations_tenant_using ON organizations USING (
  id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);
CREATE POLICY organizations_tenant_with_check ON organizations WITH CHECK (
  id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_tenant_using ON users USING (
  org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);
CREATE POLICY users_tenant_with_check ON users WITH CHECK (
  org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);

ALTER TABLE web_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE web_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY web_sessions_tenant_using ON web_sessions USING (
  org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);
CREATE POLICY web_sessions_tenant_with_check ON web_sessions WITH CHECK (
  org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);

ALTER TABLE provider_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY provider_keys_tenant_using ON provider_keys USING (
  org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);
CREATE POLICY provider_keys_tenant_with_check ON provider_keys WITH CHECK (
  org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);

ALTER TABLE virtual_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE virtual_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY virtual_keys_tenant_using ON virtual_keys USING (
  org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);
CREATE POLICY virtual_keys_tenant_with_check ON virtual_keys WITH CHECK (
  org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);

RESET ROLE;
