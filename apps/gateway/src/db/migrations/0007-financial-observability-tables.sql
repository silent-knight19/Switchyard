-- 0007-financial-observability-tables.sql
-- Financial and observability tables with composite tenant foreign keys (Architecture v1.2 §§11.7–11.10, 12.1–12.4).
--
-- Creates the four authoritative tables for request tracking, provider attempts, financial
-- cost adjustments, and trace payload retention:
--
--   * gateway_requests: logical requests (including cache hits), keyset pagination index.
--   * provider_attempts: upstream provider dispatches, generated effective cost, stale reserved index.
--   * provider_cost_adjustments: append-only cost correction ledger with delta integrity check.
--   * trace_payloads: debug payloads with cascading deletion from gateway_requests and retention index.
--
-- Security and tenant isolation posture:
--   * Owned by gateway_owner (§12.1).
--   * ENABLE ROW LEVEL SECURITY + FORCE ROW LEVEL SECURITY (§12.3).
--   * Zero permissive policies (maintains deliberate Batch A default-deny posture until Subphase 1.4).
--   * REVOKE ALL FROM PUBLIC. No runtime-role grants in this migration.

SET ROLE gateway_owner;

CREATE TABLE gateway_requests (
  request_id UUID PRIMARY KEY,
  org_id UUID NOT NULL,
  virtual_key_id UUID NOT NULL,
  gateway_instance_id UUID NOT NULL,
  gateway_epoch BIGINT NOT NULL,
  requested_model TEXT NOT NULL,
  billing_period TEXT NOT NULL CHECK (billing_period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  status TEXT NOT NULL CHECK (status IN ('in_progress', 'completed', 'failed', 'client_aborted', 'interrupted')),
  final_provider TEXT NULL,
  final_model TEXT NULL,
  attempt_count INT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  cache_status TEXT NOT NULL CHECK (cache_status IN ('miss', 'exact_hit', 'semantic_hit', 'bypass')),
  http_status INT NULL CHECK (http_status >= 100 AND http_status <= 599),
  ttft_ms INT NULL CHECK (ttft_ms >= 0),
  total_latency_ms INT NULL CHECK (total_latency_ms >= 0),
  pii_redacted_count INT NOT NULL DEFAULT 0 CHECK (pii_redacted_count >= 0),
  error_code TEXT NULL,
  admitted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  deadline_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  finalized_at TIMESTAMPTZ NULL,
  CONSTRAINT uq_gateway_requests_request_org UNIQUE (request_id, org_id),
  CONSTRAINT fk_gateway_requests_org FOREIGN KEY (org_id)
    REFERENCES organizations(id) ON DELETE RESTRICT,
  CONSTRAINT fk_gateway_requests_virtual_key FOREIGN KEY (virtual_key_id, org_id)
    REFERENCES virtual_keys(id, org_id) ON DELETE RESTRICT
);

CREATE INDEX idx_gateway_requests_org_pagination
  ON gateway_requests (org_id, created_at DESC, request_id DESC);

CREATE TABLE provider_attempts (
  attempt_id UUID PRIMARY KEY,
  request_id UUID NOT NULL,
  org_id UUID NOT NULL,
  virtual_key_id UUID NOT NULL,
  attempt_number INT NOT NULL CHECK (attempt_number >= 1),
  gateway_instance_id UUID NOT NULL,
  gateway_epoch BIGINT NOT NULL,
  billing_period TEXT NOT NULL CHECK (billing_period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  sanitized_fields TEXT[] NOT NULL DEFAULT '{}',
  status TEXT NOT NULL CHECK (status IN ('reserved', 'settled', 'interrupted')),
  outcome TEXT NULL CHECK (outcome IN ('completed', 'client_aborted', 'pre_token_timeout', 'pre_token_error', 'mid_stream_error', 'interrupted')),
  tokens_in INT NULL CHECK (tokens_in >= 0),
  tokens_out INT NULL CHECK (tokens_out >= 0),
  duration_ms INT NULL CHECK (duration_ms >= 0),
  http_status INT NULL CHECK (http_status >= 100 AND http_status <= 599),
  estimated_cost_microdollars BIGINT NOT NULL CHECK (estimated_cost_microdollars >= 0),
  actual_cost_microdollars BIGINT NULL CHECK (actual_cost_microdollars >= 0),
  effective_cost_microdollars BIGINT GENERATED ALWAYS AS (COALESCE(actual_cost_microdollars, estimated_cost_microdollars)) STORED,
  cost_status TEXT NOT NULL CHECK (cost_status IN ('estimated', 'confirmed')),
  admitted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  hard_deadline_at TIMESTAMPTZ NOT NULL,
  settled_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_provider_attempts_request_attempt UNIQUE (request_id, attempt_number),
  CONSTRAINT uq_provider_attempts_attempt_org UNIQUE (attempt_id, org_id),
  CONSTRAINT fk_provider_attempts_request FOREIGN KEY (request_id, org_id)
    REFERENCES gateway_requests(request_id, org_id) ON DELETE RESTRICT,
  CONSTRAINT fk_provider_attempts_virtual_key FOREIGN KEY (virtual_key_id, org_id)
    REFERENCES virtual_keys(id, org_id) ON DELETE RESTRICT
);

CREATE INDEX idx_provider_attempts_billing
  ON provider_attempts (org_id, billing_period, created_at DESC);

CREATE INDEX idx_provider_attempts_stale_reserved
  ON provider_attempts (hard_deadline_at) WHERE status = 'reserved';

CREATE TABLE provider_cost_adjustments (
  adjustment_id UUID PRIMARY KEY,
  attempt_id UUID NOT NULL,
  org_id UUID NOT NULL,
  previous_cost_microdollars BIGINT NOT NULL CHECK (previous_cost_microdollars >= 0),
  corrected_cost_microdollars BIGINT NOT NULL CHECK (corrected_cost_microdollars >= 0),
  delta_microdollars BIGINT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('provider_usage', 'provider_invoice', 'manual_review')),
  source_reference TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT chk_provider_cost_adjustments_delta
    CHECK (delta_microdollars = corrected_cost_microdollars - previous_cost_microdollars),
  CONSTRAINT fk_provider_cost_adjustments_attempt FOREIGN KEY (attempt_id, org_id)
    REFERENCES provider_attempts(attempt_id, org_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX uq_provider_cost_adjustments_source_ref
  ON provider_cost_adjustments (attempt_id, source, source_reference)
  WHERE source_reference IS NOT NULL;

CREATE TABLE trace_payloads (
  request_id UUID PRIMARY KEY,
  org_id UUID NOT NULL,
  request_body JSONB NULL,
  response_text TEXT NULL,
  truncated BOOLEAN NOT NULL DEFAULT FALSE,
  expires_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT fk_trace_payloads_request FOREIGN KEY (request_id, org_id)
    REFERENCES gateway_requests(request_id, org_id) ON DELETE CASCADE
);

CREATE INDEX idx_trace_payloads_retention ON trace_payloads (expires_at);

-- Tenant table RLS and default-deny posture (§12.3)
ALTER TABLE gateway_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE provider_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_attempts FORCE ROW LEVEL SECURITY;
ALTER TABLE provider_cost_adjustments ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_cost_adjustments FORCE ROW LEVEL SECURITY;
ALTER TABLE trace_payloads ENABLE ROW LEVEL SECURITY;
ALTER TABLE trace_payloads FORCE ROW LEVEL SECURITY;

-- No public privileges on financial or observability tables
REVOKE ALL ON gateway_requests, provider_attempts, provider_cost_adjustments, trace_payloads FROM PUBLIC;

RESET ROLE;
