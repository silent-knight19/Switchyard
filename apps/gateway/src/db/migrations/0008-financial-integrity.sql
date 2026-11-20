-- 0008-financial-integrity.sql
-- Financial immutability, append-only adjustments, and monetary integrity (Architecture v1.2 §§5.1–5.3, 6.2–6.4, 7.1, 7.8–7.9, 8.5, 11.7–11.10, 12.1–12.4).
--
-- Hardens the financial schema established in 0007:
--   1. Immutable UTC billing periods and identity fields on gateway_requests and provider_attempts.
--   2. Admission-time consistency check between billing_period and admitted_at UTC month.
--   3. Immutable terminal base costs, status regressions, and identity reattribution on provider_attempts.
--   4. Append-only enforcement on provider_cost_adjustments: blocks UPDATE, DELETE, and TRUNCATE.
--   5. Verifies parent attempt is terminal (settled or interrupted) before cost adjustments can be inserted.
--   6. Monetary integrity: nonnegative bounds and BIGINT representability preserved from 0007;
--      PostgreSQL as canonical financial ledger (§5.2 #6) preserves authoritative cost records
--      including overspend (§5.2 #9) without artificial individual-attempt caps.
--
-- Security posture:
--   * Functions created in app_private, owned by gateway_owner.
--   * Hardened search_path = pg_catalog, app_private, pg_temp.
--   * REVOKE ALL ON FUNCTION ... FROM PUBLIC.
--   * Zero permissive RLS policies; default-deny posture preserved.

SET ROLE gateway_owner;

-- 1. Admission-time consistency: billing_period must equal UTC YYYY-MM of admitted_at
ALTER TABLE gateway_requests
  ADD CONSTRAINT chk_gateway_requests_billing_period
  CHECK (billing_period = to_char(admitted_at AT TIME ZONE 'UTC', 'YYYY-MM'));

-- 2. Trigger Function: enforce gateway_requests immutability
CREATE OR REPLACE FUNCTION app_private.enforce_gateway_requests_immutability()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, app_private, pg_temp
AS $$
BEGIN
  -- Identity, tenancy, and admission fields are strictly immutable
  IF NEW.request_id IS DISTINCT FROM OLD.request_id THEN
    RAISE EXCEPTION 'request_id is immutable for gateway_requests %', OLD.request_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.org_id IS DISTINCT FROM OLD.org_id THEN
    RAISE EXCEPTION 'org_id is immutable for gateway_requests %', OLD.request_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.virtual_key_id IS DISTINCT FROM OLD.virtual_key_id THEN
    RAISE EXCEPTION 'virtual_key_id is immutable for gateway_requests %', OLD.request_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.billing_period IS DISTINCT FROM OLD.billing_period THEN
    RAISE EXCEPTION 'billing_period is immutable for gateway_requests %', OLD.request_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.admitted_at IS DISTINCT FROM OLD.admitted_at THEN
    RAISE EXCEPTION 'admitted_at is immutable for gateway_requests %', OLD.request_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.gateway_instance_id IS DISTINCT FROM OLD.gateway_instance_id OR
     NEW.gateway_epoch IS DISTINCT FROM OLD.gateway_epoch THEN
    RAISE EXCEPTION 'gateway instance and epoch are immutable for gateway_requests %', OLD.request_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.requested_model IS DISTINCT FROM OLD.requested_model THEN
    RAISE EXCEPTION 'requested_model is immutable for gateway_requests %', OLD.request_id
      USING ERRCODE = '23514';
  END IF;

  -- Terminal status cannot be regressed or changed
  IF OLD.status <> 'in_progress' THEN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
      RAISE EXCEPTION 'Cannot change status of terminal request % from % to %',
        OLD.request_id, OLD.status, NEW.status
        USING ERRCODE = '23514';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

ALTER FUNCTION app_private.enforce_gateway_requests_immutability() OWNER TO gateway_owner;
REVOKE ALL ON FUNCTION app_private.enforce_gateway_requests_immutability() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_private.enforce_gateway_requests_immutability()
  TO gateway_owner, gateway_migrator, gateway_app, gateway_worker;

CREATE TRIGGER trg_gateway_requests_immutability
  BEFORE UPDATE ON gateway_requests
  FOR EACH ROW
  EXECUTE FUNCTION app_private.enforce_gateway_requests_immutability();

-- 3. Trigger Function: enforce provider_attempts immutability and valid settlement transitions
CREATE OR REPLACE FUNCTION app_private.enforce_provider_attempts_immutability()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, app_private, pg_temp
AS $$
BEGIN
  -- Attempt identity, tenancy, and dispatch metadata are strictly immutable
  IF NEW.attempt_id IS DISTINCT FROM OLD.attempt_id THEN
    RAISE EXCEPTION 'attempt_id is immutable for provider_attempts %', OLD.attempt_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.request_id IS DISTINCT FROM OLD.request_id THEN
    RAISE EXCEPTION 'request_id is immutable for provider_attempts %', OLD.attempt_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.org_id IS DISTINCT FROM OLD.org_id THEN
    RAISE EXCEPTION 'org_id is immutable for provider_attempts %', OLD.attempt_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.virtual_key_id IS DISTINCT FROM OLD.virtual_key_id THEN
    RAISE EXCEPTION 'virtual_key_id is immutable for provider_attempts %', OLD.attempt_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.attempt_number IS DISTINCT FROM OLD.attempt_number THEN
    RAISE EXCEPTION 'attempt_number is immutable for provider_attempts %', OLD.attempt_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.billing_period IS DISTINCT FROM OLD.billing_period THEN
    RAISE EXCEPTION 'billing_period is immutable for provider_attempts %', OLD.attempt_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.gateway_instance_id IS DISTINCT FROM OLD.gateway_instance_id OR
     NEW.gateway_epoch IS DISTINCT FROM OLD.gateway_epoch THEN
    RAISE EXCEPTION 'gateway instance and epoch are immutable for provider_attempts %', OLD.attempt_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.provider IS DISTINCT FROM OLD.provider OR NEW.model IS DISTINCT FROM OLD.model THEN
    RAISE EXCEPTION 'provider and model are immutable for provider_attempts %', OLD.attempt_id
      USING ERRCODE = '23514';
  END IF;

  IF NEW.admitted_at IS DISTINCT FROM OLD.admitted_at THEN
    RAISE EXCEPTION 'admitted_at is immutable for provider_attempts %', OLD.attempt_id
      USING ERRCODE = '23514';
  END IF;

  -- Reservation estimate is immutable once admitted
  IF NEW.estimated_cost_microdollars IS DISTINCT FROM OLD.estimated_cost_microdollars THEN
    RAISE EXCEPTION 'estimated_cost_microdollars is immutable for provider_attempts %', OLD.attempt_id
      USING ERRCODE = '23514';
  END IF;

  -- Rules for attempts that were already terminal
  IF OLD.status IN ('settled', 'interrupted') THEN
    -- Status regression or flip is prohibited
    IF NEW.status IS DISTINCT FROM OLD.status THEN
      RAISE EXCEPTION 'Cannot change status of terminal attempt % from % to %',
        OLD.attempt_id, OLD.status, NEW.status
        USING ERRCODE = '23514';
    END IF;

    -- Base actual cost and cost status are immutable
    IF NEW.actual_cost_microdollars IS DISTINCT FROM OLD.actual_cost_microdollars THEN
      RAISE EXCEPTION 'actual_cost_microdollars is immutable for terminal attempt %', OLD.attempt_id
        USING ERRCODE = '23514';
    END IF;

    IF NEW.cost_status IS DISTINCT FROM OLD.cost_status THEN
      RAISE EXCEPTION 'cost_status is immutable for terminal attempt %', OLD.attempt_id
        USING ERRCODE = '23514';
    END IF;
  END IF;

  -- If old status was reserved, allowed transitions are to settled or interrupted (or remaining reserved)
  IF OLD.status = 'reserved' AND NEW.status NOT IN ('reserved', 'settled', 'interrupted') THEN
    RAISE EXCEPTION 'Invalid status transition for attempt % from reserved to %',
      OLD.attempt_id, NEW.status
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

ALTER FUNCTION app_private.enforce_provider_attempts_immutability() OWNER TO gateway_owner;
REVOKE ALL ON FUNCTION app_private.enforce_provider_attempts_immutability() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_private.enforce_provider_attempts_immutability()
  TO gateway_owner, gateway_migrator, gateway_app, gateway_worker;

CREATE TRIGGER trg_provider_attempts_immutability
  BEFORE UPDATE ON provider_attempts
  FOR EACH ROW
  EXECUTE FUNCTION app_private.enforce_provider_attempts_immutability();

-- 4. Trigger Function: enforce provider_cost_adjustments append-only on UPDATE and DELETE
CREATE OR REPLACE FUNCTION app_private.enforce_provider_cost_adjustments_immutability()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, app_private, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'provider_cost_adjustments is append-only: % is prohibited', TG_OP
    USING ERRCODE = '23514';
END;
$$;

ALTER FUNCTION app_private.enforce_provider_cost_adjustments_immutability() OWNER TO gateway_owner;
REVOKE ALL ON FUNCTION app_private.enforce_provider_cost_adjustments_immutability() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_private.enforce_provider_cost_adjustments_immutability()
  TO gateway_owner, gateway_migrator, gateway_app, gateway_worker;

CREATE TRIGGER trg_provider_cost_adjustments_no_update_delete
  BEFORE UPDATE OR DELETE ON provider_cost_adjustments
  FOR EACH ROW
  EXECUTE FUNCTION app_private.enforce_provider_cost_adjustments_immutability();

-- 5. Trigger Function: enforce provider_cost_adjustments append-only on TRUNCATE
CREATE OR REPLACE FUNCTION app_private.enforce_provider_cost_adjustments_truncate()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, app_private, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'provider_cost_adjustments is append-only: TRUNCATE is prohibited'
    USING ERRCODE = '23514';
END;
$$;

ALTER FUNCTION app_private.enforce_provider_cost_adjustments_truncate() OWNER TO gateway_owner;
REVOKE ALL ON FUNCTION app_private.enforce_provider_cost_adjustments_truncate() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_private.enforce_provider_cost_adjustments_truncate()
  TO gateway_owner, gateway_migrator, gateway_app, gateway_worker;

CREATE TRIGGER trg_provider_cost_adjustments_no_truncate
  BEFORE TRUNCATE ON provider_cost_adjustments
  FOR EACH STATEMENT
  EXECUTE FUNCTION app_private.enforce_provider_cost_adjustments_truncate();

-- 6. Trigger Function: verify parent attempt is terminal on adjustment INSERT
CREATE OR REPLACE FUNCTION app_private.enforce_provider_cost_adjustments_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, app_private, pg_temp
AS $$
DECLARE
  v_attempt_status TEXT;
BEGIN
  SELECT status INTO v_attempt_status
  FROM public.provider_attempts
  WHERE attempt_id = NEW.attempt_id AND org_id = NEW.org_id;

  IF v_attempt_status IS NULL THEN
    -- Foreign key constraint will catch this, but fail closed regardless
    RAISE EXCEPTION 'Parent attempt % does not exist for adjustment %',
      NEW.attempt_id, NEW.adjustment_id
      USING ERRCODE = '23503';
  END IF;

  IF v_attempt_status = 'reserved' THEN
    RAISE EXCEPTION 'Cannot adjust active reserved attempt %; attempt must be settled or interrupted',
      NEW.attempt_id
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

ALTER FUNCTION app_private.enforce_provider_cost_adjustments_insert() OWNER TO gateway_owner;
REVOKE ALL ON FUNCTION app_private.enforce_provider_cost_adjustments_insert() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_private.enforce_provider_cost_adjustments_insert()
  TO gateway_owner, gateway_migrator, gateway_app, gateway_worker;

CREATE TRIGGER trg_provider_cost_adjustments_insert
  BEFORE INSERT ON provider_cost_adjustments
  FOR EACH ROW
  EXECUTE FUNCTION app_private.enforce_provider_cost_adjustments_insert();

RESET ROLE;
