-- 0004-gateway-control-privileges.sql
-- Global control-plane privileges (Architecture v1.2 §§11.2, 12.5; review finding DB-05).
--
-- gateway_control is the only global, non-tenant table. It has no RLS (0002) and no PUBLIC
-- grants. Privileges are intentionally narrow:
--
--   gateway_app      SELECT only (§12.5: never SELECT ... FOR SHARE on this table).
--   gateway_startup  SELECT plus UPDATE of gateway_epoch only (§12.1: "updates
--                    gateway_control.gateway_epoch only").
--   gateway_worker   no privilege.
--   executors        no privilege in Batch A.
--
-- The invariant "startup updates the epoch only while holding the singleton session lock and
-- the exclusive transaction advisory lock" (§12.5) is a Phase 2 admission-protocol invariant.
-- Column grants can enforce which column may change; they cannot enforce lock ordering. That
-- remaining invariant is documented in docs/DEVELOPMENT.md §7.7 and is not implemented here.

SET ROLE gateway_owner;

REVOKE ALL ON gateway_control FROM PUBLIC;
REVOKE ALL ON gateway_control FROM gateway_app, gateway_startup, gateway_worker;

GRANT SELECT ON gateway_control TO gateway_app;
GRANT SELECT ON gateway_control TO gateway_startup;
GRANT UPDATE (gateway_epoch) ON gateway_control TO gateway_startup;

RESET ROLE;
