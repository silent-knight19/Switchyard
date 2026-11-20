-- 0005-virtual-key-integrity.sql
-- Enforces present, positive virtual-key integrity fields (Architecture v1.2 §11.6;
-- review finding DB-08).
--
-- 0002-org-tables.sql allowed NULL in key_hash, rpm_limit, tpm_limit, and
-- concurrent_stream_limit. A virtual key without a key verifier or without positive
-- rate/concurrency limits is not a valid key, so all four columns become NOT NULL. The
-- existing CHECK (limit > 0) constraints then make zero/negative values impossible.
--
-- No default limit value is invented: an installation holding legacy NULL rows fails this
-- migration closed with SQLSTATE 23502 ("column ... contains null values") and rolls back.
-- Operators must resolve those rows explicitly; the runner never guesses limits.
--
-- allowed_models stays NOT NULL with no default; an empty array remains deny-all (§11.6).
-- Cache/redaction flags keep their default-disabled values from 0002.

SET ROLE gateway_owner;

ALTER TABLE virtual_keys ALTER COLUMN key_hash SET NOT NULL;
ALTER TABLE virtual_keys ALTER COLUMN rpm_limit SET NOT NULL;
ALTER TABLE virtual_keys ALTER COLUMN tpm_limit SET NOT NULL;
ALTER TABLE virtual_keys ALTER COLUMN concurrent_stream_limit SET NOT NULL;

RESET ROLE;
