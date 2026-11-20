#!/bin/sh
set -e

# One-time development PostgreSQL initialization script (review findings DB-12, DB-15).
# Executed by the official postgres entrypoint during initial database creation (when the data
# volume is empty). Role definitions are loaded first by 01-provision-roles.sql as the superuser;
# this script sets local credentials for the application, migration, and operational roles.
# Schema migrations are deliberately NOT executed here; they are applied by the authoritative
# migration runner (apps/gateway/src/db/migrate.ts) via the one-shot migrate service.

echo "==> Setting development passwords for Switchyard roles..."
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  ALTER ROLE gateway_migrator PASSWORD '${GATEWAY_MIGRATOR_PASSWORD:-switchyard_migrator_password}';
  ALTER ROLE gateway_app PASSWORD '${GATEWAY_APP_PASSWORD:-switchyard_app_password}';
  ALTER ROLE gateway_startup PASSWORD '${GATEWAY_STARTUP_PASSWORD:-switchyard_startup_password}';
  ALTER ROLE gateway_worker PASSWORD '${GATEWAY_WORKER_PASSWORD:-switchyard_worker_password}';
EOSQL

echo "==> Switchyard development role credentials initialized."
