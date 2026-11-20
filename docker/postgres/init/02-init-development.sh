#!/bin/sh
set -e

# One-time development PostgreSQL initialization script (review findings DB-12, DB-15, DB-16).
# Executed by the official postgres entrypoint during initial database creation (when the data
# volume is empty). Role definitions are loaded first by 01-provision-roles.sql as the superuser;
# this script sets local credentials for the application, migration, and operational roles.
# Uses psql variables with literal quoting (:'var') to prevent SQL injection or statement breakage
# from passwords containing quotes, spaces, or SQL-sensitive characters (DB-16).

echo "==> Setting development passwords for Switchyard roles..."
psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  -v migrator_pass="${GATEWAY_MIGRATOR_PASSWORD:-switchyard_migrator_password}" \
  -v app_pass="${GATEWAY_APP_PASSWORD:-switchyard_app_password}" \
  -v startup_pass="${GATEWAY_STARTUP_PASSWORD:-switchyard_startup_password}" \
  -v worker_pass="${GATEWAY_WORKER_PASSWORD:-switchyard_worker_password}" \
  <<'EOSQL'
  ALTER ROLE gateway_migrator PASSWORD :'migrator_pass';
  ALTER ROLE gateway_app PASSWORD :'app_pass';
  ALTER ROLE gateway_startup PASSWORD :'startup_pass';
  ALTER ROLE gateway_worker PASSWORD :'worker_pass';
EOSQL

echo "==> Switchyard development role credentials initialized."
