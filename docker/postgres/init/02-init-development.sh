#!/bin/sh
set -e

# One-time development PostgreSQL initialization script (review finding DB-12).
# Executed by the official postgres entrypoint during initial database creation (when the data
# volume is empty). Role definitions are loaded first by 01-provision-roles.sql as the superuser;
# this script sets local credentials and applies initial migrations as gateway_migrator.

echo "==> Setting development passwords for Switchyard roles..."
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  ALTER ROLE gateway_migrator PASSWORD '${GATEWAY_MIGRATOR_PASSWORD:-switchyard_migrator_password}';
  ALTER ROLE gateway_app PASSWORD '${GATEWAY_APP_PASSWORD:-switchyard_app_password}';
  ALTER ROLE gateway_startup PASSWORD '${GATEWAY_STARTUP_PASSWORD:-switchyard_startup_password}';
  ALTER ROLE gateway_worker PASSWORD '${GATEWAY_WORKER_PASSWORD:-switchyard_worker_password}';
EOSQL

echo "==> Applying Switchyard schema migrations as gateway_migrator..."
export PGPASSWORD="${GATEWAY_MIGRATOR_PASSWORD:-switchyard_migrator_password}"

psql -v ON_ERROR_STOP=1 --username gateway_migrator --dbname "$POSTGRES_DB" <<-EOSQL
  CREATE TABLE IF NOT EXISTS gateway_migrations (
    version TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
  );
  ALTER TABLE gateway_migrations ADD COLUMN IF NOT EXISTS checksum TEXT;
EOSQL

for migration in $(ls /docker-entrypoint-initdb.d/migrations/*.sql | sort); do
  [ -f "$migration" ] || continue
  filename=$(basename "$migration")
  version=$(echo "$filename" | cut -d'-' -f1)
  name=$(echo "$filename" | sed 's/\.sql$//')
  checksum=$(sha256sum "$migration" | cut -d' ' -f1)

  echo "==> Applying migration $filename (version: $version, checksum: $checksum)..."
  psql -v ON_ERROR_STOP=1 --username gateway_migrator --dbname "$POSTGRES_DB" <<-EOSQL
    BEGIN;
    \i $migration
    INSERT INTO gateway_migrations (version, name, checksum)
    VALUES ('$version', '$name', '$checksum')
    ON CONFLICT (version) DO UPDATE SET checksum = EXCLUDED.checksum;
    COMMIT;
EOSQL
done

echo "==> Switchyard development database initialization complete."
