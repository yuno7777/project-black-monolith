#!/usr/bin/env bash
set -euo pipefail

: "${MONOLITH_DATABASE_RUNTIME_PASSWORD:?runtime database password is required}"

# Cluster roles are infrastructure, not application schema. Compose runs this
# as the database superuser; a Docker-free setup may provide an equivalent
# administrative connection in DATABASE_ADMIN_URL.
psql_args=(--set=ON_ERROR_STOP=1 --set=runtime_password="$MONOLITH_DATABASE_RUNTIME_PASSWORD")
if [[ -n "${DATABASE_ADMIN_URL:-}" ]]; then
  psql_args=("$DATABASE_ADMIN_URL" "${psql_args[@]}")
else
  psql_args=(--username postgres --dbname postgres "${psql_args[@]}")
  if [[ -n "${PGHOST:-}" ]]; then
    psql_args+=(--host "$PGHOST")
  fi
fi

psql "${psql_args[@]}" <<'SQL'
select 'create role monolith_app nologin nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls'
where not exists (select 1 from pg_roles where rolname = 'monolith_app')
\gexec

select format(
  'create role monolith_runtime login password %L nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls',
  :'runtime_password'
)
where not exists (select 1 from pg_roles where rolname = 'monolith_runtime')
\gexec

-- Reconcile the password on an existing volume. Deliberately does NOT restate
-- nosuperuser/noreplication/nobypassrls: altering those attributes requires a
-- superuser even to turn them off, and this runs as `postgres`, which in the
-- supabase image has CREATEROLE but not SUPERUSER. CREATE ROLE above already
-- set them, so restating here only bought an unconditional failure.
select format(
  'alter role monolith_runtime with login password %L',
  :'runtime_password'
)
\gexec

grant monolith_app to monolith_runtime;
alter role monolith_runtime set statement_timeout = '30s';
alter role monolith_runtime set idle_in_transaction_session_timeout = '15s';
SQL
