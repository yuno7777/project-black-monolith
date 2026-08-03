#!/usr/bin/env bash
set -euo pipefail

: "${MONOLITH_DATABASE_RUNTIME_PASSWORD:?runtime database password is required}"

# Cluster roles are infrastructure, not application schema. This script runs
# only during first-time Postgres initialization as the database superuser.
# Application migrations deliberately reject role-management statements.
psql_args=(
  --username postgres \
  --dbname postgres \
  --set=ON_ERROR_STOP=1 \
  --set=runtime_password="$MONOLITH_DATABASE_RUNTIME_PASSWORD"
)
if [[ -n "${PGHOST:-}" ]]; then
  psql_args+=(--host "$PGHOST")
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

select format(
  'alter role monolith_runtime with login password %L nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls',
  :'runtime_password'
)
\gexec

grant monolith_app to monolith_runtime;
alter role monolith_runtime set statement_timeout = '30s';
alter role monolith_runtime set idle_in_transaction_session_timeout = '15s';
SQL
