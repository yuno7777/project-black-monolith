-- Cross-layer session circuit breaker, retention cascade fix, and strict
-- tenant-scoped session cleanup policy.

-- ---------------------------------------------------------------------------
-- DB-1: Allow retention pruning of security_events to cascade into
-- incident_audit when monolith.retention_prune = 'on' (transaction-local),
-- while keeping monolith.incident_audit strictly append-only for all other
-- callers and operations.

create or replace function monolith.forbid_incident_audit_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if tg_op = 'DELETE' and pg_catalog.current_setting('monolith.retention_prune', true) = 'on' then
    return old;
  end if;
  raise exception 'monolith.incident_audit is append-only (attempted %)', tg_op;
end;
$$;

create or replace function monolith.incident_audit_is_append_only()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if tg_op = 'DELETE' and pg_catalog.current_setting('monolith.retention_prune', true) = 'on' then
    return old;
  end if;
  raise exception 'monolith.incident_audit is append-only (attempted %)', tg_op;
end;
$$;

revoke all on function monolith.forbid_incident_audit_mutation()
  from public, anon, authenticated;
revoke all on function monolith.incident_audit_is_append_only()
  from public, anon, authenticated;

drop trigger if exists incident_audit_no_update on monolith.incident_audit;
create trigger incident_audit_no_update
  before update or delete on monolith.incident_audit
  for each row execute function monolith.forbid_incident_audit_mutation();

create or replace function monolith.prune_security_events(
  retain_for interval default interval '90 days'
)
returns bigint
language plpgsql
set search_path = ''
as $$
declare
  removed bigint;
begin
  if retain_for < interval '1 day' or retain_for > interval '10 years' then
    raise exception 'retain_for must be between 1 day and 10 years';
  end if;
  perform pg_catalog.set_config('monolith.retention_prune', 'on', true);
  delete from monolith.security_events
  where received_at < pg_catalog.now() - retain_for;
  get diagnostics removed = row_count;
  return removed;
end;
$$;

revoke all on function monolith.prune_security_events(interval)
  from public, anon, authenticated, monolith_app;

-- ---------------------------------------------------------------------------
-- DB-2: Require explicit tenant context on operator_sessions delete policy
-- (no fallback to 'default').

drop policy if exists monolith_app_operator_sessions_delete
  on monolith.operator_sessions;
create policy monolith_app_operator_sessions_delete
  on monolith.operator_sessions for delete to monolith_app
  using (
    tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
    and (revoked_at is not null or expires_at <= now())
  );

-- ---------------------------------------------------------------------------
-- DB-3: Cross-layer session revocation table with forced tenant RLS.

create table if not exists monolith.revoked_sessions (
  tenant_id text not null check (length(tenant_id) between 1 and 128),
  agent_id text not null check (length(agent_id) between 1 and 128),
  session_id text not null check (length(session_id) between 1 and 128),
  revoked_at timestamptz not null default now(),
  reason text not null check (length(reason) between 1 and 512),
  triggered_by text not null check (length(triggered_by) between 1 and 128),
  layers text[] not null default '{}',
  primary key (tenant_id, agent_id, session_id)
);

create index if not exists revoked_sessions_tenant_revoked_at_idx
  on monolith.revoked_sessions (tenant_id, revoked_at desc);

alter table monolith.revoked_sessions enable row level security;
alter table monolith.revoked_sessions force row level security;

revoke all on monolith.revoked_sessions from public, anon, authenticated, monolith_app;
grant select, insert, update, delete on monolith.revoked_sessions to monolith_app;

drop policy if exists monolith_app_revoked_sessions_tenant_isolation
  on monolith.revoked_sessions;
create policy monolith_app_revoked_sessions_tenant_isolation
  on monolith.revoked_sessions for all to monolith_app
  using (
    tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
  )
  with check (
    tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
  );

-- Non-mutating login rate-limit check so valid sign-ins do not increment the
-- failure counter before credential verification.
create or replace function monolith.check_operator_login_allowed(candidate_key text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_attempts integer;
begin
  if candidate_key !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid login rate-limit key';
  end if;

  select attempts into current_attempts
  from monolith.operator_login_limits
  where key_hash = candidate_key
    and window_started >= pg_catalog.now() - interval '15 minutes';

  return coalesce(current_attempts, 0) < 8;
end;
$$;

revoke all on function monolith.check_operator_login_allowed(text)
  from public, anon, authenticated;
grant execute on function monolith.check_operator_login_allowed(text) to monolith_app;
