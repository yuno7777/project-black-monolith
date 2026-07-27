-- Production trust model.
--
-- 1. A tenant + agent + session tuple is the correlation boundary. Session
--    labels are not assumed to be globally unique.
-- 2. The dashboard runtime assumes a NOLOGIN role with only the operations it
--    needs. Migration/bootstrap continues to use the administrative connection.
-- 3. RLS remains enabled and receives role-scoped policies as defense in depth.

-- ---------------------------------------------------------------------------
-- Tenant-aware event and benchmark identity

alter table monolith.security_events
  add column if not exists tenant_id text;

update monolith.security_events
set tenant_id = 'default'
where tenant_id is null;

alter table monolith.security_events
  alter column tenant_id set default 'default',
  alter column tenant_id set not null;

alter table monolith.security_events
  drop constraint if exists security_events_tenant_id_length,
  add constraint security_events_tenant_id_length
    check (length(tenant_id) between 1 and 128),
  drop constraint if exists security_events_agent_id_length,
  add constraint security_events_agent_id_length
    check (agent_id is null or length(agent_id) between 1 and 128),
  drop constraint if exists security_events_session_id_length,
  add constraint security_events_session_id_length
    check (session_id is null or length(session_id) between 1 and 128),
  drop constraint if exists security_events_trace_id_length,
  add constraint security_events_trace_id_length
    check (trace_id is null or length(trace_id) between 1 and 128),
  drop constraint if exists security_events_correlation_id_length,
  add constraint security_events_correlation_id_length
    check (correlation_id is null or length(correlation_id) between 1 and 128);

drop index if exists monolith.security_events_session_idx;
create index if not exists security_events_identity_session_idx
  on monolith.security_events
    (tenant_id, agent_id, session_id, received_at desc)
  where agent_id is not null and session_id is not null;

create index if not exists security_events_tenant_received_idx
  on monolith.security_events (tenant_id, received_at desc);

alter table monolith.benchmark_runs
  add column if not exists tenant_id text;

update monolith.benchmark_runs
set tenant_id = 'default'
where tenant_id is null;

alter table monolith.benchmark_runs
  alter column tenant_id set default 'default',
  alter column tenant_id set not null,
  drop constraint if exists benchmark_runs_tenant_id_length,
  add constraint benchmark_runs_tenant_id_length
    check (length(tenant_id) between 1 and 128),
  drop constraint if exists benchmark_runs_version_range,
  add constraint benchmark_runs_version_range
    check (benchmark_version between 1 and 32767),
  drop constraint if exists benchmark_runs_latency_nonnegative,
  add constraint benchmark_runs_latency_nonnegative
    check (
      (latency_p50_us is null and latency_p95_us is null and latency_p99_us is null)
      or (
        latency_p50_us >= 0
        and latency_p95_us >= latency_p50_us
        and latency_p99_us >= latency_p95_us
      )
    );

drop index if exists monolith.benchmark_runs_run_at_idx;
drop index if exists monolith.benchmark_runs_module_detector_idx;
create index if not exists benchmark_runs_tenant_run_at_idx
  on monolith.benchmark_runs (tenant_id, run_at desc);
create index if not exists benchmark_runs_tenant_detector_idx
  on monolith.benchmark_runs (tenant_id, module, detector, run_at desc);

-- Browser sessions contain only an opaque random value. Its SHA-256 digest is
-- stored here so a database read cannot be replayed as a browser credential.
create table if not exists monolith.operator_sessions (
  session_hash text primary key
    check (session_hash ~ '^[0-9a-f]{64}$'),
  actor text not null check (length(actor) between 1 and 128),
  role text not null check (role in ('viewer', 'analyst', 'admin')),
  tenant_id text not null check (length(tenant_id) between 1 and 128),
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  last_seen_at timestamptz not null default now(),
  check (expires_at > issued_at)
);

create index if not exists operator_sessions_expiry_idx
  on monolith.operator_sessions (expires_at)
  where revoked_at is null;

alter table monolith.operator_sessions enable row level security;
revoke all on monolith.operator_sessions from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- Runtime role

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'monolith_app') then
    create role monolith_app
      nologin
      nosuperuser
      nocreatedb
      nocreaterole
      noinherit
      noreplication
      nobypassrls;
  end if;
end
$$;

-- Supabase's `postgres` login can create ordinary roles, but it is not the
-- bootstrap superuser and therefore cannot reassign SUPERUSER/BYPASSRLS role
-- attributes. Validate an existing role instead of attempting a privileged
-- cluster mutation from the application migration path.
do $$
begin
  if exists (
    select 1
    from pg_roles
    where rolname = 'monolith_app'
      and (
        rolcanlogin
        or rolsuper
        or rolcreatedb
        or rolcreaterole
        or rolinherit
        or rolreplication
        or rolbypassrls
      )
  ) then
    raise exception using
      errcode = '42501',
      message = 'monolith_app exists with unsafe role attributes',
      hint = 'Repair monolith_app with the database bootstrap superuser before running app migrations.';
  end if;
end
$$;

-- The local and hosted migration connection is the postgres role. It remains
-- the login/bootstrap identity, then the dashboard runtime uses SET ROLE to
-- shed its administrative privileges.
grant monolith_app to postgres;
grant usage on schema monolith to monolith_app;

revoke all on monolith.security_events from monolith_app;
revoke all on monolith.incident_triage from monolith_app;
revoke all on monolith.incident_audit from monolith_app;
revoke all on monolith.benchmark_runs from monolith_app;
revoke all on monolith.operator_sessions from monolith_app;

grant select, insert on monolith.security_events to monolith_app;
grant select, insert, update on monolith.incident_triage to monolith_app;
grant select, insert on monolith.incident_audit to monolith_app;
grant select, insert on monolith.benchmark_runs to monolith_app;
grant select, insert, update on monolith.operator_sessions to monolith_app;
grant usage, select on sequence monolith.incident_audit_audit_id_seq
  to monolith_app;

-- The dashboard sets monolith.tenant_id (or the opaque session hash for the
-- pre-identity session lookup) with transaction-local set_config(). With no
-- context the comparisons evaluate false, so pooled connections fail closed.
drop policy if exists monolith_app_security_events_select
  on monolith.security_events;
create policy monolith_app_security_events_select
  on monolith.security_events for select to monolith_app
  using (
    tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
  );

drop policy if exists monolith_app_security_events_insert
  on monolith.security_events;
create policy monolith_app_security_events_insert
  on monolith.security_events for insert to monolith_app
  with check (
    tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
  );

drop policy if exists monolith_app_incident_triage_select
  on monolith.incident_triage;
create policy monolith_app_incident_triage_select
  on monolith.incident_triage for select to monolith_app
  using (
    exists (
      select 1 from monolith.security_events e
      where e.event_id = incident_triage.event_id
        and e.tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
    )
  );

drop policy if exists monolith_app_incident_triage_insert
  on monolith.incident_triage;
create policy monolith_app_incident_triage_insert
  on monolith.incident_triage for insert to monolith_app
  with check (
    exists (
      select 1 from monolith.security_events e
      where e.event_id = incident_triage.event_id
        and e.tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
    )
  );

drop policy if exists monolith_app_incident_triage_update
  on monolith.incident_triage;
create policy monolith_app_incident_triage_update
  on monolith.incident_triage for update to monolith_app
  using (
    exists (
      select 1 from monolith.security_events e
      where e.event_id = incident_triage.event_id
        and e.tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
    )
  )
  with check (
    exists (
      select 1 from monolith.security_events e
      where e.event_id = incident_triage.event_id
        and e.tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
    )
  );

drop policy if exists monolith_app_incident_audit_select
  on monolith.incident_audit;
create policy monolith_app_incident_audit_select
  on monolith.incident_audit for select to monolith_app
  using (
    exists (
      select 1 from monolith.security_events e
      where e.event_id = incident_audit.event_id
        and e.tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
    )
  );

drop policy if exists monolith_app_incident_audit_insert
  on monolith.incident_audit;
create policy monolith_app_incident_audit_insert
  on monolith.incident_audit for insert to monolith_app
  with check (
    exists (
      select 1 from monolith.security_events e
      where e.event_id = incident_audit.event_id
        and e.tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
    )
  );

drop policy if exists monolith_app_benchmark_runs_select
  on monolith.benchmark_runs;
create policy monolith_app_benchmark_runs_select
  on monolith.benchmark_runs for select to monolith_app
  using (
    tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
  );

drop policy if exists monolith_app_benchmark_runs_insert
  on monolith.benchmark_runs;
create policy monolith_app_benchmark_runs_insert
  on monolith.benchmark_runs for insert to monolith_app
  with check (
    tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
  );

drop policy if exists monolith_app_operator_sessions_select
  on monolith.operator_sessions;
create policy monolith_app_operator_sessions_select
  on monolith.operator_sessions for select to monolith_app
  using (
    session_hash = nullif(current_setting('monolith.session_hash', true), '')
  );

drop policy if exists monolith_app_operator_sessions_insert
  on monolith.operator_sessions;
create policy monolith_app_operator_sessions_insert
  on monolith.operator_sessions for insert to monolith_app
  with check (
    tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
  );

drop policy if exists monolith_app_operator_sessions_update
  on monolith.operator_sessions;
create policy monolith_app_operator_sessions_update
  on monolith.operator_sessions for update to monolith_app
  using (
    session_hash = nullif(current_setting('monolith.session_hash', true), '')
  )
  with check (
    session_hash = nullif(current_setting('monolith.session_hash', true), '')
  );
