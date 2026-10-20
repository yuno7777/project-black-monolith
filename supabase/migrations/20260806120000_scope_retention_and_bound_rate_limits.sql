-- Tenant-scoped retention, protection for open investigations, and a bounded
-- rate-limit sweep.
--
-- The previous retention functions deleted by age alone. `security_events` is
-- a multi-tenant table, so one scheduled prune removed every tenant's
-- evidence in a single statement, and the cascade into `incident_audit`
-- destroyed the audit trail of investigations that were still open.
-- Retention is now explicit about which tenant it prunes, and an incident
-- that has not been resolved keeps its evidence.

-- ---------------------------------------------------------------------------
-- 1. Evidence retention is tenant-scoped and leaves open investigations alone.

drop function if exists monolith.prune_security_events(interval);

create or replace function monolith.prune_security_events(
  prune_tenant text,
  retain_for interval default interval '90 days'
)
returns bigint
language plpgsql
set search_path = ''
as $$
declare
  removed bigint;
begin
  if prune_tenant is null or length(prune_tenant) not between 1 and 128 then
    raise exception 'prune_tenant must be a tenant identifier of 1 to 128 characters';
  end if;
  if retain_for < interval '1 day' or retain_for > interval '10 years' then
    raise exception 'retain_for must be between 1 day and 10 years';
  end if;

  -- The append-only trigger on `incident_audit` permits the cascade only while
  -- this transaction-local flag is set. The flag is a convenience switch, not
  -- a security boundary: the invariant that a non-owner cannot delete audit
  -- rows is enforced by the absence of a DELETE grant.
  perform pg_catalog.set_config('monolith.retention_prune', 'on', true);

  delete from monolith.security_events e
   where e.tenant_id = prune_tenant
     and e.received_at < pg_catalog.now() - retain_for
     -- An incident that is still open keeps its evidence. Retention is a
     -- storage policy, not a way to lose an investigation.
     and not exists (
       select 1
         from monolith.incident_triage t
        where t.event_id = e.event_id
          and t.status <> 'resolved'
     );
  get diagnostics removed = row_count;
  return removed;
end;
$$;

revoke all on function monolith.prune_security_events(text, interval)
  from public, anon, authenticated, monolith_app;

-- ---------------------------------------------------------------------------
-- 2. Alert-delivery pruning is tenant-scoped and reachable by the dispatcher.
--
-- The dispatcher runs as `monolith_app` and called the previous global
-- overload, which is revoked from that role: every call raised a permission
-- error that the dispatcher swallowed, so delivered and dead alert rows were
-- never removed and the outbox grew without bound.

grant delete on monolith.alert_outbox to monolith_app;

drop policy if exists monolith_app_alert_outbox_delete on monolith.alert_outbox;
create policy monolith_app_alert_outbox_delete
  on monolith.alert_outbox for delete to monolith_app
  using (
    tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
  );

drop function if exists monolith.prune_alert_deliveries(interval);

create or replace function monolith.prune_alert_deliveries(
  prune_tenant text,
  retain_for interval default interval '30 days'
)
returns bigint
language plpgsql
set search_path = ''
as $$
declare
  removed bigint;
  active_tenant text;
begin
  if prune_tenant is null or length(prune_tenant) not between 1 and 128 then
    raise exception 'prune_tenant must be a tenant identifier of 1 to 128 characters';
  end if;
  if retain_for < interval '1 day' or retain_for > interval '10 years' then
    raise exception 'retain_for must be between 1 day and 10 years';
  end if;

  -- The caller must already be acting as this tenant. The delete is scoped
  -- by an explicit tenant filter as well as by row-level security, so the
  -- function cannot be used to reach another tenant's rows.
  active_tenant := nullif(current_setting('monolith.tenant_id', true), '');
  if active_tenant is null or active_tenant <> prune_tenant then
    raise exception 'prune_tenant must match the active tenant context';
  end if;

  delete from monolith.alert_outbox
   where tenant_id = prune_tenant
     and status in ('delivered', 'dead')
     and created_at < pg_catalog.now() - retain_for;
  get diagnostics removed = row_count;
  return removed;
end;
$$;

revoke all on function monolith.prune_alert_deliveries(text, interval)
  from public, anon, authenticated;
grant execute on function monolith.prune_alert_deliveries(text, interval) to monolith_app;

-- ---------------------------------------------------------------------------
-- 3. The failed-login sweep is bounded.
--
-- Every failed attempt deleted every row older than 24 hours, so the cost of
-- an unauthenticated request grew with the size of a table that the same
-- request could grow. The sweep now removes a bounded batch, and an index
-- makes finding the expired rows cheap.

create index if not exists operator_login_limits_window_started_idx
  on monolith.operator_login_limits (window_started);

create or replace function monolith.record_operator_login_attempt(candidate_key text)
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

  insert into monolith.operator_login_limits (key_hash, window_started, attempts)
  values (candidate_key, pg_catalog.now(), 1)
  on conflict (key_hash) do update
  set
    attempts = case
      when operator_login_limits.window_started < pg_catalog.now() - interval '15 minutes'
        then 1
      else least(1000, operator_login_limits.attempts + 1)
    end,
    window_started = case
      when operator_login_limits.window_started < pg_catalog.now() - interval '15 minutes'
        then pg_catalog.now()
      else operator_login_limits.window_started
    end
  returning attempts into current_attempts;

  delete from monolith.operator_login_limits
   where key_hash in (
     select key_hash
       from monolith.operator_login_limits
      where window_started < pg_catalog.now() - interval '24 hours'
      limit 512
   );

  return current_attempts <= 8;
end;
$$;

revoke all on function monolith.record_operator_login_attempt(text)
  from public, anon, authenticated;
grant execute on function monolith.record_operator_login_attempt(text) to monolith_app;
