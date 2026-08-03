-- Durable live delivery, cursor pagination, and explicit retention controls.

create index if not exists security_events_tenant_cursor_idx
  on monolith.security_events (tenant_id, received_at desc, event_id desc);

create index if not exists security_events_details_search_idx
  on monolith.security_events using gin (
    to_tsvector('simple', coalesce(details::text, ''))
  );

create or replace function monolith.notify_security_event()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  perform pg_catalog.pg_notify(
    'monolith_security_events',
    pg_catalog.json_build_object(
      'event_id', new.event_id,
      'tenant_id', new.tenant_id
    )::text
  );
  return new;
end;
$$;

revoke all on function monolith.notify_security_event() from public, anon, authenticated;

drop trigger if exists notify_security_event_insert on monolith.security_events;
create trigger notify_security_event_insert
after insert on monolith.security_events
for each row execute function monolith.notify_security_event();

-- Session garbage collection is tenant-scoped by RLS. The dashboard only
-- deletes rows that are already expired or revoked.
grant delete on monolith.operator_sessions to monolith_app;

drop policy if exists monolith_app_operator_sessions_delete
  on monolith.operator_sessions;
create policy monolith_app_operator_sessions_delete
  on monolith.operator_sessions for delete to monolith_app
  using (
    tenant_id = coalesce(
      nullif(current_setting('monolith.tenant_id', true), ''),
      'default'
    )
    and (expires_at <= now() or revoked_at is not null)
  );

-- Security evidence stays append-only to the application role. Database
-- owners may invoke this bounded maintenance function from their scheduler.
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
  delete from monolith.security_events
  where received_at < pg_catalog.now() - retain_for;
  get diagnostics removed = row_count;
  return removed;
end;
$$;

revoke all on function monolith.prune_security_events(interval)
  from public, anon, authenticated, monolith_app;
