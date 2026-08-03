-- Durable, tenant-isolated outbound alert delivery. Critical evidence is
-- committed together with its webhook job; a separate runtime worker handles
-- network delivery so collector availability never depends on the receiver.

create table if not exists monolith.alert_outbox (
  event_id uuid primary key references monolith.security_events(event_id) on delete cascade,
  tenant_id text not null,
  payload jsonb not null,
  status text not null default 'pending'
    check (status in ('pending', 'delivered', 'dead')),
  attempts integer not null default 0 check (attempts >= 0),
  next_attempt_at timestamptz not null default now(),
  last_error text,
  created_at timestamptz not null default now(),
  delivered_at timestamptz
);

create index if not exists alert_outbox_due_idx
  on monolith.alert_outbox (tenant_id, next_attempt_at, created_at)
  where status = 'pending';

alter table monolith.alert_outbox enable row level security;
revoke all on monolith.alert_outbox from public, anon, authenticated, monolith_app;
grant select, insert, update on monolith.alert_outbox to monolith_app;

drop policy if exists monolith_app_alert_outbox_select on monolith.alert_outbox;
create policy monolith_app_alert_outbox_select
  on monolith.alert_outbox for select to monolith_app
  using (
    tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
  );

drop policy if exists monolith_app_alert_outbox_insert on monolith.alert_outbox;
create policy monolith_app_alert_outbox_insert
  on monolith.alert_outbox for insert to monolith_app
  with check (
    tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
  );

drop policy if exists monolith_app_alert_outbox_update on monolith.alert_outbox;
create policy monolith_app_alert_outbox_update
  on monolith.alert_outbox for update to monolith_app
  using (
    tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
  )
  with check (
    tenant_id = nullif(current_setting('monolith.tenant_id', true), '')
  );

create or replace function monolith.prune_alert_deliveries(
  retain_for interval default interval '30 days'
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
  delete from monolith.alert_outbox
  where status in ('delivered', 'dead')
    and created_at < pg_catalog.now() - retain_for;
  get diagnostics removed = row_count;
  return removed;
end;
$$;

revoke all on function monolith.prune_alert_deliveries(interval)
  from public, anon, authenticated, monolith_app;
