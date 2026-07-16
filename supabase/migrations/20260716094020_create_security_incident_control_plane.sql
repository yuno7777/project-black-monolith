create extension if not exists pgcrypto;
create schema if not exists monolith;

revoke all on schema monolith from public, anon, authenticated;

create table if not exists monolith.security_events (
  event_id uuid primary key,
  schema_version smallint not null default 1 check (schema_version between 1 and 2),
  occurred_at_ms bigint not null check (occurred_at_ms > 0),
  received_at timestamptz not null default now(),
  module text not null check (module in ('mcp-shield', 'vector-anchor', 'trace-audit')),
  event_type text not null,
  severity text not null check (severity in ('info', 'warning', 'critical')),
  details jsonb not null default '{}'::jsonb,
  agent_id text,
  session_id text,
  trace_id text,
  correlation_id text,
  resource_type text,
  resource_id text,
  outcome text,
  policy_version text,
  source text not null default 'module'
);

create index if not exists security_events_received_at_idx
  on monolith.security_events (received_at desc);
create index if not exists security_events_module_received_at_idx
  on monolith.security_events (module, received_at desc);
create index if not exists security_events_severity_received_at_idx
  on monolith.security_events (severity, received_at desc);
create index if not exists security_events_correlation_idx
  on monolith.security_events (correlation_id, received_at desc)
  where correlation_id is not null;
create index if not exists security_events_session_idx
  on monolith.security_events (session_id, received_at desc)
  where session_id is not null;
create index if not exists security_events_details_gin_idx
  on monolith.security_events using gin (details);

alter table monolith.security_events enable row level security;
revoke all on monolith.security_events from public, anon, authenticated;
