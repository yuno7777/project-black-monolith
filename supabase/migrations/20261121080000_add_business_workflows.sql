create table monolith.business_agents (
  tenant_id text not null,
  agent_id text not null,
  owner text not null,
  allowed_kinds text[] not null,
  paused boolean not null,
  practice_only boolean not null default true,
  updated_at timestamptz not null default clock_timestamp(),
  primary key (tenant_id, agent_id)
);

create table monolith.business_policies (
  tenant_id text primary key,
  policy jsonb not null
);

create table monolith.business_cases (
  tenant_id text not null,
  case_id text not null,
  template_id text not null,
  primary key (tenant_id, case_id)
);

create table monolith.business_decisions (
  tenant_id text not null,
  id uuid not null default gen_random_uuid(),
  agent_id text not null,
  session_id text not null,
  request_id uuid not null,
  case_id text not null,
  template_id text not null,
  action jsonb not null,
  digest text not null check (digest ~ '^[0-9a-f]{64}$'),
  reviewer_team text not null,
  reason text not null,
  status text not null default 'pending' check (status in
     ('pending','dispatching','denied','changes_requested','succeeded','failed','uncertain','expired','stale','revoked')),
  reviewer text,
  reference text,
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null default (clock_timestamp() + interval '15 minutes'),
  reviewed_at timestamptz,
  primary key (tenant_id, id),
  unique (tenant_id, agent_id, session_id, request_id),
  foreign key (tenant_id, case_id) references monolith.business_cases,
  foreign key (tenant_id, agent_id) references monolith.business_agents
);
-- A lost acknowledgment must never unlock a second payment for the same case.
create unique index business_case_one_refund on monolith.business_decisions (tenant_id, case_id)
  where action->>'kind' = 'refund' and status in ('dispatching','uncertain','succeeded');
create index business_decision_time on monolith.business_decisions (tenant_id, created_at desc, id desc);

create table monolith.business_activity (
  tenant_id text not null,
  id uuid not null default gen_random_uuid(),
  decision_id uuid,
  actor text not null,
  event text not null,
  note text not null,
  created_at timestamptz not null default clock_timestamp(),
  primary key (tenant_id,id),
  foreign key (tenant_id,decision_id) references monolith.business_decisions
);
create index business_activity_time on monolith.business_activity (tenant_id,created_at desc,id desc);

do $$
declare rel text;
begin
  foreach rel in array array['business_agents','business_policies','business_cases','business_decisions','business_activity']
  loop
    execute format('alter table monolith.%I enable row level security', rel);
    execute format('create policy tenant_scope on monolith.%I to monolith_app
      using (tenant_id = nullif(current_setting(''monolith.tenant_id'', true), ''''))
      with check (tenant_id = nullif(current_setting(''monolith.tenant_id'', true), ''''))', rel);
    execute format('revoke all on monolith.%I from public, monolith_app', rel);
    execute format('grant select on monolith.%I to monolith_app', rel);
  end loop;
end $$;

grant insert (tenant_id,agent_id,owner,allowed_kinds,paused,practice_only), update (owner,allowed_kinds,paused,practice_only,updated_at)
  on monolith.business_agents to monolith_app;
grant insert (tenant_id,policy), update (policy) on monolith.business_policies to monolith_app;
grant insert (tenant_id,case_id,template_id) on monolith.business_cases to monolith_app;
grant insert (tenant_id,id,agent_id,session_id,request_id,case_id,template_id,action,digest,reviewer_team,reason),
  update (status,reviewer,reviewed_at,reference) on monolith.business_decisions to monolith_app;
grant insert (tenant_id,decision_id,actor,event,note) on monolith.business_activity to monolith_app;
