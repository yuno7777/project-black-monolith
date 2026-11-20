create table monolith.github_triage_actions (
  id uuid primary key default gen_random_uuid(),
  tenant_id text not null,
  agent_id text not null,
  session_id text not null,
  request_id uuid not null,
  repository text not null,
  issue integer not null check (issue > 0),
  kind text not null check (kind in ('reply', 'add_label', 'remove_label')),
  value text not null check (octet_length(value) between 1 and 12000),
  digest text not null check (digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null default (clock_timestamp() + interval '15 minutes'),
  status text not null default 'pending' check (status in (
    'pending', 'denied', 'dispatching', 'succeeded', 'failed', 'uncertain', 'expired', 'revoked'
  )),
  reviewer text,
  reviewed_at timestamptz,
  finished_at timestamptz,
  github_status integer,
  github_comment_id text,
  unique (tenant_id, agent_id, session_id, request_id)
);

create index github_triage_tenant_created_idx
  on monolith.github_triage_actions (tenant_id, created_at desc, id desc);

alter table monolith.github_triage_actions enable row level security;
create policy github_triage_tenant on monolith.github_triage_actions to monolith_app
  using (tenant_id = nullif(current_setting('monolith.tenant_id', true), ''))
  with check (tenant_id = nullif(current_setting('monolith.tenant_id', true), ''));

revoke all on monolith.github_triage_actions from public;
grant select on monolith.github_triage_actions to monolith_app;
grant insert (tenant_id, agent_id, session_id, request_id, repository, issue, kind, value, digest)
  on monolith.github_triage_actions to monolith_app;
grant update (status, reviewer, reviewed_at, finished_at, github_status, github_comment_id)
  on monolith.github_triage_actions to monolith_app;
