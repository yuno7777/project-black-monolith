-- Incident lifecycle on top of the event ledger.
--
-- security_events stays exactly what it is: an immutable record of what the
-- detectors saw. Triage is human judgement *about* an event, so it lives in a
-- separate table rather than as mutable columns on the evidence itself.

create table if not exists monolith.incident_triage (
  event_id uuid primary key
    references monolith.security_events (event_id) on delete cascade,
  status text not null default 'new'
    check (status in ('new', 'acknowledged', 'resolved')),
  assignee text check (assignee is null or length(assignee) between 1 and 128),
  note text check (note is null or length(note) <= 2000),
  resolution text
    check (resolution is null or resolution in ('true_positive', 'false_positive', 'benign', 'duplicate')),
  updated_at timestamptz not null default now(),
  updated_by text not null,
  -- A resolved incident must say what it was resolved *as*. Without this a
  -- "resolved" queue is just a hidden queue, and the false-positive rate — the
  -- number this project is actually evaluated on — can never be recovered.
  constraint resolved_needs_a_resolution
    check (status <> 'resolved' or resolution is not null)
);

create index if not exists incident_triage_status_updated_idx
  on monolith.incident_triage (status, updated_at desc);

-- Append-only transition log. The triage row holds current state; this holds
-- how it got there. For a security tool the trail is the point: "who cleared
-- this critical, when, and why" must survive later edits.
create table if not exists monolith.incident_audit (
  audit_id bigint generated always as identity primary key,
  event_id uuid not null
    references monolith.security_events (event_id) on delete cascade,
  at timestamptz not null default now(),
  actor text not null,
  from_status text,
  to_status text not null,
  assignee text,
  resolution text,
  note text
);

create index if not exists incident_audit_event_at_idx
  on monolith.incident_audit (event_id, at desc);

-- Enforce append-only in the database rather than by convention. A REVOKE
-- would not bind the table's owner, which is the role the app connects as, so
-- the guarantee has to be a trigger.
create or replace function monolith.incident_audit_is_append_only()
returns trigger
language plpgsql
as $$
begin
  raise exception 'monolith.incident_audit is append-only (attempted %)', tg_op;
end;
$$;

drop trigger if exists incident_audit_no_update on monolith.incident_audit;
create trigger incident_audit_no_update
  before update or delete on monolith.incident_audit
  for each row execute function monolith.incident_audit_is_append_only();

alter table monolith.incident_triage enable row level security;
alter table monolith.incident_audit enable row level security;
revoke all on monolith.incident_triage from public, anon, authenticated;
revoke all on monolith.incident_audit from public, anon, authenticated;
