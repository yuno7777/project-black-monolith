-- A bounded revocation snapshot needs a way to say "this is the whole set".
--
-- The snapshot a module polls is bounded, because the module reads it with a
-- 64 KiB cap and an unbounded body is cut short, fails to parse, and leaves
-- the module serving a session that was revoked a moment ago. A bounded body
-- that a module cannot interpret is worse than no body at all: the module
-- would replace its local set with a partial one and un-revoke everything
-- that was missing.
--
-- So the body says whether it is complete, and the tenant's live revoked set
-- carries a revision that advances whenever the set changes. A count is not
-- enough — the same count can mean two different sets — and a timestamp
-- cannot be compared across two readers.

-- ---------------------------------------------------------------------------
-- The per-tenant revision counter.

create table if not exists monolith.revocation_revisions (
  tenant_id text primary key check (length(tenant_id) between 1 and 128),
  revision bigint not null default 0 check (revision >= 0)
);

comment on table monolith.revocation_revisions is
  'The per-tenant revision of the live revoked set. Advanced by a trigger on monolith.revoked_sessions, never by application code.';

-- The counter is written only by the trigger, which reaches it through a
-- security definer function. No runtime role holds a privilege on the table
-- at all, so row level security is enabled as a second line of defence but
-- deliberately not forced: forcing it would put the owner under the policies
-- too, and the owner is the only writer.
alter table monolith.revocation_revisions enable row level security;

revoke all on monolith.revocation_revisions from public, anon, authenticated, monolith_app;

-- A tenant that already holds live revocations when the counter is created is
-- not at revision 0: revision 0 means nothing is revoked. The counter starts
-- the tenant off at 1 so that the first change moves it to 2, and the
-- revision a reader sees is never a claim that a revoked tenant is empty.
insert into monolith.revocation_revisions as r (tenant_id, revision)
select distinct tenant_id, 1
  from monolith.revoked_sessions
 where restored_at is null
on conflict (tenant_id) do update set revision = greatest(r.revision, 1);

-- ---------------------------------------------------------------------------
-- Advancing the counter.

create or replace function monolith.advance_revocation_revision(tenant text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tenant is null or pg_catalog.length(tenant) = 0 then
    return;
  end if;
  insert into monolith.revocation_revisions as r (tenant_id, revision)
  values (tenant, 1)
  on conflict (tenant_id) do update set revision = r.revision + 1;
end;
$$;

revoke all on function monolith.advance_revocation_revision(text)
  from public, anon, authenticated, monolith_app;

-- The revision advances when the tenant's live revoked set changes, and not
-- when a row is rewritten without changing whether it is live. The upsert
-- that re-revokes an already-revoked session rewrites the reason and the
-- layer list and leaves the set exactly as it was; a revision that moved on
-- every rewrite would stop being a change detector and would make every
-- module re-read the snapshot for nothing.
create or replace function monolith.bump_revocation_revision()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tg_op = 'DELETE' then
    if old.restored_at is null then
      perform monolith.advance_revocation_revision(old.tenant_id);
    end if;
    return old;
  end if;
  if tg_op = 'INSERT' then
    if new.restored_at is null then
      perform monolith.advance_revocation_revision(new.tenant_id);
    end if;
    return new;
  end if;
  if old.tenant_id is distinct from new.tenant_id then
    perform monolith.advance_revocation_revision(old.tenant_id);
    perform monolith.advance_revocation_revision(new.tenant_id);
  elsif (old.restored_at is null) is distinct from (new.restored_at is null) then
    perform monolith.advance_revocation_revision(new.tenant_id);
  end if;
  return new;
end;
$$;

revoke all on function monolith.bump_revocation_revision()
  from public, anon, authenticated, monolith_app;

drop trigger if exists revoked_sessions_revision on monolith.revoked_sessions;
create trigger revoked_sessions_revision
  after insert or update or delete on monolith.revoked_sessions
  for each row execute function monolith.bump_revocation_revision();

-- ---------------------------------------------------------------------------
-- Reading the counter.

-- The revision is read through a function rather than off the table so that
-- the runtime role never holds a privilege on the counter. The tenant comes
-- from the transaction-local setting, exactly as the row level security
-- policies read it, so a module cannot ask for another tenant's revision by
-- naming it.
create or replace function monolith.revocation_revision()
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  tenant text;
begin
  tenant := nullif(pg_catalog.current_setting('monolith.tenant_id', true), '');
  if tenant is null then
    raise exception 'tenant context is not set';
  end if;
  return coalesce(
    (select r.revision from monolith.revocation_revisions r where r.tenant_id = tenant),
    0
  );
end;
$$;

revoke all on function monolith.revocation_revision()
  from public, anon, authenticated;
grant execute on function monolith.revocation_revision() to monolith_app;
