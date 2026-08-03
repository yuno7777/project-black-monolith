-- Cross-instance login throttling. The table is reachable only through two
-- fixed-policy functions in the non-exposed monolith schema.

create table if not exists monolith.operator_login_limits (
  key_hash text primary key check (key_hash ~ '^[0-9a-f]{64}$'),
  window_started timestamptz not null,
  attempts integer not null check (attempts between 1 and 1000)
);

revoke all on monolith.operator_login_limits from public, anon, authenticated, monolith_app;

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
  where window_started < pg_catalog.now() - interval '24 hours';

  return current_attempts <= 8;
end;
$$;

create or replace function monolith.clear_operator_login_attempts(candidate_key text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if candidate_key ~ '^[0-9a-f]{64}$' then
    delete from monolith.operator_login_limits where key_hash = candidate_key;
  end if;
end;
$$;

revoke all on function monolith.record_operator_login_attempt(text)
  from public, anon, authenticated;
revoke all on function monolith.clear_operator_login_attempts(text)
  from public, anon, authenticated;
grant execute on function monolith.record_operator_login_attempt(text) to monolith_app;
grant execute on function monolith.clear_operator_login_attempts(text) to monolith_app;
