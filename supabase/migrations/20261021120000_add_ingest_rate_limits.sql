-- Rate limits for the event ingest path.
--
-- The operator login path already had a throttle. The ingest path had none,
-- so one module — or one module whose spool had gone wrong — could file
-- thousands of events a minute and push the real detection out of the
-- operator's view of the ledger before anyone looked.
--
-- The budget belongs to a module credential, not to a source address: the
-- credential is what identifies a module, one address may host several
-- modules, and an address is something a caller can change. The counter
-- therefore holds events rather than requests, because a module that posted
-- one event per request would otherwise spend a request budget one event at
-- a time and never meet the limit.

create table if not exists monolith.ingest_rate_limits (
  key_hash text primary key check (key_hash ~ '^[0-9a-f]{64}$'),
  window_started timestamptz not null,
  -- The ceiling is a million events, not the login table's thousand. This
  -- counter holds events and the default budget is two thousand of them, so
  -- a ceiling of a thousand would stop counting before the budget was ever
  -- reached and the limit would never fire. The ceiling still has to sit
  -- above the largest budget an operator can configure, which is why the
  -- dashboard caps MONOLITH_INGEST_RATE_LIMIT_EVENTS at the same million.
  attempts integer not null check (attempts between 1 and 1000000)
);

revoke all on monolith.ingest_rate_limits from public, anon, authenticated, monolith_app;

create index if not exists ingest_rate_limits_window_started_idx
  on monolith.ingest_rate_limits (window_started);

create or replace function monolith.record_ingest_attempt(candidate_key text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_attempts integer;
  charged integer;
  budget integer;
begin
  if candidate_key !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid ingest rate-limit key';
  end if;

  -- The batch size and the operator's budget arrive as transaction-local
  -- settings, so the function keeps a single argument and the limit is
  -- configured in exactly one place: the dashboard that owns the modules.
  -- A setting that is absent means a caller that did not set one, which is
  -- charged the default budget of two thousand events.
  charged := coalesce(
    nullif(pg_catalog.current_setting('monolith.ingest_event_count', true), ''),
    '0'
  )::integer;
  budget := coalesce(
    nullif(pg_catalog.current_setting('monolith.ingest_event_budget', true), ''),
    '2000'
  )::integer;
  if charged < 1 then charged := 1; end if;
  if charged > 1000000 then charged := 1000000; end if;
  if budget < 1 then budget := 1; end if;

  insert into monolith.ingest_rate_limits (key_hash, window_started, attempts)
  values (candidate_key, pg_catalog.now(), charged)
  on conflict (key_hash) do update
  set
    attempts = case
      when ingest_rate_limits.window_started < pg_catalog.now() - interval '60 seconds'
        then charged
      else least(1000000, ingest_rate_limits.attempts + charged)
    end,
    window_started = case
      when ingest_rate_limits.window_started < pg_catalog.now() - interval '60 seconds'
        then pg_catalog.now()
      else ingest_rate_limits.window_started
    end
  returning attempts into current_attempts;

  -- The sweep is bounded. An unbounded sweep makes the request that grows
  -- the table also pay to clean it, which is a denial of service dressed up
  -- as housekeeping.
  delete from monolith.ingest_rate_limits
   where key_hash in (
     select key_hash
       from monolith.ingest_rate_limits
      where window_started < pg_catalog.now() - interval '1 day'
      limit 512
   );

  return current_attempts <= budget;
end;
$$;

revoke all on function monolith.record_ingest_attempt(text)
  from public, anon, authenticated;
grant execute on function monolith.record_ingest_attempt(text) to monolith_app;
