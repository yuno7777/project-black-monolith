-- A manual session restore has to outlive the ledger history that tripped the
-- breaker. Deleting the revocation row is not enough: the session's earlier
-- critical events remain in the immutable ledger, so the next event for that
-- session re-runs the breaker against that history and re-revokes immediately.
--
-- Keep the row as a watermark instead. `restored_at` means "everything this
-- session did before this instant has already been judged"; only detections
-- received after it may trip the breaker again. The row stays because a fresh
-- trip needs somewhere to record its own revocation.

alter table monolith.revoked_sessions
  add column if not exists restored_at timestamptz;

comment on column monolith.revoked_sessions.restored_at is
  'When an analyst restored the session. Detections received before this instant do not count toward an automatic re-trip.';

-- The module-facing snapshot only ever asks for live revocations, so keep that
-- lookup cheap no matter how many restored rows accumulate.
create index if not exists revoked_sessions_active_tenant_idx
  on monolith.revoked_sessions (tenant_id, revoked_at desc)
  where restored_at is null;
