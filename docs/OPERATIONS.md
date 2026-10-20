# Operations runbook

The `/operations` page is the live control-plane view for one authenticated
tenant. It reconciles evidence already committed to PostgreSQL with the
delivery state reported by the two long-running Python defenses every 15
seconds.

## What the page means

| Signal | Source | Interpretation |
| --- | --- | --- |
| Ledger events | `security_events` | Durable evidence visible to the operator tenant |
| Database response | Timed tenant-scoped ledger query | Control-plane query latency, not detector latency |
| Last evidence | Newest event for each defense layer | Evidence age; absence is shown explicitly |
| Policy versions | Event envelope `policy_version` | Detector/enforcement versions observed in the ledger |
| Queued delivery | `/stats` on VectorAnchor and TraceAudit | Events preserved locally but not yet accepted by ingest |
| Dead letters | `/stats` on VectorAnchor and TraceAudit | Permanently rejected deliveries requiring investigation |
| Runtime | Authenticated `/stats` probe | Reachability from the dashboard, not proof that detection is correct |
| Alert queue | `alert_outbox` | Critical webhooks pending, delivered, or permanently rejected |

MCP-Shield is short-lived and uses a durable JSONL spool plus a resident
`--drain-outbox` process. Its policy and evidence freshness appear in the
ledger, but its local spool count is not currently exposed through an HTTP
runtime probe.

## Required runtime configuration

```text
MONOLITH_MODULE_ADMIN_TOKEN=<shared service-admin credential>
VECTOR_ANCHOR_INTERNAL_URL=http://vector-anchor:8001
TRACE_AUDIT_INTERNAL_URL=http://trace-audit:8002
```

When a URL or token is absent, the page says **Not configured**. A failed or
timed-out probe says **Unavailable**. Neither state is silently presented as a
healthy zero.

## Incident evidence export

Any viewer can download `/api/incidents/<event-id>/export`. The versioned
`project-black-monolith/evidence-bundle@1` JSON contains:

- the immutable event as received;
- current incident/triage state;
- the append-only audit trail;
- the tenant-scoped correlated session when identity is complete.

The export is an investigation handoff, not a cryptographic archive. Preserve
the file with your case system's normal hashing/signing procedure if external
chain-of-custody guarantees are required.

## Critical webhook alerts

Set both values to enable the feature; leaving both unset disables it:

```text
MONOLITH_ALERT_WEBHOOK_URL=https://alerts.example.test/monolith
MONOLITH_ALERT_WEBHOOK_SECRET=<32-512 character HMAC secret>
```

Critical events and their alert jobs commit in one database transaction. The
dispatcher POSTs `project-black-monolith/critical-alert@1` JSON with:

```text
X-Monolith-Event-Id: <stable idempotency key>
X-Monolith-Timestamp: <Unix milliseconds>
X-Monolith-Signature: sha256=<hex HMAC>
```

The signature input is `<timestamp>.<raw request body>`. Receivers should reject
stale timestamps, compare the HMAC in constant time, and deduplicate by event
ID. Redirects are not followed. Network errors, 408, 429, and 5xx retry with
bounded exponential backoff; other non-2xx responses and ten exhausted attempts
become dead letters. Production destinations require HTTPS; HTTP is accepted
only for loopback test receivers.

## Cross-layer session circuit breaker

When independent defenses agree that a session is compromised, the dashboard
revokes it and every layer stops serving that identity. A single detector hit
is a finding; agreement across layers is treated as an active compromise.

- **Trip condition.** Two distinct modules (default) report a `critical` event
  for the same `(tenant_id, agent_id, session_id)`. `MONOLITH_CIRCUIT_BREAKER_MIN_LAYERS`
  changes the layer count (1–3) and `MONOLITH_CIRCUIT_BREAKER_MIN_SEVERITY`
  (`critical` default, `warning`, or `info`) lowers the severity bar.
- **Enforcement.** MCP-Shield answers `tools/call` with an `isError` result;
  VectorAnchor returns no results and `session_quarantined: true`; TraceAudit
  terminates with `reason: "session_revoked"` (streaming) or a
  `content_filter` refusal (OpenAI-compatible response).
- **Propagation.** Modules adopt the revoked-session set from every ingest
  response and poll `GET /api/sessions/revoked` every
  `MONOLITH_SESSION_POLL_MS` (default 15 s, `0` disables) so an idle session
  is still cut off. The poll uses the module's existing ingest credential.
- **Fail closed.** A failed or malformed refresh leaves the previous set in
  place; only an authoritative snapshot can lift a revocation. Revocations do
  not expire on a timer.
- **Manual control.** `POST /api/incidents/<event-id>/session` quarantines and
  `DELETE` restores; both require the `analyst` role. The same actions are
  available from the investigation queue. Restores propagate on the next
  ingest response or poll.
- **Restore is a watermark.** The ledger is append-only, so the detections
  that tripped the breaker stay on record. A restore therefore settles
  everything the session did up to that moment (kept as `restored_at` on the
  revocation row) instead of deleting the evidence: the old history cannot
  immediately re-revoke the session, but detections received after the restore
  can trip it again. The session drops out of `/api/sessions/revoked`
  immediately.
- **Visibility.** Each refusal emits one `session_quarantined` critical event
  per session, so repeated retries do not flood the ledger. Refusal events are
  consequences of a revocation, not evidence, so the breaker never counts them
  toward a new trip.

## Retention and cleanup

Evidence is append-only to the dashboard runtime. A database owner may schedule
bounded retention explicitly, per tenant:

```sql
select monolith.prune_security_events('default', interval '90 days');
select monolith.prune_alert_deliveries('default', interval '30 days');
```

Both functions take the tenant they prune. The evidence prune never touches
another tenant, and it never removes the evidence of an incident that has not
been resolved, so a scheduled retention job cannot destroy an open
investigation. The alert prune is called by the alert dispatcher itself, under
the tenant's row-level-security context.

The functions accept one day through ten years and are revoked from the
runtime role, with the exception of the alert prune, which the dispatcher
calls for the tenants it serves. Operator session cleanup is narrower: the
application may delete only rows that are already expired or revoked, under
the active tenant's RLS context.

## First response checklist

1. Check dead letters before queue depth; permanent rejection needs a config or
   contract fix, while pending delivery may simply be retrying an outage.
2. Compare last-evidence age with the expected traffic level. A quiet detector
   and an unreachable detector are different states.
3. Confirm every active layer reports the expected policy version.
4. Open the investigation, export its evidence bundle, and preserve the audit
   trail before coordinating outside the dashboard.
5. Re-run the deterministic evaluation profile after any detector or policy
   change; use the real profile only when its external backends are available.
