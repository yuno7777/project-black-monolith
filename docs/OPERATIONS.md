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

## Retention and cleanup

Evidence is append-only to the dashboard runtime. A database owner may schedule
bounded retention explicitly:

```sql
select monolith.prune_security_events(interval '90 days');
```

The function accepts one day through ten years and is revoked from the runtime
role. Operator session cleanup is narrower: the application may delete only
rows that are already expired or revoked, under the active tenant's RLS
context.

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

