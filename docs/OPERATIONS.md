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

## Onboarding a new agent

`/onboarding` is the operator's route from "the stack is up" to "my agent is
behind it and the dashboard shows what it tripped". It reads the same signals
the `/operations` page reads, plus the host-side facts that only the machine
running the agent can answer.

`GET /api/onboarding` (viewer) returns one object:

| Field | Meaning |
| --- | --- |
| `stack.modules[]` | Per-layer reachability from the dashboard |
| `corpus` | Document and quarantine counts read from VectorAnchor `/stats` |
| `shield_binary` | Where the tool layer's binary is, or that the dashboard cannot see the host |
| `sessions[]` | Recent agent sessions, newest first |
| `steps[]` | The checklist, each `ready` / `todo` / `blocked` / `unknown` |

`POST /api/onboarding` (admin) takes
`{"action": "seed-corpus" | "seed-bait" | "reset-detection"}` and performs the
setup step server-side against VectorAnchor. An unknown action is a 422, and
nothing is called before the action has been validated.

`GET /api/sessions?limit=` (viewer) is the discovery side of the ledger.
`/api/sessions/<id>` answers 200 with zero events for a session that never
happened, so it cannot answer "is my agent connected yet?"; the list route can.
A `limit` outside 1-100 is a 422.

### What the page will not do

- It never renders a credential. The launcher reads the repository's own
  `.env`, so the command the page renders carries no secret, and the module
  admin token stays on the server.
- It does not start the agent or build the tool layer. Those happen on the
  machine that runs the agent, so the page renders the command rather than
  pretending to have run it.
- The tool-layer check reports **not checked** when the dashboard runs in a
  container: that host is not this filesystem, and saying *missing* would be
  wrong.

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
  `0` is the only way to turn the poll off: a cadence the module cannot read
  — a sub-second value, a typo, a number with a unit suffix — falls back to
  the default and says so, rather than leaving a revoked session running
  with nothing to show for it.
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

### The revocation snapshot is bounded

Modules learn the tenant's revoked set from two places: the `revoked_sessions`
list in every ingest response, and `GET /api/sessions/revoked`, which a module
with no event traffic polls. Both bodies are **bounded**, because both are
read with a 64 KiB cap (`MAX_SNAPSHOT_BYTES` in the Python emitter,
`MAX_INGEST_RESPONSE_BYTES` in MCP-Shield's spool). A body that does not fit
is cut short: it fails to parse, the module keeps the set it already had, and
a session revoked a moment ago is still served. The revocation path has to
fail closed, so the body has to fit — for every tenant, and whatever
identifiers the tenant's agents choose.

The snapshot body:

```json
{
  "tenant_id": "default",
  "generated_at_ms": 1750000000000,
  "revision": 42,
  "complete": true,
  "truncated": false,
  "revoked_sessions": ["session-a", "session-b"],
  "revocations": [
    { "session_id": "session-a", "agent_id": "agent-1", "revoked_at_ms": 1750000000000 }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `tenant_id` | The tenant the snapshot describes |
| `generated_at_ms` | When the snapshot was read |
| `revision` | The tenant's revision of its live revoked set |
| `complete` | True when the body carries the tenant's **entire** live revoked set |
| `truncated` | The same fact from the other side: true when the set did not fit |
| `revoked_sessions` | The live revoked session ids, newest first |
| `revocations` | The same revocations, each with its agent id and revocation time |

`revoked_sessions` stays a flat array of ids so a module that predates the
bounded snapshot still reads it. `revocations` carries the same entries plus
the agent id, because the ledger's revocation key is
`(tenant_id, agent_id, session_id)` — a session id alone does not identify a
revocation.

**The cap and the arithmetic.** At most **128** live revocations, newest
first. Every revocation is carried twice, and at the longest identifier the
schema allows (128 characters) that is:

```text
"revoked_sessions":  128 + 2 quotes + 1 comma                       = 131 bytes
"revocations":       13 + 130 + 1 + 11 + 130 + 1 + 15 + 13 digits + 2 = 316 bytes
                                                                   -----------
                                                                     447 bytes

128 revocations are 57,216 bytes, which with the envelope stays inside the
60 KiB budget; one more would not fit.
```

**A row cap is not a byte cap.** An identifier is agent-supplied, and JSON
escaping can make it six times longer than it is — a session id of 128 quote
characters serializes to 256 bytes. The row cap therefore cannot by itself
guarantee the body fits, so the body is also *measured*: the oldest entries
are dropped until the serialized body is inside the 60 KiB budget, and the
newest are kept, because a revocation the module has not seen yet is the one
it cannot do without. The 128 is the row cap from the arithmetic above; the
60 KiB budget is the guarantee.

**The revision.** A monotonically increasing integer per tenant, advanced by
a **trigger** on `monolith.revoked_sessions` whenever the tenant's live
revoked set changes — a new revocation, or a restore. A trigger, so no code
path can forget to advance it. It is 0 while nothing is revoked. A count is
not enough (the same count can mean two different sets) and a timestamp
cannot be compared across two readers.

**What a module does with the body.**

```text
complete: true                          -> replace the local revoked set
complete: false                         -> add to the local set, keep what it has
truncated read / unparseable body       -> leave the local set exactly as it was
```

The last line is reported as an error, not swallowed: a truncated body is not
a snapshot. It can parse as JSON and look authoritative while describing only
part of the revoked set. Only an authoritative snapshot can lift a
revocation, and only a failure can leave the module holding what it had.

**The threshold that is live until the module half ships.** The dashboard half
is bounded today; the module half that reads `complete` and `truncated` is
not in the running layers yet. Until it is, a module replaces its local set
wholesale, so **a tenant with more than 128 live revocations has only its
newest 128 enforced by the layers** — the older revocations are still in the
ledger and still reported by the dashboard, but the layers stop refusing
them. Below 128 live revocations the snapshot is complete and every layer
refuses every revoked session.

An operator can check where a tenant stands today:

```bash
curl -s -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_VECTOR_ANCHOR" \
  -H "x-monolith-tenant-id: $MONOLITH_TENANT_ID" \
  -H "x-monolith-module: vector-anchor" \
  http://localhost:3000/api/sessions/revoked
```

`complete: true` (with `truncated: false`) means the tenant is under the
threshold and the layers enforce the whole set. `complete: false` means the
tenant is at or over it, and `revision` says how far the set has moved since
it was last read. The same fact in SQL:

```sql
select tenant_id, count(*) as live_revocations
  from monolith.revoked_sessions
 where restored_at is null
 group by tenant_id
 order by live_revocations desc;
```

A tenant at 128 or more is over the threshold.

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
