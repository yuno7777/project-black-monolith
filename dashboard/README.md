# Unified Dashboard

**Project Black Monolith — real-time threat dashboard (Next.js 15)**

A single live view of detection events from all three defense modules
(MCP-Shield, VectorAnchor, TraceAudit). Events stream in over Server-Sent
Events — no polling — and render in one unified feed, color-coded by module
and by severity, with a live session summary and per-module status.

## Integration choice

All three modules already emit the shared Project Black Monolith event JSON
(`timestamp_ms`, `module`, `event_type`, `severity`, `details`). The
lowest-effort reliable integration is therefore **each module POSTs that JSON
to this dashboard's `/api/ingest` endpoint** (set `MONOLITH_DASHBOARD_URL` on
each module). No message queue, no log-file tailing, no shared volume.

```text
  MCP-Shield ─┐                      ┌─▶ Postgres ledger ─┐
  VectorAnchor├─POST /api/ingest ───▶│   (persist first)  │─SSE /api/events─▶ browser
  TraceAudit ─┘  Bearer <token>      └─▶ in-process broker┘   (replay + live)
     │                                    (fan-out only)
     └── durable on-disk outbox: spool → retry → dead-letter
```

Each module spools every event to a local outbox and fsyncs it *before* the
detection path continues, then delivers asynchronously with exponential
backoff. The dashboard being down costs delivery latency, not evidence.

- `lib/event-ingest.ts` — process-wide singleton broker: a bounded ring
  buffer of recent events plus a subscriber set. Stored on `globalThis` so it
  survives dev hot-reloads and is shared across route handlers.
- `app/api/ingest/route.ts` — `POST` accepts one event or an array; `GET` is a
  liveness probe.
- `app/api/events/route.ts` — `GET` SSE stream: replays the recent buffer to a
  newly-connected client, then streams new events live, with keep-alives and
  clean teardown on disconnect.
- `app/page.tsx` — client component; subscribes via `EventSource`, de-dupes by
  sequence number, derives all stats client-side.
- `lib/incident-store.ts` — the investigation queue and incident lifecycle.
- `app/api/incidents/route.ts` — `GET` the queue (filtered, worst-first), `POST`
  a triage transition.
- `app/api/incidents/[eventId]/audit/route.ts` — `GET` one incident's trail.
- `app/investigate/page.tsx` — the queue UI.
- `app/components/` — `ThreatFeed` (newest-first, click to expand),
  `ModuleStatusCard` (per-module status + counts), `SessionSummary` (totals,
  severity distribution, per-layer breakdown, avg detection latency),
  `EventDetail` (full payload).

Because ingest is a plain HTTP endpoint, the feed also works without the other
services running — `curl -X POST localhost:3000/api/ingest -d '{...}'` pushes a
synthetic event straight onto the live feed.

## Run

```sh
cd dashboard
npm install
npm run dev        # http://localhost:3000
# or: npm run build && npm start
```

Then generate traffic by running any module's `fixtures/run_demo.sh` with
`MONOLITH_DASHBOARD_URL=http://localhost:3000/api/ingest` set, or the
root `run_full_demo.sh` against the full Docker stack.

## Design notes

- **Dark, technical aesthetic**, system-ui/sans-serif (not monospace), per the
  project styling preference. Modules are color-coded — MCP-Shield (blue),
  VectorAnchor (teal), TraceAudit (violet) — and severity by info/warning/
  critical.
- **Latency** in the summary averages `details.detection_latency_ms` (or
  `latency_ms`) across events that carry it.
- **Ingest is authenticated.** Every POST carries a per-module bearer token
  (`EVENT_INGEST_TOKENS_JSON`), compared with `timingSafeEqual` and scoped to
  a single module, so one module's credential cannot forge another's events.
  An unknown or cross-module token is a 401.
- **Events are persisted**, not just buffered: they are written to the
  Postgres ledger before being published to SSE, and a newly connected client
  is replayed that history. `event_id` is the primary key, so a module that
  retries an uncertain delivery is deduplicated (`accepted: 0,
  duplicates: 1`) rather than double-inserted. The in-process broker is now
  only a live fan-out over the durable store.
- A supplied `event_id` must be a UUID (the column is a Postgres `uuid`); a
  malformed one is a permanent 422 rather than a 503 that outboxes would
  retry forever.

## Investigation queue (`/investigate`)

The live feed answers "what is happening"; the queue answers "what has anyone
done about it". It reads the persisted ledger — not the SSE stream — filtered by
status, severity, module, time window and free text, ordered **worst-first then
newest-first**, and supports assigning, acknowledging and resolving.

Design notes:

- **Triage is stored separately from the event.** `security_events` stays an
  immutable record of what the detectors saw; `incident_triage` holds human
  judgement *about* an event. Nothing an analyst does mutates evidence.
- **An event with no triage row reads as `new`**, synthesized on read. Back-
  filling a triage row at ingest would put an extra write on the detection path
  for every event, and the queue treats "never looked at" and "new" alike.
- **Resolving requires a verdict** (`true_positive` / `false_positive` /
  `benign` / `duplicate`), enforced by a CHECK constraint as well as the API.
  Without it a "resolved" queue is just a hidden queue, and the false-positive
  rate — the number this project is evaluated on — could never be recovered.
- **`incident_audit` is append-only**, enforced by a trigger rather than a
  `REVOKE`, because a REVOKE would not bind the table's owner, which is the role
  the app connects as. Each transition and its resulting state are written in
  the **same transaction** as the state change.
- Omitting a field on a transition means "leave it alone", not "clear it" —
  otherwise resolving an incident without restating the assignee would silently
  unassign it. `resolution` is the deliberate exception: reopening clears the
  stale verdict.
- The queue **polls every 15s rather than subscribing to SSE**. It is a working
  surface, and re-sorting rows under an analyst's cursor mid-triage would be
  hostile.

## Operator authentication

Triage is authenticated with an **operator token** (`OPERATOR_TOKENS_JSON`, an
operator-name-to-token map; `scripts/generate_secrets.sh` writes one). This is
deliberately separate from the per-module ingest tokens: those identify a
*module*, and if one worked here any module could close its own findings.

The property that matters is that **the actor is derived from the token and is
never read from the request body**. An actor a caller can name itself records
only what it wished to be called — that is not evidence, and it is worse than an
empty trail because it looks like one. For the same reason the client cannot
assign work to itself by name: "take this" is sent as `assign_to_me: true` and
the server resolves it to whoever the credential authenticates as.

If `OPERATOR_TOKENS_JSON` is missing or malformed the endpoint returns **503 and
refuses every write**. An authenticator that was never configured must never be
mistaken for one that passed.

> [!IMPORTANT]
> **Known gaps.** `GET /api/incidents` is *not* authenticated — the read path
> exposes only what the dashboard already renders on a single-operator local
> stack, but it is a real hole anywhere else. The token is a bearer credential
> held in `localStorage`, so anything with access to the browser profile has it,
> and there is no session management, expiry, or rotation. This is honest
> single-operator auth, not an identity layer; a multi-user deployment needs
> real sessions in front of these routes.
