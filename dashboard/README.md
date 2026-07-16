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
