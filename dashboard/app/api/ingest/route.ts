// POST /api/ingest — the endpoint each Monolith module POSTs its events to.
// Accepts a single event object or an array of them.
//
// THE INGEST PIPELINE (this route IS the delivery spine's receiver)
// -----------------------------------------------------------------
//   module outbox POST (JSON, single or batch of 1-100)
//    -> readJsonBody (256 KB hard cap)                  [request-body.ts]
//    -> normalizeEvent per event (STRICT validation)    [event-store.ts]
//    -> batch must be one module, one tenant
//    -> authenticateIngest (per-(tenant,module) token,  [ingest-auth.ts]
//        timing-safe comparison)
//    -> persistEvents (single tenant-scoped transaction,
//        `on conflict (event_id) do nothing`,           [event-store.ts]
//        critical + webhook -> alert_outbox row in the same transaction)
//    -> 201 { accepted, duplicates, event_ids }
//
// Error semantics (the modules' outboxes depend on these EXACTLY):
//   401/422/413/400 -> PERMANENT, dead-lettered, never retried.
//   503             -> transient, retried with backoff by the outbox.
// The poison-pill fix lives here: a malformed (non-UUID) event_id is a
// permanent 422, NOT a 503 — otherwise the outbox would retry forever.
//
// WHO CALLS IT
// ------------
//   python-common outbox (vector-anchor, trace-audit)
//   mcp-shield outbox.rs (Rust)
//   scripts/verify_ingest.sh (contract tests)
// GET is a liveness probe for the Compose healthcheck.

import { normalizeEvent, persistEvents, checkDatabase } from "@/lib/event-store";
import { authenticateIngest } from "@/lib/ingest-auth";
import { jsonBodyError, readJsonBody } from "@/lib/request-body";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  // 1. Read the body with a hard 256 KB byte cap (rejects oversized/chunked
  //    bodies before they are buffered fully).
  let body: unknown;
  try {
    body = await readJsonBody(req, 256 * 1024);
  } catch (error) {
    return jsonBodyError(error) ?? Response.json({ error: "invalid JSON" }, { status: 400 });
  }

  // 2. Accept a single event or a batch of 1-100.
  const items = Array.isArray(body) ? body : [body];
  if (items.length === 0 || items.length > 100) {
    return Response.json({ error: "submit between 1 and 100 events" }, { status: 422 });
  }

  // 3. Strictly validate every event (reject, don't coerce — see
  //    event-store.ts normalizeEvent). Any failure -> 422.
  let events;
  try {
    events = items.map(normalizeEvent);
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : "invalid event" }, { status: 422 });
  }

  // 4. A batch may contain events from ONE module only (the credential is
  //    per module) and ONE tenant only (one transaction = one RLS context).
  const moduleName = events[0].module;
  if (events.some((event) => event.module !== moduleName)) {
    return Response.json({ error: "a batch may contain events from one module only" }, { status: 422 });
  }
  const tenant = events[0].tenant_id;
  if (events.some((event) => event.tenant_id !== tenant)) {
    return Response.json({ error: "a batch may contain events from one tenant only" }, { status: 422 });
  }

  // 5. Authenticate: the bearer token must match the (tenant, module) the
  //    events claim. Misconfiguration -> 503 (fail closed, never a silent
  //    pass).
  try {
    if (!authenticateIngest(req, tenant, moduleName)) {
      return Response.json({ error: "invalid module credential" }, { status: 401 });
    }
  } catch (error) {
    console.error("event ingest authentication is misconfigured", error);
    return Response.json({ error: "ingest authentication is unavailable" }, { status: 503 });
  }

  // 6. Persist in one tenant-scoped transaction. The response counts
  //    accepted vs duplicates so a module's logs can distinguish a real
  //    insertion from an idempotent redelivery.
  try {
    const persisted = await persistEvents(events);
    return Response.json({
      accepted: persisted.filter((result) => result.inserted).length,
      duplicates: persisted.filter((result) => !result.inserted).length,
      event_ids: persisted.map((result) => result.event.event_id),
    }, { status: 201 });
  } catch (error) {
    console.error("failed to persist security events", error);
    return Response.json({ error: "event collector is temporarily unavailable" }, { status: 503 });
  }
}

// Convenience for a quick liveness check from a browser (and the Compose
// healthcheck for the dashboard container).
export async function GET() {
  try {
    await checkDatabase();
    return Response.json({ status: "ok" });
  } catch {
    return Response.json({ status: "database unavailable" }, { status: 503 });
  }
}
