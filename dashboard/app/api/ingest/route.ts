// POST /api/ingest — the endpoint each Monolith module POSTs its events to.
// Accepts a single event object or an array of them.

import { getEventBroker } from "@/lib/event-ingest";
import { normalizeEvent, persistEvents, checkDatabase } from "@/lib/event-store";
import { evaluateSessionCircuitBreaker, MAX_REVOCATION_SNAPSHOT_BYTES } from "@/lib/incident-store";
import { authenticateIngest } from "@/lib/ingest-auth";
import { jsonBodyError, readJsonBody } from "@/lib/request-body";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  let body: unknown;
  try {
    body = await readJsonBody(req, 256 * 1024);
  } catch (error) {
    return jsonBodyError(error) ?? Response.json({ error: "invalid JSON" }, { status: 400 });
  }

  const items = Array.isArray(body) ? body : [body];
  if (items.length === 0 || items.length > 100) {
    return Response.json({ error: "submit between 1 and 100 events" }, { status: 422 });
  }
  let events;
  try {
    events = items.map(normalizeEvent);
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : "invalid event" }, { status: 422 });
  }
  const moduleName = events[0].module;
  if (events.some((event) => event.module !== moduleName)) {
    return Response.json({ error: "a batch may contain events from one module only" }, { status: 422 });
  }
  const tenant = events[0].tenant_id;
  if (events.some((event) => event.tenant_id !== tenant)) {
    return Response.json({ error: "a batch may contain events from one tenant only" }, { status: 422 });
  }
  try {
    if (!authenticateIngest(req, tenant, moduleName)) {
      return Response.json({ error: "invalid module credential" }, { status: 401 });
    }
  } catch (error) {
    console.error("event ingest authentication is misconfigured", error);
    return Response.json({ error: "ingest authentication is unavailable" }, { status: 503 });
  }

  try {
    const persisted = await persistEvents(events);
    const newlyAccepted = persisted
      .filter((result) => result.inserted)
      .map((result) => result.event);
    if (newlyAccepted.length) {
      getEventBroker().publish(newlyAccepted);
    }
    // The circuit breaker runs after the events are committed, so its failure
    // must not fail the request: a 5xx here would tell the module that the
    // batch was not accepted, and the module would retry it and finally
    // dead-letter an event that is already in the ledger. The breaker is a
    // reaction to the evidence, not a precondition for accepting it.
    let revokedSessions: string[] = [];
    try {
      revokedSessions = await evaluateSessionCircuitBreaker(
        persisted.map((result) => result.event),
      );
    } catch (breakerError) {
      console.error("session circuit breaker evaluation failed", breakerError);
    }
    // The revocation snapshot travels in the ingest response, and a module
    // reads a response body under a hard byte cap. A snapshot that does not
    // fit cannot be parsed, so the module would keep the set it already had
    // — a set that is stale, and stale forever once every later snapshot is
    // too large as well. A snapshot that does not fit is therefore not sent
    // here at all: the module keeps what it had, and the polled snapshot
    // (which is paged) is what tells it the whole truth.
    const snapshotFits = revokedSessions.reduce((total, id) => total + id.length + 3, 0)
      <= MAX_REVOCATION_SNAPSHOT_BYTES;
    return Response.json({
      accepted: newlyAccepted.length,
      duplicates: persisted.filter((result) => !result.inserted).length,
      event_ids: persisted.map((result) => result.event.event_id),
      ...(snapshotFits ? { revoked_sessions: revokedSessions } : {}),
      revoked_sessions_complete: snapshotFits,
      revoked_sessions_total: revokedSessions.length,
    }, { status: 201 });
  } catch (error) {
    console.error("failed to persist security events", error);
    return Response.json({ error: "event collector is temporarily unavailable" }, { status: 503 });
  }
}

// Convenience for a quick liveness check from a browser.
export async function GET() {
  try {
    await checkDatabase();
    return Response.json({ status: "ok" });
  } catch {
    return Response.json({ status: "database unavailable" }, { status: 503 });
  }
}
