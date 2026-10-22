// POST /api/ingest — the endpoint each Monolith module POSTs its events to.
// Accepts a single event object or an array of them.

import { getEventBroker } from "@/lib/event-ingest";
import { normalizeEvent, persistEvents, checkDatabase } from "@/lib/event-store";
import { evaluateSessionCircuitBreaker, unknownRevocationSnapshot } from "@/lib/incident-store";
import { authenticateIngest } from "@/lib/ingest-auth";
import {
  chargeIngestEvents,
  INGEST_RATE_LIMIT_WINDOW_SECONDS,
} from "@/lib/ingest-rate-limit";
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

  // The budget is spent after the credential is checked, never before. A
  // limit counted before authentication would let an unauthenticated caller
  // spend a legitimate module's budget, which is a denial of service on the
  // defence rather than on the caller: the module would be throttled by
  // someone who never had its credential.
  let charged;
  try {
    charged = await chargeIngestEvents(tenant, moduleName, events.length);
  } catch (error) {
    console.error("ingest rate limiter is unavailable", error);
    return Response.json({ error: "ingest rate limiter is unavailable" }, { status: 503 });
  }
  if (!charged.allowed) {
    return Response.json(
      {
        error: `ingest rate limit exceeded: ${charged.limit} events per ${INGEST_RATE_LIMIT_WINDOW_SECONDS}s window`,
        limit: charged.limit,
        limit_window_seconds: INGEST_RATE_LIMIT_WINDOW_SECONDS,
        module: moduleName,
        retry_after_seconds: charged.retryAfterSeconds,
      },
      {
        status: 429,
        headers: { "retry-after": String(charged.retryAfterSeconds) },
      },
    );
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
    //
    // When it fails, the response says so rather than claiming the revoked
    // set is whole. A module that believes the set is whole replaces its
    // local set with this one, and a set of "nothing is revoked" lifts every
    // revocation the dashboard holds.
    let snapshot = unknownRevocationSnapshot(tenant);
    try {
      snapshot = await evaluateSessionCircuitBreaker(
        persisted.map((result) => result.event),
      );
    } catch (breakerError) {
      console.error("session circuit breaker evaluation failed", breakerError);
    }
    return Response.json({
      accepted: newlyAccepted.length,
      duplicates: persisted.filter((result) => !result.inserted).length,
      event_ids: persisted.map((result) => result.event.event_id),
      revoked_sessions: snapshot.revoked_sessions,
      // The list above is bounded. A module that is told the list is the
      // whole set replaces its local revoked set with it, so a bounded list
      // that claimed completeness would drop every revocation the dashboard
      // holds past the bound — the session revoked a moment ago would be
      // served again. `complete` tells the module whether it may replace;
      // `truncated` says the same thing from the other side.
      revoked_sessions_complete: snapshot.complete,
      revoked_sessions_truncated: snapshot.truncated,
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
