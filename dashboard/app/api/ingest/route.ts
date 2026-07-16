// POST /api/ingest — the endpoint each Monolith module POSTs its events to.
// Accepts a single event object or an array of them.

import { getBroker } from "@/lib/event-ingest";
import { normalizeEvent, persistEvents, checkDatabase } from "@/lib/event-store";
import { authenticateIngest } from "@/lib/ingest-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  const contentLength = Number(req.headers.get("content-length") ?? 0);
  if (contentLength > 256 * 1024) {
    return Response.json({ error: "payload exceeds 256 KiB" }, { status: 413 });
  }

  let body: unknown;
  try {
    const text = await req.text();
    if (text.length > 256 * 1024) {
      return Response.json({ error: "payload exceeds 256 KiB" }, { status: 413 });
    }
    body = JSON.parse(text);
  } catch {
    return Response.json({ error: "invalid JSON" }, { status: 400 });
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
  const module = events[0].module;
  if (events.some((event) => event.module !== module)) {
    return Response.json({ error: "a batch may contain events from one module only" }, { status: 422 });
  }
  try {
    if (!authenticateIngest(req, module)) {
      return Response.json({ error: "invalid module credential" }, { status: 401 });
    }
  } catch (error) {
    console.error("event ingest authentication is misconfigured", error);
    return Response.json({ error: "ingest authentication is unavailable" }, { status: 503 });
  }

  try {
    const persisted = await persistEvents(events);
    const broker = getBroker();
    for (const result of persisted) {
      if (result.inserted) broker.ingest(result.event);
    }
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

// Convenience for a quick liveness check from a browser.
export async function GET() {
  try {
    await checkDatabase();
    return Response.json({ status: "ok", buffered: getBroker().recent().length });
  } catch {
    return Response.json({ status: "database unavailable" }, { status: 503 });
  }
}
