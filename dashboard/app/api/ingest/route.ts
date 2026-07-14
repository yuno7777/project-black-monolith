// POST /api/ingest — the endpoint each Monolith module POSTs its events to.
// Accepts a single event object or an array of them.

import { getBroker } from "@/lib/event-ingest";
import type { MonolithEvent } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "invalid JSON" }, { status: 400 });
  }

  const broker = getBroker();
  const items = Array.isArray(body) ? body : [body];
  let accepted = 0;
  for (const item of items) {
    if (item && typeof item === "object") {
      broker.ingest(item as Partial<MonolithEvent>);
      accepted++;
    }
  }
  return Response.json({ accepted });
}

// Convenience for a quick liveness check from a browser.
export async function GET() {
  return Response.json({ status: "ok", buffered: getBroker().recent().length });
}
