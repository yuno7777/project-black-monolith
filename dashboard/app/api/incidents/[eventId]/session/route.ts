// GET /api/incidents/<event_id>/session — what else happened in this event's
// agent session, broken down by defense layer.
//
// This is the endpoint the whole correlation effort exists for: one module
// firing is a detection, but the same session tripping the tool, memory and
// reasoning layers is a compromised agent, and no single module can see that.
//
// 404 is not an error here in the usual sense — an event whose caller never
// told us its session simply cannot be correlated, and saying so is better than
// inventing a grouping.

import { sessionForEvent } from "@/lib/incident-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function GET(_req: Request, context: { params: Promise<{ eventId: string }> }) {
  const { eventId } = await context.params;
  if (!UUID_PATTERN.test(eventId)) {
    return Response.json({ error: "event_id must be a UUID" }, { status: 422 });
  }
  try {
    const session = await sessionForEvent(eventId);
    if (!session) {
      return Response.json(
        { error: "this event carries no session id, so it cannot be correlated" },
        { status: 404 },
      );
    }
    return Response.json({ session });
  } catch (error) {
    console.error("failed to read an event's session", error);
    return Response.json({ error: "the ledger is temporarily unavailable" }, { status: 503 });
  }
}
