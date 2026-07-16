// GET /api/incidents/<event_id>/audit — the append-only transition trail for
// one incident: who changed it, when, from what to what, and why.

import { getAuditTrail } from "@/lib/incident-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function GET(_req: Request, context: { params: Promise<{ eventId: string }> }) {
  const { eventId } = await context.params;
  if (!UUID_PATTERN.test(eventId)) {
    return Response.json({ error: "event_id must be a UUID" }, { status: 422 });
  }
  try {
    return Response.json({ audit: await getAuditTrail(eventId) });
  } catch (error) {
    console.error("failed to read an incident audit trail", error);
    return Response.json({ error: "the ledger is temporarily unavailable" }, { status: 503 });
  }
}
