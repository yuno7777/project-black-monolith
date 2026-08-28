// GET /api/incidents/<event_id>/export — download one incident as a versioned
// JSON evidence bundle.
//
// WHAT IT PRODUCES
// ----------------
// A single JSON file ("monolith-evidence-<eventId>.json") containing the
// immutable event, its triage state, its full append-only audit trail, and its
// cross-layer session view. This is the "export the evidence" workflow: an
// operator can hand the bundle to someone else without that person needing
// dashboard access, and the bundle is self-contained.
//
// The format is versioned ("project-black-monolith/evidence-bundle@1") so a
// future format change is detectable. All four parts are read in parallel,
// tenant-scoped, viewer+ role required.

import { getAuditTrail, getIncident, sessionForEvent } from "@/lib/incident-store";
import { requireOperator } from "@/lib/route-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ eventId: string }> },
) {
  const identity = await requireOperator(req);
  if (identity instanceof Response) return identity;
  const { eventId } = await params;
  try {
    const [incident, audit, session] = await Promise.all([
      getIncident(eventId, identity.tenant_id),
      getAuditTrail(eventId, identity.tenant_id),
      sessionForEvent(eventId, identity.tenant_id),
    ]);
    if (!incident) {
      return Response.json({ error: "no such event in the ledger" }, { status: 404 });
    }
    const payload = {
      format: "project-black-monolith/evidence-bundle@1",
      exported_at: new Date().toISOString(),
      exported_by: identity.actor,
      tenant_id: identity.tenant_id,
      incident,
      audit,
      session,
    };
    return new Response(`${JSON.stringify(payload, null, 2)}\n`, {
      headers: {
        "content-type": "application/json; charset=utf-8",
        "content-disposition": `attachment; filename="monolith-evidence-${eventId}.json"`,
        "cache-control": "private, no-store",
      },
    });
  } catch (error) {
    console.error("failed to export incident evidence", error);
    return Response.json({ error: "evidence export is temporarily unavailable" }, { status: 503 });
  }
}
