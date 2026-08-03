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
