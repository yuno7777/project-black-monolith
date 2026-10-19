import { exportIncidentEvidence } from "@/lib/incident-store";
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
    const payload = await exportIncidentEvidence(eventId, identity.tenant_id, identity.actor);
    if (!payload) {
      return Response.json({ error: "no such event in the ledger" }, { status: 404 });
    }
    const headers: Record<string, string> = {
      "content-type": "application/json; charset=utf-8",
      "content-disposition": `attachment; filename="monolith-evidence-${eventId}.json"`,
      "cache-control": "private, no-store",
      "X-Monolith-Evidence-SHA256": payload.integrity.canonical_sha256,
    };
    if (payload.integrity.signature) {
      headers["X-Monolith-Evidence-Signature"] = `hmac-sha256=${payload.integrity.signature}`;
    }
    return new Response(`${JSON.stringify(payload, null, 2)}\n`, {
      headers,
    });
  } catch (error) {
    console.error("failed to export incident evidence", error);
    return Response.json({ error: "evidence export is temporarily unavailable" }, { status: 503 });
  }
}
