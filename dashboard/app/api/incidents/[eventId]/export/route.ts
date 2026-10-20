import { exportIncidentEvidence } from "@/lib/incident-store";
import { requireOperator } from "@/lib/route-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function GET(
  req: Request,
  { params }: { params: Promise<{ eventId: string }> },
) {
  const identity = await requireOperator(req);
  if (identity instanceof Response) return identity;
  const { eventId } = await params;
  // The event id reaches the database as a uuid parameter and the response
  // filename, so it is validated before either. Without this a malformed id
  // is a server fault (invalid input syntax for type uuid) rather than a
  // rejected request, and the raw path segment lands in a header.
  if (!UUID_PATTERN.test(eventId)) {
    return Response.json({ error: "event id must be a uuid" }, { status: 422 });
  }
  try {
    const payload = await exportIncidentEvidence(eventId, identity.tenant_id, identity.actor);
    if (!payload) {
      return Response.json({ error: "no such event in the ledger" }, { status: 404 });
    }
    const headers: Record<string, string> = {
      "content-type": "application/json; charset=utf-8",
      "content-disposition": `attachment; filename="monolith-evidence-${eventId}.json"`,
      "cache-control": "private, no-store",
      // The digest is a checksum of the canonical body. It detects accidental
      // corruption; it is not an authenticity claim, because anyone who can
      // edit the bundle can recompute it. The signature header is what
      // carries authenticity, and it is present only when a bundle is
      // actually signed.
      "X-Monolith-Evidence-Algorithm": payload.integrity.algorithm,
      "X-Monolith-Evidence-SHA256": payload.integrity.canonical_sha256,
      "X-Monolith-Evidence-Signed": payload.integrity.signature ? "true" : "false",
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
