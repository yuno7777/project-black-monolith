// GET /api/sessions/revoked — the revocation snapshot modules poll when no
// events are flowing. Authenticated with the caller's per-module ingest token
// (the same credential it already uses to POST events), scoped to a tenant.

import { listRevokedSessions } from "@/lib/incident-store";
import { authenticateIngest } from "@/lib/ingest-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const KNOWN_MODULES = new Set(["mcp-shield", "vector-anchor", "trace-audit"]);

export async function GET(req: Request) {
  const tenant = req.headers.get("x-monolith-tenant-id")?.trim() ?? "";
  const moduleName = req.headers.get("x-monolith-module")?.trim() ?? "";
  if (!tenant || tenant.length > 128 || !KNOWN_MODULES.has(moduleName)) {
    return Response.json({ error: "a known module and tenant are required" }, { status: 401 });
  }
  try {
    if (!authenticateIngest(req, tenant, moduleName)) {
      return Response.json({ error: "invalid module credential" }, { status: 401 });
    }
  } catch (error) {
    console.error("revocation snapshot authentication is misconfigured", error);
    return Response.json({ error: "authentication is unavailable" }, { status: 503 });
  }

  try {
    const revoked = await listRevokedSessions(tenant);
    return Response.json({
      tenant_id: tenant,
      generated_at_ms: Date.now(),
      revoked_sessions: Array.from(new Set(revoked.map((entry) => entry.session_id))),
    });
  } catch (error) {
    console.error("failed to read revoked sessions", error);
    return Response.json({ error: "the ledger is temporarily unavailable" }, { status: 503 });
  }
}
