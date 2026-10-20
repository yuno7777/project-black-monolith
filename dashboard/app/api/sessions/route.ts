// GET /api/sessions — the sessions the ledger knows about, newest first.
//
// The per-session endpoint (/api/sessions/<id>) answers "what did this one
// session do", and it deliberately answers 200 with zero events for a session
// that never happened — so it cannot answer "is my agent connected yet?".
// This route is the discovery side: it lists the sessions that exist, which
// is what the onboarding page and the overview's first-run prompt need.
//
// It is an operator surface (a human reading the ledger), so it uses the
// operator credential rather than a module's ingest token.

import { listRecentSessions, MAX_RECENT_SESSIONS } from "@/lib/onboarding-store";
import { requireOperator } from "@/lib/route-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const identity = await requireOperator(req);
  if (identity instanceof Response) return identity;

  const raw = new URL(req.url).searchParams.get("limit");
  let limit = 20;
  if (raw !== null) {
    const parsed = Number(raw);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > MAX_RECENT_SESSIONS) {
      return Response.json({ error: "limit is out of range" }, { status: 422 });
    }
    limit = parsed;
  }

  try {
    const sessions = await listRecentSessions(identity.tenant_id, limit);
    return Response.json({
      tenant_id: identity.tenant_id,
      generated_at_ms: Date.now(),
      sessions,
    });
  } catch (error) {
    console.error("failed to list sessions", error);
    return Response.json({ error: "the session ledger is temporarily unavailable" }, { status: 503 });
  }
}
