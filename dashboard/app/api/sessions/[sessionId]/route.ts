// GET /api/sessions/<session_id> — everything one agent session did, in one
// place.
//
// The agent gateway mints a session id per agent run and hands it to every
// layer, so the three defenses report against the same key. This is the
// read side of that: the tool-layer, memory-layer and reasoning-layer
// events for one session, plus the counts an operator actually asks about
// ("what did this run trip, and what did it cost the agent?").

import { listSessionIncidents, summarizeSession } from "@/lib/session-report";
import { requireOperator } from "@/lib/route-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const SESSION_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

export async function GET(req: Request, context: { params: Promise<{ sessionId: string }> }) {
  const identity = await requireOperator(req, "viewer");
  if (identity instanceof Response) return identity;
  const { sessionId } = await context.params;
  if (!SESSION_ID_PATTERN.test(sessionId)) {
    return Response.json({ error: "session_id is not a valid session identifier" }, { status: 422 });
  }

  try {
    const incidents = await listSessionIncidents(identity.tenant_id, sessionId);
    return Response.json({
      session_id: sessionId,
      tenant_id: identity.tenant_id,
      generated_at_ms: Date.now(),
      summary: summarizeSession(incidents),
      events: incidents,
    });
  } catch (error) {
    console.error("failed to read a session report", error);
    return Response.json({ error: "the ledger is temporarily unavailable" }, { status: 503 });
  }
}
