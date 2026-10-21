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

// The agent id is a query parameter, so it is bound into the query and never
// interpolated. It is checked against the shape ingest accepts — printable,
// bounded — so a report cannot be asked about an agent that no event could
// ever name.
const AGENT_ID_PATTERN = /^[^\u0000-\u001f\u007f]{1,128}$/;

/**
 * The agent id the caller asked for, if any.
 *
 * An absent parameter and an empty one both mean "no agent": the report
 * is then about every agent that used the session id, and says so. A
 * request whose URL cannot be parsed has no agent either, rather than
 * failing a read that could still be answered.
 */
function requestedAgentId(req: Request): string | undefined {
  let raw: string | null = null;
  try {
    raw = new URL(req.url).searchParams.get("agent_id");
  } catch {
    return undefined;
  }
  const trimmed = raw?.trim();
  return trimmed ? trimmed : undefined;
}

export async function GET(req: Request, context: { params: Promise<{ sessionId: string }> }) {
  const identity = await requireOperator(req, "viewer");
  if (identity instanceof Response) return identity;
  const { sessionId } = await context.params;
  if (!SESSION_ID_PATTERN.test(sessionId)) {
    return Response.json({ error: "session_id is not a valid session identifier" }, { status: 422 });
  }

  // The correlation boundary is (tenant, agent, session), so a session id
  // on its own can name more than one agent's run. The agent id narrows
  // the report to one of them; left out, the report covers every agent
  // that used the session id and says so, rather than merging two runs
  // into one answer about "what this run tripped".
  const requestedAgent = requestedAgentId(req);
  if (requestedAgent !== undefined && !AGENT_ID_PATTERN.test(requestedAgent)) {
    return Response.json({ error: "agent_id is not a valid agent identifier" }, { status: 422 });
  }
  const agentId = requestedAgent;

  try {
    const page = await listSessionIncidents(identity.tenant_id, sessionId, { agentId });
    return Response.json({
      session_id: sessionId,
      tenant_id: identity.tenant_id,
      agent_id: agentId ?? null,
      // The agents the report actually covers, and whether it was narrowed
      // to one. An unscoped report says so rather than reading like a
      // single run's report.
      agent_ids: page.agentIds,
      scoped_to_agent: agentId !== undefined,
      generated_at_ms: Date.now(),
      summary: summarizeSession(page.incidents, page.total),
      total_events: page.total,
      truncated: page.total > page.incidents.length,
      events: page.incidents,
    });
  } catch (error) {
    console.error("failed to read a session report", error);
    return Response.json({ error: "the ledger is temporarily unavailable" }, { status: 503 });
  }
}
