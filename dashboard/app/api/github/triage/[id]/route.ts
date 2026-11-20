import { githubConfig, TriageError, triageResponse } from "@/lib/github-triage";
import { reviewAction, revokeActionSession, triageId } from "@/lib/github-triage-store";
import { jsonBodyError, readJsonBody } from "@/lib/request-body";
import { requireOperator } from "@/lib/route-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const operator = await requireOperator(req, "analyst");
  if (operator instanceof Response) return operator;
  try {
    const { id } = await params;
    const body = await readJsonBody(req, 1024) as Record<string, unknown> | null;
    if (!body || Object.keys(body).length !== 2 || typeof body.digest !== "string" ||
        !/^[a-f0-9]{64}$/.test(body.digest) ||
        (body.decision !== "approve" && body.decision !== "deny" && body.decision !== "revoke_session")) {
      throw new TriageError(422, "a digest and review decision are required");
    }
    if (body.decision === "revoke_session") {
      if (operator.actor === "auth-disabled") throw new TriageError(503, "GitHub triage is unavailable");
      const session = await revokeActionSession(operator.tenant_id, triageId(id), body.digest, operator.actor);
      return Response.json({ session });
    }
    const config = githubConfig();
    if (operator.tenant_id !== config.tenant) throw new TriageError(404, "action not found");
    const action = await reviewAction(config, triageId(id), body.digest, body.decision, operator.actor);
    return Response.json({ action });
  } catch (error) {
    return jsonBodyError(error) ?? triageResponse(error);
  }
}
