import { githubAction, githubConfig, githubWorkload, issueNumber, TriageError, triageResponse } from "@/lib/github-triage";
import { listActions, proposeAction, triageId } from "@/lib/github-triage-store";
import { jsonBodyError, readJsonBody } from "@/lib/request-body";
import { requireOperator } from "@/lib/route-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const operator = await requireOperator(req, "viewer");
  if (operator instanceof Response) return operator;
  try {
    if (operator.actor === "auth-disabled") throw new TriageError(503, "GitHub triage is unavailable");
    const before = new URL(req.url).searchParams.get("before");
    const result = await listActions(operator.tenant_id, before === null ? undefined : triageId(before));
    return Response.json({ ...result, can_review: operator.role !== "viewer" });
  } catch (error) {
    return triageResponse(error);
  }
}

export async function POST(req: Request) {
  try {
    const config = githubConfig();
    const identity = githubWorkload(req, config.tenant);
    const body = await readJsonBody(req, 16 * 1024) as Record<string, unknown> | null;
    if (!body || typeof body !== "object" || Object.keys(body).length !== 3 ||
        !("request_id" in body && "issue" in body && "action" in body)) {
      throw new TriageError(422, "request_id, issue, and action are required");
    }
    const action = await proposeAction(
      identity, triageId(body.request_id), config.repository, issueNumber(body.issue), githubAction(body.action),
    );
    return Response.json({ action }, { status: 202 });
  } catch (error) {
    return jsonBodyError(error) ?? triageResponse(error);
  }
}
