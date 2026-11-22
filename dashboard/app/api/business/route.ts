import { businessWorkspace } from "@/lib/business-store";
import { BUSINESS_TEMPLATES } from "@/lib/business-policy";
import { businessOperator, businessError } from "@/lib/business-http";
import { reviewerTeams } from "@/lib/business-connector";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  try {
    const operator = await businessOperator(req, "viewer");
    if (operator instanceof Response) return operator;
    const teams = reviewerTeams(operator.tenant_id, operator.actor);
    const search = new URL(req.url).searchParams;
    const workspace = await businessWorkspace(operator.tenant_id, {
      before: search.get("before") ?? undefined,
      activityBefore: search.get("activityBefore") ?? undefined,
      status: search.get("status") ?? undefined,
      id: search.get("id") ?? undefined,
    });
    return Response.json({ ...workspace, templates: BUSINESS_TEMPLATES,
      operator: { role: operator.role, actor: operator.actor, teams } }, {
      headers: { "Cache-Control": "private, no-store" },
    });
  } catch (error) {
    return businessError(error);
  }
}
