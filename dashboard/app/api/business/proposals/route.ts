import { proposeBusinessAction } from "@/lib/business-store";
import { parseBusinessAction, validateTemplateAction } from "@/lib/business-policy";
import { businessBody, businessWorkload, businessError } from "@/lib/business-http";
import { TriageError } from "@/lib/github-triage";
import { triageId } from "@/lib/github-triage-store";

export const runtime = "nodejs";

export async function POST(req: Request) {
  try {
    const workload = businessWorkload(req);
    const body = await businessBody(req, ["requestId", "caseId", "templateId", "action"]);
    const action = parseBusinessAction(body.action);
    const templateId = validateTemplateAction(body.templateId, action);
    if (typeof body.caseId !== "string") throw new TriageError(422, "invalid case identifier");
    const decision = await proposeBusinessAction(workload, {
      requestId: triageId(body.requestId), caseId: body.caseId, templateId, action,
    });
    return Response.json({ decision }, { status: 202 });
  } catch (error) {
    return businessError(error);
  }
}
