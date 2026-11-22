import { readBusinessPolicy, practiceBusinessAction as practiceWorkload } from "@/lib/business-store";
import { parseBusinessAction, practiceBusinessAction, validateTemplateAction } from "@/lib/business-policy";
import { businessBody, businessOperator, businessWorkload, businessError } from "@/lib/business-http";

export const runtime = "nodejs";

export async function POST(req: Request) {
  try {
    if (req.headers.has("x-monolith-workload-token")) {
      const workload = businessWorkload(req);
      const body = await businessBody(req, ["action", "templateId"]);
      const action = parseBusinessAction(body.action);
      const templateId = validateTemplateAction(body.templateId, action);
      return Response.json(await practiceWorkload(workload, { action, templateId }));
    }
    const operator = await businessOperator(req, "viewer");
    if (operator instanceof Response) return operator;
    const body = await businessBody(req, ["action"], ["policy", "templateId"]);
    const policy = body.policy === undefined ? await readBusinessPolicy(operator.tenant_id) : body.policy;
    return Response.json(practiceBusinessAction(body.action, policy, body.templateId));
  } catch (error) {
    return businessError(error);
  }
}
