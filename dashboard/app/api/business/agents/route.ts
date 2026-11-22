import { saveBusinessAgent } from "@/lib/business-store";
import { BUSINESS_TEMPLATES, type BusinessActionKind } from "@/lib/business-policy";
import { businessBody, businessOperator, businessError } from "@/lib/business-http";
import { TriageError } from "@/lib/github-triage";

export const runtime = "nodejs";

const kinds = new Set<unknown>(BUSINESS_TEMPLATES.flatMap(template => template.actionKinds));
function actionKind(value: unknown): value is BusinessActionKind { return kinds.has(value); }

export async function POST(req: Request) {
  try {
    const operator = await businessOperator(req, "admin");
    if (operator instanceof Response) return operator;
    const { agentId, owner, allowedKinds, paused, practiceOnly = true } =
      await businessBody(req, ["agentId", "owner", "allowedKinds", "paused"], ["practiceOnly"]);
    if (typeof agentId !== "string" || typeof owner !== "string" ||
        typeof paused !== "boolean" || typeof practiceOnly !== "boolean" ||
        !Array.isArray(allowedKinds) || !allowedKinds.every(actionKind)) {
      throw new TriageError(422, "invalid agent settings");
    }
    const agent = await saveBusinessAgent(operator.tenant_id, operator.actor, {
      agentId, owner, allowedKinds, paused, practiceOnly,
    });
    return Response.json({ agent });
  } catch (error) {
    return businessError(error);
  }
}
