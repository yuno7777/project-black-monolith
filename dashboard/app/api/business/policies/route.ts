import { saveBusinessPolicy } from "@/lib/business-store";
import { parseBusinessPolicy } from "@/lib/business-policy";
import { businessBody, businessOperator, businessError } from "@/lib/business-http";

export const runtime = "nodejs";

export async function POST(req: Request) {
  try {
    const operator = await businessOperator(req, "admin");
    if (operator instanceof Response) return operator;
    const body = await businessBody(req, ["policy"]);
    const policy = await saveBusinessPolicy(operator.tenant_id, operator.actor, parseBusinessPolicy(body.policy));
    return Response.json({ policy });
  } catch (error) {
    return businessError(error);
  }
}
