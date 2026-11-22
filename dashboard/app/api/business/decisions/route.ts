import { reviewBusinessAction } from "@/lib/business-store";
import { businessDispatcher, reviewerTeams } from "@/lib/business-connector";
import { businessBody, businessOperator, businessError } from "@/lib/business-http";
import { TriageError } from "@/lib/github-triage";
import { triageId } from "@/lib/github-triage-store";

export const runtime = "nodejs";

export async function POST(req: Request) {
  try {
    const operator = await businessOperator(req, "analyst");
    if (operator instanceof Response) return operator;
    const teams = reviewerTeams(operator.tenant_id, operator.actor);
    if (!teams.length) throw new TriageError(403, "review team membership is required");
    const {id, digest, decision, note} = await businessBody(req, ["id", "digest", "decision"], ["note"]);
    if (!(decision === "approve" || decision === "deny" || decision === "request_changes" ||
          decision === "confirm" || decision === "not_applied") ||
        typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest) ||
        (note !== undefined && (typeof note !== "string" || note.length > 1000 || note.includes("\0")))) {
      throw new TriageError(422, "invalid review decision");
    }
    if (["request_changes", "confirm", "not_applied"].includes(decision) && !note?.trim()) {
      throw new TriageError(422, "a review note is required");
    }
    const dispatch = decision === "approve" ? businessDispatcher(operator.tenant_id) : async () => {
      throw new Error("dispatch requires approval");
    };
    const result = await reviewBusinessAction(operator.tenant_id, operator.actor, teams,
      {id: triageId(id), digest, decision, note}, dispatch);
    return Response.json({ decision: result });
  } catch (error) {
    return businessError(error);
  }
}
