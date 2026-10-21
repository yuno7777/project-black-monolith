// GET  /api/onboarding — how close the stack is to running an agent.
// POST /api/onboarding — the setup actions the dashboard can perform.
//
// The read side is an operator surface: it reports what the stack looks like
// from where the dashboard sits. The write side performs the steps the
// dashboard can actually take — seeding the memory layer's corpus, clearing
// its detector state — so an operator does not have to run a fixture script
// by hand. The steps that live on the agent's own machine (building the tool
// layer, starting the agent) are rendered as commands instead; the dashboard
// container cannot reach that filesystem and must not pretend otherwise.
//
// No credential is ever returned by either verb. The launcher reads the
// repository's own .env, so the command the page renders carries no secret.

import { isOnboardingAction } from "@/lib/onboarding-actions";
import {
  readOnboardingState,
  resetVectorDetection,
  seedDemoCorpus,
} from "@/lib/onboarding-store";
import { requireOperator } from "@/lib/route-auth";
import { jsonBodyError, readJsonBody } from "@/lib/request-body";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const identity = await requireOperator(req);
  if (identity instanceof Response) return identity;

  try {
    const state = await readOnboardingState(identity.tenant_id);
    return Response.json({ ...state, role: identity.role });
  } catch (error) {
    console.error("failed to read the onboarding state", error);
    return Response.json({ error: "the onboarding state is temporarily unavailable" }, { status: 503 });
  }
}

export async function POST(req: Request) {
  // Seeding a corpus and clearing detector state change what the defenses
  // see, so they are an administrator's action, not a viewer's.
  const identity = await requireOperator(req, "admin");
  if (identity instanceof Response) return identity;

  let body: unknown;
  try {
    body = await readJsonBody(req, 4 * 1024);
  } catch (error) {
    return jsonBodyError(error) ?? Response.json({ error: "invalid JSON" }, { status: 400 });
  }

  const action =
    body && typeof body === "object" && "action" in body
      ? (body as { action: unknown }).action
      : undefined;
  if (!isOnboardingAction(action)) {
    return Response.json({ error: "unknown onboarding action" }, { status: 422 });
  }

  try {
    if (action === "seed-corpus" || action === "seed-bait") {
      const seeded = await seedDemoCorpus(action === "seed-bait");
      return Response.json({ action, ...seeded });
    }
    if (action === "reset-detection") {
      await resetVectorDetection();
      return Response.json({ action, status: "reset" });
    }
    // Every action the list offers is handled above. Refusing is safer than
    // falling through: the branch that clears the memory layer's detector
    // state must only ever be reached by an action that asked for it.
    return Response.json({ error: "unknown onboarding action" }, { status: 422 });
  } catch (error) {
    console.error("failed to run the onboarding action", error);
    return Response.json(
      { error: error instanceof Error ? error.message : "the action failed" },
      { status: 503 },
    );
  }
}
