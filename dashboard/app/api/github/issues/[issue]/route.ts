import { githubConfig, githubWorkload, issueNumber, readIssue, TriageError, triageResponse } from "@/lib/github-triage";
import { isSessionRevoked } from "@/lib/incident-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request, { params }: { params: Promise<{ issue: string }> }) {
  try {
    const config = githubConfig();
    const identity = githubWorkload(req, config.tenant);
    const { issue } = await params;
    if (await isSessionRevoked(identity.tenant, identity.agent, identity.session)) {
      throw new TriageError(403, "workload session is revoked");
    }
    return Response.json(await readIssue(config, issueNumber(/^\d+$/.test(issue) ? Number(issue) : null)));
  } catch (error) {
    return triageResponse(error);
  }
}
