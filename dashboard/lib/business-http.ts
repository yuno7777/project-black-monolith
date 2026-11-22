import { requireOperator, isAuthDisabled } from "@/lib/route-auth";
import type { OperatorRole } from "@/lib/operator-auth";
import { BusinessPolicyError } from "@/lib/business-policy";
import { githubWorkload, TriageError } from "@/lib/github-triage";
import { jsonBodyError, readJsonBody } from "@/lib/request-body";

export function requireBusinessAuth() {
  if (isAuthDisabled()) throw new TriageError(503, "business workflows require operator authentication");
}

export async function businessOperator(req: Request, minimum: OperatorRole) {
  requireBusinessAuth();
  return requireOperator(req, minimum);
}

export async function businessBody(req: Request, required: string[], optional: string[] = []) {
  const body = await readJsonBody(req, 32 * 1024);
  if (!body || typeof body !== "object" || Array.isArray(body) ||
      required.some((key) => !Object.hasOwn(body, key)) ||
      Object.keys(body).some((key) => !required.includes(key) && !optional.includes(key))) {
    throw new TriageError(422, "unexpected or missing request fields");
  }
  return body as Record<string, unknown>;
}

export function businessError(error: unknown) {
  if (error instanceof BusinessPolicyError) return Response.json({ error: error.message }, { status: 422 });
  if (error instanceof TriageError) return Response.json({ error: error.message }, { status: error.status });
  const invalid = jsonBodyError(error);
  if (invalid) return invalid;
  console.error("Business workspace request failed", error instanceof Error ? error.name : "unknown");
  return Response.json({ error: "business workspace temporarily unavailable" }, { status: 503 });
}

export function businessWorkload(req: Request) {
  requireBusinessAuth();
  const tenant = process.env.MONOLITH_TENANT_ID || "default";
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(tenant)) {
    throw new TriageError(503, "business workload tenant is unavailable");
  }
  return githubWorkload(req, tenant);
}
