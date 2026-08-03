import { readLedgerHealth } from "@/lib/operations-store";
import { requireOperator } from "@/lib/route-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const MODULES = [
  { module: "vector-anchor", env: "VECTOR_ANCHOR_INTERNAL_URL" },
  { module: "trace-audit", env: "TRACE_AUDIT_INTERNAL_URL" },
] as const;

async function moduleRuntimeHealth(module: string, baseUrl: string | undefined, token: string | undefined) {
  if (!baseUrl || !token) return { module, configured: false, reachable: false };
  try {
    const response = await fetch(new URL("/stats", baseUrl), {
      headers: { authorization: `Bearer ${token}` },
      cache: "no-store",
      signal: AbortSignal.timeout(1_500),
    });
    if (!response.ok) {
      return { module, configured: true, reachable: false, status: response.status };
    }
    const body = (await response.json()) as Record<string, unknown>;
    return {
      module,
      configured: true,
      reachable: true,
      delivery: body.delivery ?? null,
      backend: body.backend ?? null,
    };
  } catch (error) {
    return {
      module,
      configured: true,
      reachable: false,
      error: error instanceof Error ? error.name : "request failed",
    };
  }
}

export async function GET(req: Request) {
  const identity = await requireOperator(req);
  if (identity instanceof Response) return identity;

  try {
    const token = process.env.MONOLITH_MODULE_ADMIN_TOKEN;
    const [ledger, runtimes] = await Promise.all([
      readLedgerHealth(identity.tenant_id),
      Promise.all(
        MODULES.map(({ module, env }) =>
          moduleRuntimeHealth(module, process.env[env], token),
        ),
      ),
    ]);
    return Response.json({ generated_at_ms: Date.now(), ledger, runtimes });
  } catch (error) {
    console.error("failed to read operations health", error);
    return Response.json({ error: "operations health is temporarily unavailable" }, { status: 503 });
  }
}
