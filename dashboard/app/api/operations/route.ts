import {
  moduleStatsUrl,
  probeModuleRuntimes,
  readLedgerHealth,
  replayDeadLetters,
} from "@/lib/operations-store";
import { requireOperator } from "@/lib/route-auth";
import { alertConfigStatus } from "@/lib/alert-config";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export { moduleStatsUrl };

export async function GET(req: Request) {
  const identity = await requireOperator(req);
  if (identity instanceof Response) return identity;

  try {
    const [ledger, runtimes] = await Promise.all([
      readLedgerHealth(identity.tenant_id),
      probeModuleRuntimes(),
    ]);
    return Response.json({
      generated_at_ms: Date.now(),
      ledger,
      runtimes,
      alerting: alertConfigStatus(),
    });
  } catch (error) {
    console.error("failed to read operations health", error);
    return Response.json({ error: "operations health is temporarily unavailable" }, { status: 503 });
  }
}

export async function POST(req: Request) {
  const identity = await requireOperator(req, "admin");
  if (identity instanceof Response) return identity;

  try {
    const replay = await replayDeadLetters(identity.tenant_id);
    return Response.json(replay);
  } catch (error) {
    console.error("failed to replay dead-lettered events", error);
    return Response.json({ error: "dead-letter replay is temporarily unavailable" }, { status: 503 });
  }
}
