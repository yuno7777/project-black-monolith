// GET  /api/benchmarks — the latest detection-benchmark run + per-detector history.
// POST /api/benchmarks — record a run (operator-authenticated).
//
// A benchmark run is an operator/CI action, not a module detection and not human
// triage, so it uses the operator credential — the same gate as /api/incidents.
// Benchmark results are evaluation metadata and never enter the event ledger.

import {
  BenchmarkInputError,
  detectorHistory,
  latestRun,
  normalizeRun,
  persistRun,
} from "@/lib/benchmark-store";
import { requireOperator } from "@/lib/route-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const identity = await requireOperator(req);
  if (identity instanceof Response) return identity;
  try {
    const [run, history] = await Promise.all([
      latestRun(identity.tenant_id),
      detectorHistory(identity.tenant_id),
    ]);
    return Response.json({ run, history });
  } catch (error) {
    console.error("failed to read benchmark runs", error);
    return Response.json({ error: "the benchmark ledger is temporarily unavailable" }, { status: 503 });
  }
}

export async function POST(req: Request) {
  // Authenticate before parsing, and fail closed if auth was never configured.
  const identity = await requireOperator(req, "analyst");
  if (identity instanceof Response) return identity;

  let body: unknown;
  try {
    const text = await req.text();
    if (text.length > 256 * 1024) {
      return Response.json({ error: "payload exceeds 256 KiB" }, { status: 413 });
    }
    body = JSON.parse(text);
  } catch {
    return Response.json({ error: "invalid JSON" }, { status: 400 });
  }

  let run;
  try {
    run = normalizeRun(body, identity.tenant_id);
  } catch (error) {
    if (error instanceof BenchmarkInputError) {
      return Response.json({ error: error.message }, { status: 422 });
    }
    throw error;
  }

  try {
    const result = await persistRun(run);
    return Response.json({ recorded: result.rows, run_id: result.run_id }, { status: 201 });
  } catch (error) {
    console.error("failed to persist a benchmark run", error);
    return Response.json({ error: "the benchmark ledger is temporarily unavailable" }, { status: 503 });
  }
}
