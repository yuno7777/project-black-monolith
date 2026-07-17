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
import { authenticateOperator, OperatorAuthUnavailable } from "@/lib/operator-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const [run, history] = await Promise.all([latestRun(), detectorHistory()]);
    return Response.json({ run, history });
  } catch (error) {
    console.error("failed to read benchmark runs", error);
    return Response.json({ error: "the benchmark ledger is temporarily unavailable" }, { status: 503 });
  }
}

export async function POST(req: Request) {
  // Authenticate before parsing, and fail closed if auth was never configured.
  let actor: string | null;
  try {
    actor = authenticateOperator(req);
  } catch (error) {
    if (error instanceof OperatorAuthUnavailable) {
      console.error("operator authentication is misconfigured", error);
      return Response.json({ error: "operator authentication is unavailable" }, { status: 503 });
    }
    throw error;
  }
  if (!actor) {
    return Response.json({ error: "invalid operator credential" }, { status: 401 });
  }

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
    run = normalizeRun(body);
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
