import { randomUUID } from "node:crypto";
import { getDb } from "@/lib/db";

// Benchmark results are evaluation metadata, deliberately separate from the
// event ledger. This module owns reading and writing monolith.benchmark_runs.

const KNOWN_MODULES = new Set(["mcp-shield", "vector-anchor", "trace-audit"]);
const PARADIGMS = new Set(["threshold", "exact", "regex"]);
const MAX_NOTES = 2000;

export class BenchmarkInputError extends Error {}

export interface BenchmarkDetector {
  module: string;
  detector: string;
  paradigm: string;
  benchmark_version: number;
  corpus: { attack_samples: number; benign_samples: number };
  confusion: { tp: number; fp: number; tn: number; fn: number };
  metrics: {
    detection_rate: number;
    false_positive_rate: number;
    precision: number;
    recall: number;
    f1: number;
  };
  latency_us: { p50: number; p95: number; p99: number } | null;
  thresholds: Record<string, unknown>;
  notes?: string;
}

export interface BenchmarkRun {
  run_id: string;
  run_at_ms: number;
  git_commit?: string;
  detectors: BenchmarkDetector[];
}

// --- validation ------------------------------------------------------------

function int(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || !Number.isInteger(value)) {
    throw new BenchmarkInputError(`${field} must be a non-negative integer`);
  }
  return value;
}

function rate(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new BenchmarkInputError(`${field} must be a number in [0, 1]`);
  }
  return value;
}

function optNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** Validate and normalize an incoming run. Never trusts the derived metrics —
 *  they are recomputed from the confusion matrix so a bad rate cannot land. */
export function normalizeRun(raw: unknown): BenchmarkRun {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new BenchmarkInputError("body must be a JSON object");
  }
  const value = raw as Record<string, unknown>;
  const detectorsRaw = value.detectors ?? value; // accept a bare array too
  const list = Array.isArray(detectorsRaw)
    ? detectorsRaw
    : Array.isArray(value.reports)
      ? value.reports
      : null;
  if (!list || list.length === 0 || list.length > 50) {
    throw new BenchmarkInputError("a run must carry between 1 and 50 detector reports");
  }

  const detectors = list.map((d): BenchmarkDetector => {
    if (!d || typeof d !== "object") throw new BenchmarkInputError("each detector must be an object");
    const r = d as Record<string, unknown>;
    const module = typeof r.module === "string" ? r.module : "";
    if (!KNOWN_MODULES.has(module)) throw new BenchmarkInputError("unknown module in a detector report");
    const detector = typeof r.detector === "string" ? r.detector.slice(0, 64) : "";
    if (!detector) throw new BenchmarkInputError("detector name is required");
    const paradigm = typeof r.paradigm === "string" ? r.paradigm : "";
    if (!PARADIGMS.has(paradigm)) throw new BenchmarkInputError(`unknown paradigm '${paradigm}'`);

    const confusion = (r.confusion ?? {}) as Record<string, unknown>;
    const tp = int(confusion.tp, "tp");
    const fp = int(confusion.fp, "fp");
    const tn = int(confusion.tn, "tn");
    const fnv = int(confusion.fn, "fn");

    // Recompute the metrics rather than trusting the client's numbers.
    const detection = tp + fnv > 0 ? tp / (tp + fnv) : 0;
    const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = detection;
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

    const lat = r.latency_us as Record<string, unknown> | null | undefined;
    const latency = lat && typeof lat === "object"
      ? { p50: optNumber(lat.p50) ?? 0, p95: optNumber(lat.p95) ?? 0, p99: optNumber(lat.p99) ?? 0 }
      : null;

    const notes = typeof r.notes === "string" ? r.notes.slice(0, MAX_NOTES) : undefined;
    const version = typeof r.benchmark_version === "number" ? Math.trunc(r.benchmark_version) : 1;
    const thresholds = r.thresholds && typeof r.thresholds === "object" && !Array.isArray(r.thresholds)
      ? (r.thresholds as Record<string, unknown>)
      : {};

    return {
      module,
      detector,
      paradigm,
      benchmark_version: version,
      corpus: { attack_samples: tp + fnv, benign_samples: fp + tn },
      confusion: { tp, fp, tn, fn: fnv },
      metrics: {
        detection_rate: round4(detection),
        false_positive_rate: round4(fpr),
        precision: round4(precision),
        recall: round4(recall),
        f1: round4(f1),
      },
      latency_us: latency,
      thresholds,
      notes,
    };
  });

  const runAt = typeof value.run_at_ms === "number" && Number.isFinite(value.run_at_ms)
    ? Math.trunc(value.run_at_ms)
    : Date.now();
  const gitCommit = typeof value.git_commit === "string" ? value.git_commit.slice(0, 64) : undefined;

  return { run_id: randomUUID(), run_at_ms: runAt, git_commit: gitCommit, detectors };
}

function round4(x: number): number {
  return Math.round(x * 10_000) / 10_000;
}

// --- writes ----------------------------------------------------------------

export async function persistRun(run: BenchmarkRun): Promise<{ run_id: string; rows: number }> {
  const db = getDb();
  const client = await db.connect();
  try {
    await client.query("begin");
    for (const d of run.detectors) {
      await client.query(
        `insert into monolith.benchmark_runs (
           run_id, benchmark_version, run_at, git_commit, module, detector, paradigm,
           attack_samples, benign_samples, tp, fp, tn, fn,
           detection_rate, false_positive_rate, precision, recall, f1,
           latency_p50_us, latency_p95_us, latency_p99_us, thresholds, notes
         ) values (
           $1, $2, to_timestamp($3::double precision / 1000), $4, $5, $6, $7,
           $8, $9, $10, $11, $12, $13,
           $14, $15, $16, $17, $18,
           $19, $20, $21, $22::jsonb, $23
         )`,
        [
          run.run_id, d.benchmark_version, run.run_at_ms, run.git_commit ?? null,
          d.module, d.detector, d.paradigm,
          d.corpus.attack_samples, d.corpus.benign_samples,
          d.confusion.tp, d.confusion.fp, d.confusion.tn, d.confusion.fn,
          d.metrics.detection_rate, d.metrics.false_positive_rate,
          d.metrics.precision, d.metrics.recall, d.metrics.f1,
          d.latency_us?.p50 ?? null, d.latency_us?.p95 ?? null, d.latency_us?.p99 ?? null,
          JSON.stringify(d.thresholds), d.notes ?? null,
        ],
      );
    }
    await client.query("commit");
    return { run_id: run.run_id, rows: run.detectors.length };
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

// --- reads -----------------------------------------------------------------

type Row = {
  run_id: string;
  run_at_ms: string;
  git_commit: string | null;
  module: string;
  detector: string;
  paradigm: string;
  attack_samples: number;
  benign_samples: number;
  tp: number; fp: number; tn: number; fn: number;
  detection_rate: string; false_positive_rate: string;
  precision: string; recall: string; f1: string;
  latency_p50_us: string | null; latency_p95_us: string | null; latency_p99_us: string | null;
  thresholds: Record<string, unknown>;
  notes: string | null;
};

function fromRow(r: Row): BenchmarkDetector & { module: string } {
  const lat = r.latency_p50_us !== null
    ? { p50: Number(r.latency_p50_us), p95: Number(r.latency_p95_us), p99: Number(r.latency_p99_us) }
    : null;
  return {
    module: r.module,
    detector: r.detector,
    paradigm: r.paradigm,
    benchmark_version: 1,
    corpus: { attack_samples: r.attack_samples, benign_samples: r.benign_samples },
    confusion: { tp: r.tp, fp: r.fp, tn: r.tn, fn: r.fn },
    metrics: {
      detection_rate: Number(r.detection_rate),
      false_positive_rate: Number(r.false_positive_rate),
      precision: Number(r.precision),
      recall: Number(r.recall),
      f1: Number(r.f1),
    },
    latency_us: lat,
    thresholds: r.thresholds ?? {},
    notes: r.notes ?? undefined,
  };
}

/** The most recent run's detector scorecards, plus its metadata. */
export async function latestRun(): Promise<BenchmarkRun | null> {
  const db = getDb();
  const head = await db.query<{ run_id: string; run_at_ms: string; git_commit: string | null }>(
    `select run_id, (extract(epoch from run_at) * 1000)::bigint as run_at_ms, git_commit
     from monolith.benchmark_runs order by run_at desc limit 1`,
  );
  if (!head.rows.length) return null;
  const { run_id, run_at_ms, git_commit } = head.rows[0];
  const rows = await db.query<Row>(
    `select run_id, (extract(epoch from run_at) * 1000)::bigint as run_at_ms, git_commit,
            module, detector, paradigm, attack_samples, benign_samples,
            tp, fp, tn, fn, detection_rate, false_positive_rate, precision, recall, f1,
            latency_p50_us, latency_p95_us, latency_p99_us, thresholds, notes
     from monolith.benchmark_runs where run_id = $1
     order by module, detector`,
    [run_id],
  );
  return {
    run_id,
    run_at_ms: Number(run_at_ms),
    git_commit: git_commit ?? undefined,
    detectors: rows.rows.map(fromRow),
  };
}

/** Per-detector history (detection rate + F1 over time) for a small trend. */
export async function detectorHistory(limit = 20): Promise<
  { module: string; detector: string; points: { run_at_ms: number; detection_rate: number; f1: number }[] }[]
> {
  const safe = Math.max(1, Math.min(limit, 100));
  const rows = await getDb().query<{
    module: string; detector: string; run_at_ms: string; detection_rate: string; f1: string;
  }>(
    `select module, detector, (extract(epoch from run_at) * 1000)::bigint as run_at_ms,
            detection_rate, f1
     from monolith.benchmark_runs
     order by module, detector, run_at desc`,
  );
  const map = new Map<string, { module: string; detector: string; points: { run_at_ms: number; detection_rate: number; f1: number }[] }>();
  for (const r of rows.rows) {
    const key = `${r.module}/${r.detector}`;
    if (!map.has(key)) map.set(key, { module: r.module, detector: r.detector, points: [] });
    const bucket = map.get(key)!;
    if (bucket.points.length < safe) {
      bucket.points.push({ run_at_ms: Number(r.run_at_ms), detection_rate: Number(r.detection_rate), f1: Number(r.f1) });
    }
  }
  return [...map.values()];
}
