import { randomUUID } from "node:crypto";
import { withTenantDb } from "@/lib/db";

// Benchmark results are evaluation metadata, deliberately separate from the
// event ledger. This module owns reading and writing monolith.benchmark_runs.

const KNOWN_MODULES = new Set(["mcp-shield", "vector-anchor", "trace-audit"]);
const PARADIGMS = new Set(["threshold", "exact", "regex"]);
const MAX_NOTES = 2000;
const MAX_PG_INT = 2_147_483_647;
const MAX_RUN_AT_MS = 32_503_680_000_000; // 3000-01-01 UTC

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
  tenant_id: string;
  run_at_ms: number;
  git_commit?: string;
  detectors: BenchmarkDetector[];
}

// --- validation ------------------------------------------------------------

function int(value: unknown, field: string): number {
  if (
    typeof value !== "number"
    || !Number.isFinite(value)
    || value < 0
    || value > MAX_PG_INT
    || !Number.isInteger(value)
  ) {
    throw new BenchmarkInputError(
      `${field} must be a non-negative 32-bit integer`,
    );
  }
  return value;
}

function latencyNumber(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new BenchmarkInputError(`${field} must be a non-negative finite number`);
  }
  return value;
}

/** Validate and normalize an incoming run. Never trusts the derived metrics —
 *  they are recomputed from the confusion matrix so a bad rate cannot land. */
export function normalizeRun(raw: unknown, tenantId: string): BenchmarkRun {
  if (!raw || typeof raw !== "object") {
    throw new BenchmarkInputError("body must be a JSON object");
  }
  const value = (Array.isArray(raw) ? { detectors: raw } : raw) as Record<string, unknown>;
  const detectorsRaw = value.detectors;
  const list = Array.isArray(detectorsRaw)
    ? detectorsRaw
    : Array.isArray(value.reports)
      ? value.reports
      : null;
  if (!list || list.length === 0 || list.length > 50) {
    throw new BenchmarkInputError("a run must carry between 1 and 50 detector reports");
  }

  const detectorKeys = new Set<string>();
  const detectors = list.map((d): BenchmarkDetector => {
    if (!d || typeof d !== "object") throw new BenchmarkInputError("each detector must be an object");
    const r = d as Record<string, unknown>;
    const moduleName = typeof r.module === "string" ? r.module : "";
    if (!KNOWN_MODULES.has(moduleName)) throw new BenchmarkInputError("unknown module in a detector report");
    const detector = typeof r.detector === "string" ? r.detector.trim() : "";
    if (!detector) throw new BenchmarkInputError("detector name is required");
    if (detector.length > 64) {
      throw new BenchmarkInputError("detector name must be at most 64 characters");
    }
    const detectorKey = `${moduleName}/${detector}`;
    if (detectorKeys.has(detectorKey)) {
      throw new BenchmarkInputError(`duplicate detector report '${detectorKey}'`);
    }
    detectorKeys.add(detectorKey);
    const paradigm = typeof r.paradigm === "string" ? r.paradigm : "";
    if (!PARADIGMS.has(paradigm)) throw new BenchmarkInputError(`unknown paradigm '${paradigm}'`);

    const confusion = (r.confusion ?? {}) as Record<string, unknown>;
    const tp = int(confusion.tp, "tp");
    const fp = int(confusion.fp, "fp");
    const tn = int(confusion.tn, "tn");
    const fnv = int(confusion.fn, "fn");
    if (tp + fnv > MAX_PG_INT || fp + tn > MAX_PG_INT) {
      throw new BenchmarkInputError("corpus totals must fit a 32-bit integer");
    }

    // Recompute the metrics rather than trusting the client's numbers.
    const detection = tp + fnv > 0 ? tp / (tp + fnv) : 0;
    const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = detection;
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

    const lat = r.latency_us;
    let latency: BenchmarkDetector["latency_us"] = null;
    if (lat !== null && lat !== undefined) {
      if (typeof lat !== "object" || Array.isArray(lat)) {
        throw new BenchmarkInputError("latency_us must be null or an object");
      }
      const rawLatency = lat as Record<string, unknown>;
      const p50 = latencyNumber(rawLatency.p50, "latency_us.p50");
      const p95 = latencyNumber(rawLatency.p95, "latency_us.p95");
      const p99 = latencyNumber(rawLatency.p99, "latency_us.p99");
      if (!(p50 <= p95 && p95 <= p99)) {
        throw new BenchmarkInputError("latency percentiles must satisfy p50 <= p95 <= p99");
      }
      latency = { p50, p95, p99 };
    }

    const notes = typeof r.notes === "string" ? r.notes : undefined;
    if (notes && notes.length > MAX_NOTES) {
      throw new BenchmarkInputError(`notes must be at most ${MAX_NOTES} characters`);
    }
    const version = r.benchmark_version === undefined
      ? 1
      : int(r.benchmark_version, "benchmark_version");
    if (version < 1 || version > 32767) {
      throw new BenchmarkInputError("benchmark_version must be between 1 and 32767");
    }
    const thresholds = r.thresholds && typeof r.thresholds === "object" && !Array.isArray(r.thresholds)
      ? (r.thresholds as Record<string, unknown>)
      : {};

    return {
      module: moduleName,
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

  let runAt = Date.now();
  if (value.run_at_ms !== undefined) {
    if (
      typeof value.run_at_ms !== "number"
      || !Number.isFinite(value.run_at_ms)
      || value.run_at_ms < 1
      || value.run_at_ms > MAX_RUN_AT_MS
    ) {
      throw new BenchmarkInputError(
        "run_at_ms must be a positive Unix timestamp no later than 3000-01-01",
      );
    }
    runAt = Math.trunc(value.run_at_ms);
  }
  const gitCommitValue = typeof value.git_commit === "string" ? value.git_commit.trim() : "";
  const gitCommit = gitCommitValue || undefined;
  if (gitCommit && gitCommit.length > 64) {
    throw new BenchmarkInputError("git_commit must be at most 64 characters");
  }

  return {
    run_id: randomUUID(),
    tenant_id: tenantId,
    run_at_ms: runAt,
    git_commit: gitCommit,
    detectors,
  };
}

function round4(x: number): number {
  return Math.round(x * 10_000) / 10_000;
}

// --- writes ----------------------------------------------------------------

export async function persistRun(run: BenchmarkRun): Promise<{ run_id: string; rows: number }> {
  return withTenantDb(run.tenant_id, async (client) => {
    for (const d of run.detectors) {
      await client.query(
        `insert into monolith.benchmark_runs (
           run_id, tenant_id, benchmark_version, run_at, git_commit, module, detector, paradigm,
           attack_samples, benign_samples, tp, fp, tn, fn,
           detection_rate, false_positive_rate, precision, recall, f1,
           latency_p50_us, latency_p95_us, latency_p99_us, thresholds, notes
         ) values (
           $1, $2, $3, to_timestamp($4::double precision / 1000), $5, $6, $7, $8,
           $9, $10, $11, $12, $13, $14,
           $15, $16, $17, $18, $19,
           $20, $21, $22, $23::jsonb, $24
         )`,
        [
          run.run_id, run.tenant_id, d.benchmark_version, run.run_at_ms, run.git_commit ?? null,
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
    return { run_id: run.run_id, rows: run.detectors.length };
  });
}

// --- reads -----------------------------------------------------------------

type Row = {
  run_id: string;
  tenant_id: string;
  benchmark_version: number;
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
    benchmark_version: r.benchmark_version,
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
export async function latestRun(tenantId: string): Promise<BenchmarkRun | null> {
  return withTenantDb(tenantId, async (db) => {
    const head = await db.query<{ run_id: string; run_at_ms: string; git_commit: string | null }>(
      `select run_id, (extract(epoch from run_at) * 1000)::bigint as run_at_ms, git_commit
       from monolith.benchmark_runs
       where tenant_id = $1
       order by run_at desc limit 1`,
      [tenantId],
    );
    if (!head.rows.length) return null;
    const { run_id, run_at_ms, git_commit } = head.rows[0];
    const rows = await db.query<Row>(
      `select run_id, tenant_id, benchmark_version,
              (extract(epoch from run_at) * 1000)::bigint as run_at_ms, git_commit,
              module, detector, paradigm, attack_samples, benign_samples,
              tp, fp, tn, fn, detection_rate, false_positive_rate, precision, recall, f1,
              latency_p50_us, latency_p95_us, latency_p99_us, thresholds, notes
       from monolith.benchmark_runs where run_id = $1 and tenant_id = $2
       order by module, detector`,
      [run_id, tenantId],
    );
    return {
      run_id,
      tenant_id: tenantId,
      run_at_ms: Number(run_at_ms),
      git_commit: git_commit ?? undefined,
      detectors: rows.rows.map(fromRow),
    };
  });
}

/** Per-detector history (detection rate + F1 over time) for a small trend. */
export async function detectorHistory(tenantId: string, limit = 20): Promise<
  { module: string; detector: string; points: { run_at_ms: number; detection_rate: number; f1: number }[] }[]
> {
  const safe = Math.max(1, Math.min(limit, 100));
  return withTenantDb(tenantId, async (db) => {
    const rows = await db.query<{
      module: string; detector: string; run_at_ms: string; detection_rate: string; f1: string;
    }>(
      `select module, detector, run_at_ms, detection_rate, f1
       from (
         select module, detector,
                (extract(epoch from run_at) * 1000)::bigint as run_at_ms,
                detection_rate, f1,
                row_number() over (
                  partition by module, detector order by run_at desc
                ) as history_rank
         from monolith.benchmark_runs
         where tenant_id = $1
       ) ranked
       where history_rank <= $2
       order by module, detector, run_at_ms asc`,
      [tenantId, safe],
    );
    const map = new Map<string, { module: string; detector: string; points: { run_at_ms: number; detection_rate: number; f1: number }[] }>();
    for (const r of rows.rows) {
      const key = `${r.module}/${r.detector}`;
      if (!map.has(key)) map.set(key, { module: r.module, detector: r.detector, points: [] });
      const bucket = map.get(key)!;
      bucket.points.push({ run_at_ms: Number(r.run_at_ms), detection_rate: Number(r.detection_rate), f1: Number(r.f1) });
    }
    return [...map.values()];
  });
}
