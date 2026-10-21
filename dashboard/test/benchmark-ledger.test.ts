import assert from "node:assert/strict";
import { test } from "node:test";
import { GET, POST } from "../app/api/benchmarks/route";
import {
  BenchmarkInputError,
  detectorHistory,
  latestRun,
  normalizeRun,
  persistRun,
} from "../lib/benchmark-store";

/**
 * The benchmark ledger: what the detectors measured, and what the operator
 * is shown about it.
 *
 * A benchmark ledger is the one place in this repository where numbers are
 * written by a human's CI job and then read back as evidence. That makes it
 * unusual in a way that matters: the numbers are not a measurement the
 * dashboard can take itself, so the only defence against a wrong number
 * being recorded is that the ledger refuses to believe the client.
 *
 * Two properties carry that weight, and both are asserted here:
 *
 *  1. **The metrics are recomputed, never copied.** A client may report its
 *     confusion matrix; it may not report its detection rate. The rate is
 *     derived from the matrix on the way in, so a run that claims a perfect
 *     score over a matrix that says otherwise stores the matrix's answer.
 *  2. **The tenant comes from the credential.** A body that names a tenant
 *     is ignored, because a run filed under somebody else's tenant is a run
 *     the wrong operator can see and the right one cannot.
 *
 * The read path is a pair of scoped queries: the most recent run, and a
 * per-detector trend. Both must be scoped to the tenant, and both are
 * answered by a stand-in pool that records the statements actually run.
 */

const ANALYST_TOKEN = "analyst-token-000000";
const VIEWER_TOKEN = "viewer-token-000000";

const OPERATOR_ENV = JSON.stringify({
  alice: { token: ANALYST_TOKEN, role: "analyst", tenant_id: "tenant-a" },
  bob: { token: VIEWER_TOKEN, role: "viewer", tenant_id: "tenant-a" },
});

type Statement = { sql: string; params: unknown[] };

/**
 * Run a body with environment variables set, then put them back.
 */
async function withEnv(
  vars: Record<string, string | undefined>,
  body: () => void | Promise<void>,
): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(vars)) {
    saved[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    await body();
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

/** A detector report, as a CI job would file it. */
function report(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    module: "mcp-shield",
    detector: "schema_fingerprint",
    paradigm: "exact",
    confusion: { tp: 8, fp: 1, tn: 40, fn: 2 },
    latency_us: { p50: 120, p95: 400, p99: 900 },
    thresholds: { key: "hmac-sha256" },
    ...overrides,
  };
}

/**
 * A stand-in for the pooled client. It answers the four statements the
 * ledger issues and records all of them.
 */
function standInPool(options: {
  headRows?: Record<string, unknown>[];
  detectorRows?: Record<string, unknown>[];
  historyRows?: Record<string, unknown>[];
  observedRows?: Record<string, unknown>[];
} = {}): { pool: unknown; statements: Statement[] } {
  const statements: Statement[] = [];
  const pool = {
    connect: async () => ({
      query: async (sql: string, params: unknown[] = []) => {
        statements.push({ sql, params });
        if (sql.includes("insert into monolith.benchmark_runs")) {
          return { rows: [], rowCount: 1 };
        }
        if (sql.includes("order by run_at desc limit 1")) {
          return { rows: options.headRows ?? [], rowCount: (options.headRows ?? []).length };
        }
        if (sql.includes("where run_id = $1 and tenant_id = $2")) {
          const rows = options.detectorRows ?? [];
          return { rows, rowCount: rows.length };
        }
        if (sql.includes("history_rank")) {
          const rows = options.historyRows ?? [];
          return { rows, rowCount: rows.length };
        }
        if (sql.includes("count(*) filter (where t.resolution = 'true_positive')")) {
          const rows = options.observedRows ?? [];
          return { rows, rowCount: rows.length };
        }
        return { rows: [], rowCount: 0 };
      },
      release: () => {},
    }),
  };
  return { pool, statements };
}

/** Install a stand-in pool for the duration of a body. */
async function withPool(
  options: Parameters<typeof standInPool>[0],
  body: (statements: Statement[]) => void | Promise<void>,
): Promise<void> {
  const { pool, statements } = standInPool(options);
  const globalRef = globalThis as unknown as { __monolithPool?: unknown };
  const previousPool = globalRef.__monolithPool;
  globalRef.__monolithPool = pool;
  try {
    await withEnv({ DATABASE_URL: "postgresql://unused/unused" }, async () => {
      await body(statements);
    });
  } finally {
    globalRef.__monolithPool = previousPool;
  }
}

test("the metrics are computed from the matrix, not believed", () => {
  // A client that reports a perfect detection rate over a matrix that says
  // otherwise is lying about the one number the dashboard will show.
  const run = normalizeRun(
    {
      detectors: [
        report({
          confusion: { tp: 8, fp: 1, tn: 40, fn: 2 },
          metrics: {
            detection_rate: 1,
            false_positive_rate: 0,
            precision: 1,
            recall: 1,
            f1: 1,
          },
        }),
      ],
    },
    "tenant-a",
  );
  const detector = run.detectors[0];
  // 8 of 10 attacks caught.
  assert.equal(detector.metrics.detection_rate, 0.8);
  // 1 of 41 benign samples were false positives.
  assert.equal(detector.metrics.false_positive_rate, 0.0244);
  // 8 of 9 flagged samples were right.
  assert.equal(detector.metrics.precision, 0.8889);
  assert.equal(detector.metrics.recall, 0.8);
  // f1 = 2 * 0.8889 * 0.8 / (0.8889 + 0.8)
  assert.equal(detector.metrics.f1, 0.8421);
});

test("the corpus is counted from the matrix", () => {
  // The body claims a corpus of a thousand samples each. It does not get
  // one: the corpus is every sample the matrix accounts for.
  const run = normalizeRun(
    {
      detectors: [
        report({ corpus: { attack_samples: 1000, benign_samples: 1000 } }),
      ],
    },
    "tenant-a",
  );
  const detector = run.detectors[0];
  // The attack corpus is every attack sample, caught or not; the benign
  // corpus is every benign sample. A run that reported its own corpus
  // counts could claim a thousand samples over a matrix of ten.
  assert.equal(detector.corpus.attack_samples, 10);
  assert.equal(detector.corpus.benign_samples, 41);
});

test("a run must carry between one and fifty detector reports", () => {
  assert.throws(() => normalizeRun({ detectors: [] }, "tenant-a"), BenchmarkInputError);
  assert.throws(
    () => normalizeRun({ detectors: Array.from({ length: 51 }, () => report()) }, "tenant-a"),
    BenchmarkInputError,
  );
  // One is enough.
  assert.equal(normalizeRun({ detectors: [report()] }, "tenant-a").detectors.length, 1);
});

test("a report may be filed on its own, under either key", () => {
  // The fixtures file a bare list; older runs used "reports".
  const bare = normalizeRun([report()], "tenant-a");
  assert.equal(bare.detectors.length, 1);
  const legacy = normalizeRun({ reports: [report()] }, "tenant-a");
  assert.equal(legacy.detectors.length, 1);
});

test("an unknown module or paradigm is refused", () => {
  assert.throws(
    () => normalizeRun({ detectors: [report({ module: "not-a-module" })] }, "tenant-a"),
    BenchmarkInputError,
  );
  assert.throws(
    () => normalizeRun({ detectors: [report({ paradigm: "vibes" })] }, "tenant-a"),
    BenchmarkInputError,
  );
});

test("a detector without a usable name is refused", () => {
  assert.throws(
    () => normalizeRun({ detectors: [report({ detector: "" })] }, "tenant-a"),
    BenchmarkInputError,
  );
  assert.throws(
    () => normalizeRun({ detectors: [report({ detector: "   " })] }, "tenant-a"),
    BenchmarkInputError,
  );
  assert.throws(
    () => normalizeRun({ detectors: [report({ detector: "x".repeat(65) })] }, "tenant-a"),
    BenchmarkInputError,
  );
});

test("the same detector twice in one run is refused", () => {
  // Two rows for one detector in one run would make the trend chart a lie:
  // the same detector would appear to have two scores in one run.
  assert.throws(
    () => normalizeRun({ detectors: [report(), report()] }, "tenant-a"),
    BenchmarkInputError,
  );
  // The same detector name under a different module is a different detector.
  const ok = normalizeRun(
    { detectors: [report(), report({ module: "trace-audit" })] },
    "tenant-a",
  );
  assert.equal(ok.detectors.length, 2);
});

test("a confusion matrix must be made of non-negative integers", () => {
  for (const confusion of [
    { tp: -1, fp: 0, tn: 0, fn: 0 },
    { tp: 1.5, fp: 0, tn: 0, fn: 0 },
    { tp: "8", fp: 0, tn: 0, fn: 0 },
    { tp: 8, fp: 0, tn: 0 },
    { tp: 8, fp: 0, tn: 0, fn: 2_147_483_648 },
  ]) {
    assert.throws(
      () => normalizeRun({ detectors: [report({ confusion })] }, "tenant-a"),
      BenchmarkInputError,
      `accepted: ${JSON.stringify(confusion)}`,
    );
  }
});

test("latency percentiles that do not ascend are refused", () => {
  assert.throws(
    () =>
      normalizeRun(
        { detectors: [report({ latency_us: { p50: 500, p95: 400, p99: 900 } })] },
        "tenant-a",
      ),
    BenchmarkInputError,
  );
  assert.throws(
    () =>
      normalizeRun(
        { detectors: [report({ latency_us: { p50: 100, p95: 400, p99: 300 } })] },
        "tenant-a",
      ),
    BenchmarkInputError,
  );
  // An array is not a percentile set.
  assert.throws(
    () => normalizeRun({ detectors: [report({ latency_us: [1, 2, 3] })] }, "tenant-a"),
    BenchmarkInputError,
  );
  // Absent is allowed: not every detector measures its own cost.
  assert.equal(normalizeRun({ detectors: [report({ latency_us: null })] }, "tenant-a")
    .detectors[0].latency_us, null);
});

test("the benchmark version is bounded", () => {
  // The version is what makes two runs comparable, so it is part of the
  // claim rather than decoration. A missing one means version 1.
  assert.equal(
    normalizeRun({ detectors: [report()] }, "tenant-a").detectors[0].benchmark_version,
    1,
  );
  assert.equal(
    normalizeRun({ detectors: [report({ benchmark_version: 32767 })] }, "tenant-a").detectors[0]
      .benchmark_version,
    32767,
  );
  for (const benchmark_version of [0, 32768, 1.5, -1]) {
    assert.throws(
      () => normalizeRun({ detectors: [report({ benchmark_version })] }, "tenant-a"),
      BenchmarkInputError,
      `accepted: ${benchmark_version}`,
    );
  }
});

test("a latency that is not a measurement is refused", () => {
  for (const latency_us of [
    { p50: -1, p95: 400, p99: 900 },
    { p50: 100, p95: Number.NaN, p99: 900 },
    { p50: 100, p95: 400 },
  ]) {
    assert.throws(
      () => normalizeRun({ detectors: [report({ latency_us })] }, "tenant-a"),
      BenchmarkInputError,
      `accepted: ${JSON.stringify(latency_us)}`,
    );
  }
});

test("thresholds that are not an object are ignored, not stored", () => {
  // A threshold set that is not a map of values cannot be compared across
  // runs, so it is dropped rather than stored as something a later reader
  // would have to guess about.
  for (const thresholds of [["a"], "not-a-map", 7]) {
    const run = normalizeRun({ detectors: [report({ thresholds })] }, "tenant-a");
    assert.deepEqual(run.detectors[0].thresholds, {});
  }
  const kept = normalizeRun({ detectors: [report({ thresholds: { key: "hmac" } })] }, "tenant-a");
  assert.deepEqual(kept.detectors[0].thresholds, { key: "hmac" });
});

test("the notes and the commit are bounded", () => {
  assert.throws(
    () => normalizeRun({ detectors: [report({ notes: "x".repeat(2001) })] }, "tenant-a"),
    BenchmarkInputError,
  );
  assert.throws(
    () => normalizeRun({ git_commit: "x".repeat(65), detectors: [report()] }, "tenant-a"),
    BenchmarkInputError,
  );
});

test("the run's timestamp must be a real one", () => {
  for (const run_at_ms of [0, -1, 32_503_680_000_001]) {
    assert.throws(
      () => normalizeRun({ run_at_ms, detectors: [report()] }, "tenant-a"),
      BenchmarkInputError,
      `accepted: ${run_at_ms}`,
    );
  }
  const run = normalizeRun({ run_at_ms: 1770000000000, detectors: [report()] }, "tenant-a");
  assert.equal(run.run_at_ms, 1770000000000);
});

test("the tenant comes from the credential, not the body", () => {
  // A body that names a tenant is ignored. A run filed under somebody
  // else's tenant is a run the wrong operator can read.
  const run = normalizeRun({ tenant_id: "tenant-b", detectors: [report()] }, "tenant-a");
  assert.equal(run.tenant_id, "tenant-a");
});

test("a run is written one row per detector, in one transaction", async () => {
  await withPool({}, async (statements) => {
    const run = normalizeRun(
      { detectors: [report(), report({ detector: "description_scanner" })] },
      "tenant-a",
    );
    const result = await persistRun(run);
    assert.equal(result.rows, 2);
    assert.equal(result.run_id, run.run_id);

    const inserts = statements.filter((s) => s.sql.includes("insert into monolith.benchmark_runs"));
    assert.equal(inserts.length, 2, "each detector must get its own row");
    // One transaction: begin, then the inserts, then commit. A run half
    // written would show a detector with no score beside a run that has one.
    assert.ok(statements.some((s) => s.sql === "begin"), "the write was not in a transaction");
    assert.ok(statements.some((s) => s.sql === "commit"), "the transaction was never committed");
    assert.ok(
      !statements.some((s) => s.sql === "rollback"),
      "a committed write must not have rolled back",
    );
    // And the tenant is bound in the transaction context, not only in the row.
    assert.ok(
      statements.some((s) => s.sql.includes("set_config('monolith.tenant_id'")),
      "the tenant context was never set",
    );
    // The row carries the recomputed rate, not the client's claim. The
    // placeholders are 1-indexed, so $15 (detection_rate) is params[14].
    const params = inserts[0].params as unknown[];
    assert.equal(params[1], "tenant-a", "the row's tenant");
    assert.equal(params[14], 0.8, "the row's detection rate is the recomputed one");
    assert.equal(params[15], 0.0244, "the row's false-positive rate is the recomputed one");
  });
});

test("the latest run is the most recent one, for this tenant", async () => {
  await withPool(
    {
      headRows: [{ run_id: "run-1", run_at_ms: "1770000000000", git_commit: "abc123" }],
      detectorRows: [],
    },
    async (statements) => {
      const run = await latestRun("tenant-a");
      assert.equal(run?.run_id, "run-1");
      assert.equal(run?.run_at_ms, 1770000000000);
      assert.equal(run?.git_commit, "abc123");

      const head = statements.find((s) => s.sql.includes("order by run_at desc limit 1"));
      assert.ok(head, "the head of the ledger was never read");
      assert.match(head.sql, /where tenant_id = \$1/i);
      assert.deepEqual(head.params, ["tenant-a"]);

      // The detector rows are read by run id *and* tenant, so a run id
      // from another tenant cannot pull rows across.
      const rows = statements.find((s) => s.sql.includes("where run_id = $1 and tenant_id = $2"));
      assert.ok(rows, "the run's detectors were never read");
      assert.deepEqual(rows.params, ["run-1", "tenant-a"]);
    },
  );
});

test("no run yet is null, not an empty run", async () => {
  await withPool({ headRows: [] }, async () => {
    // An empty run would render as a benchmark page with no data but no
    // error, which reads as "nothing has been measured yet" — true — but
    // also as "the measurement is zero", which is not the same claim.
    assert.equal(await latestRun("tenant-a"), null);
  });
});

test("the history is one bucket per detector, oldest point first", async () => {
  await withPool(
    {
      historyRows: [
        { module: "mcp-shield", detector: "a", run_at_ms: "1000", detection_rate: "0.5", f1: "0.5" },
        { module: "mcp-shield", detector: "b", run_at_ms: "2000", detection_rate: "0.6", f1: "0.6" },
        { module: "mcp-shield", detector: "a", run_at_ms: "3000", detection_rate: "0.7", f1: "0.7" },
      ],
    },
    async (statements) => {
      const history = await detectorHistory("tenant-a");
      assert.equal(history.length, 2, "one bucket per detector");
      const first = history.find((h) => h.detector === "a");
      assert.ok(first);
      assert.equal(first.points.length, 2, "both runs of the detector are in its bucket");
      // The order is the database's; what the store must not do is mix two
      // detectors' points into one series.
      assert.equal(first.points[0].run_at_ms, 1000);
      assert.equal(first.points[0].detection_rate, 0.5);
      assert.equal(first.points[1].run_at_ms, 3000);

      const query = statements.find((s) => s.sql.includes("history_rank"));
      assert.ok(query, "the history was never read");
      assert.match(query.sql, /where tenant_id = \$1/i);
      assert.equal(query.params[0], "tenant-a");
    },
  );
});

test("the history is bounded", async () => {
  await withPool({ historyRows: [] }, async (statements) => {
    const historyLimit = () =>
      statements.filter((s) => s.sql.includes("history_rank")).at(-1)?.params[1];

    await detectorHistory("tenant-a", 0);
    assert.equal(historyLimit(), 1, "a limit below one becomes one");
    await detectorHistory("tenant-a", 5000);
    assert.equal(historyLimit(), 100, "a limit above a hundred becomes a hundred");
  });
});

test("the read route returns the run, the history and the observed accuracy together", async () => {
  await withPool(
    {
      headRows: [{ run_id: "run-1", run_at_ms: "1770000000000", git_commit: null }],
      detectorRows: [],
      historyRows: [],
      observedRows: [{ module: "mcp-shield", tp: "3", fp: "1", benign: "2", duplicate: "0" }],
    },
    async () => {
      await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV }, async () => {
        const response = await GET(
          new Request("http://localhost/api/benchmarks", {
            headers: { authorization: `Bearer ${ANALYST_TOKEN}` },
          }),
        );
        assert.equal(response.status, 200);
        const body = (await response.json()) as {
          run?: { run_id?: string };
          history?: unknown[];
          observed?: Array<{ module?: string; precision?: number | null }>;
        };
        assert.equal(body.run?.run_id, "run-1");
        assert.deepEqual(body.history, []);
        // The page's whole argument is the comparison between the lab
        // numbers and the observed ones, so they are served together.
        assert.equal(body.observed?.[0]?.module, "mcp-shield");
        assert.equal(body.observed?.[0]?.precision, 0.75);
      });
    },
  );
});

test("recording a run is an analyst's action", async () => {
  await withPool({}, async () => {
    await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV }, async () => {
      const response = await POST(
        new Request("http://localhost/api/benchmarks", {
          method: "POST",
          headers: {
            authorization: `Bearer ${VIEWER_TOKEN}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ detectors: [report()] }),
        }),
      );
      assert.equal(response.status, 403);
    });
  });
});

test("an unauthenticated caller learns nothing about the ledger", async () => {
  await withPool({}, async () => {
    await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV }, async () => {
      const read = await GET(new Request("http://localhost/api/benchmarks"));
      assert.equal(read.status, 401);
      const write = await POST(
        new Request("http://localhost/api/benchmarks", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ detectors: [report()] }),
        }),
      );
      assert.equal(write.status, 401);
    });
  });
});

test("a run that is not valid is refused with a 422", async () => {
  await withPool({}, async () => {
    await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV }, async () => {
      const response = await POST(
        new Request("http://localhost/api/benchmarks", {
          method: "POST",
          headers: {
            authorization: `Bearer ${ANALYST_TOKEN}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ detectors: [report({ module: "not-a-module" })] }),
        }),
      );
      assert.equal(response.status, 422);
      const body = (await response.json()) as { error?: string };
      assert.match(body.error ?? "", /unknown module/);
    });
  });
});

test("a body that is not JSON, or is too large, is refused", async () => {
  await withPool({}, async () => {
    await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV }, async () => {
      const notJson = await POST(
        new Request("http://localhost/api/benchmarks", {
          method: "POST",
          headers: {
            authorization: `Bearer ${ANALYST_TOKEN}`,
            "content-type": "application/json",
          },
          body: "{not json",
        }),
      );
      assert.equal(notJson.status, 400);

      // The body is bounded so a run cannot be used to fill the ledger.
      const tooLarge = await POST(
        new Request("http://localhost/api/benchmarks", {
          method: "POST",
          headers: {
            authorization: `Bearer ${ANALYST_TOKEN}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ detectors: [report()], pad: "x".repeat(256 * 1024) }),
        }),
      );
      assert.equal(tooLarge.status, 413);
    });
  });
});

test("a recorded run answers with what it recorded and nothing more", async () => {
  await withPool({}, async () => {
    await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV }, async () => {
      const response = await POST(
        new Request("http://localhost/api/benchmarks", {
          method: "POST",
          headers: {
            authorization: `Bearer ${ANALYST_TOKEN}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ detectors: [report()] }),
        }),
      );
      assert.equal(response.status, 201);
      const body = (await response.json()) as Record<string, unknown>;
      assert.equal(body.recorded, 1);
      assert.match(String(body.run_id), /^[0-9a-f-]{36}$/);
      // The answer is a receipt, not the run: it must not carry the whole
      // detector report back out, and it must never carry a credential.
      assert.deepEqual(Object.keys(body).sort(), ["recorded", "run_id"]);
    });
  });
});
