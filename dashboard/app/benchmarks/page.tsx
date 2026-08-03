"use client";

import { useEffect, useMemo, useState } from "react";
import { KNOWN_MODULES, MODULE_ACCENT, MODULE_LABELS, MODULE_LAYER } from "@/lib/types";
import type { BenchmarkDetector, BenchmarkRun } from "@/lib/benchmark-store";
import type { ObservedAccuracy } from "@/lib/incident-store";
import { Rail } from "../components/Sidebar";
import ThemeToggle from "../components/ThemeToggle";
import OperatorBadge from "../components/OperatorBadge";
import { ModuleGlyph, IconGauge, IconBolt } from "../components/Icons";

function pct(x: number): string {
  return `${(x * 100).toFixed(x === 0 || x === 1 ? 0 : 1)}%`;
}

function when(ms: number): string {
  if (!Number.isFinite(ms)) return "—";
  return new Date(ms).toLocaleString([], { hour12: false });
}

const PARADIGM_LABEL: Record<string, string> = {
  threshold: "threshold detector",
  regex: "pattern detector",
  exact: "exact match",
};

/** A labelled metric with a thin proportional bar. Higher is better for all of
 *  these except FPR, so FPR is drawn in the severity colour to read as a cost. */
function Metric({ label, value, tone }: { label: string; value: number; tone?: "bad" }) {
  const color = tone === "bad" ? "var(--sev-warning)" : "var(--accent-mod)";
  return (
    <div className="bm-metric">
      <div className="bm-metric-top">
        <span className="bm-metric-k">{label}</span>
        <span className="bm-metric-v num">{pct(value)}</span>
      </div>
      <div className="bm-bar">
        <span style={{ width: `${Math.round(value * 100)}%`, background: color }} />
      </div>
    </div>
  );
}

function ConfusionMatrix({ d }: { d: BenchmarkDetector }) {
  const { tp, fp, tn, fn } = d.confusion;
  const cell = (label: string, n: number, good: boolean) => (
    <div className={`cm-cell${good ? " good" : " bad"}`}>
      <span className="cm-n num">{n}</span>
      <span className="cm-l">{label}</span>
    </div>
  );
  return (
    <div className="cm-grid" aria-label="confusion matrix">
      {cell("true positive", tp, true)}
      {cell("false negative", fn, false)}
      {cell("false positive", fp, false)}
      {cell("true negative", tn, true)}
    </div>
  );
}

function Scorecard({ d }: { d: BenchmarkDetector }) {
  const accent = MODULE_ACCENT[d.module] ?? "var(--ink-faint)";
  const exact = d.paradigm === "exact";
  return (
    <div className="card bm-card" style={{ ["--accent-mod" as string]: accent }}>
      <div className="bm-head">
        <span className="bm-ic"><ModuleGlyph module={d.module} size={16} /></span>
        <div className="bm-title">
          <span className="bm-name">{d.detector.replace(/_/g, " ")}</span>
          <span className="bm-para">{PARADIGM_LABEL[d.paradigm] ?? d.paradigm}</span>
        </div>
        <span className="bm-samples num">
          {d.corpus.attack_samples} attack · {d.corpus.benign_samples} benign
        </span>
      </div>

      {exact ? (
        <div className="bm-exact">
          100% detection · 0 false flags — <b>by construction</b>, not a tuned detector.
        </div>
      ) : null}

      <div className="bm-metrics">
        <Metric label="Detection" value={d.metrics.detection_rate} />
        <Metric label="Precision" value={d.metrics.precision} />
        <Metric label="Recall" value={d.metrics.recall} />
        <Metric label="F1" value={d.metrics.f1} />
        <Metric label="False-positive" value={d.metrics.false_positive_rate} tone="bad" />
      </div>

      <div className="bm-lower">
        <ConfusionMatrix d={d} />
        {d.latency_us ? (
          <div className="bm-latency">
            <span className="bm-lat-k"><IconBolt size={12} /> detector overhead</span>
            <span className="bm-lat-v num">
              {d.latency_us.p50.toFixed(1)}µs <span className="bm-lat-x">p50</span>
            </span>
            <span className="bm-lat-sub num">
              p95 {d.latency_us.p95.toFixed(1)}µs · p99 {d.latency_us.p99.toFixed(1)}µs
            </span>
          </div>
        ) : null}
      </div>

      {d.notes ? <div className="bm-notes">{d.notes}</div> : null}
    </div>
  );
}

/** Precision as analysts actually judged it, next to the corpus number.
 *
 *  The lab figure says how a detector scores against documents we wrote. This
 *  says how it scored against whatever really arrived, judged by whoever
 *  handled it. Divergence between the two is a finding in either direction: a
 *  corpus that flatters the detector, or production traffic the corpus never
 *  anticipated.
 */
function ObservedPanel({ rows }: { rows: ObservedAccuracy[] }) {
  const scored = rows.filter((r) => r.scored > 0);
  return (
    <section className="bm-section">
      <div className="bm-section-head">
        <span className="bm-sec-ic"><IconBolt size={15} /></span>
        <span className="bm-sec-name">Observed in operation</span>
        <span className="bm-sec-layer">from analyst verdicts</span>
      </div>
      {scored.length === 0 ? (
        <div className="bm-observed-empty">
          No incidents resolved with a verdict yet. Precision here is computed
          from real triage decisions, so this fills in as incidents are closed
          on the investigation queue — it is deliberately empty rather than
          seeded.
        </div>
      ) : (
        <div className="bm-obs-grid">
          {scored.map((r) => (
            <div
              className="card bm-card"
              key={r.module}
              style={{ ["--accent-mod" as string]: MODULE_ACCENT[r.module] ?? "var(--ink-faint)" }}
            >
              <div className="bm-head">
                <span className="bm-ic"><ModuleGlyph module={r.module} size={16} /></span>
                <div className="bm-title">
                  <span className="bm-name">{MODULE_LABELS[r.module] ?? r.module}</span>
                  <span className="bm-para">{r.scored} verdict{r.scored === 1 ? "" : "s"} scored</span>
                </div>
              </div>
              <Metric label="observed precision" value={r.precision ?? 0} />
              <div className="bm-obs-counts">
                <span><b className="num">{r.true_positive}</b> true positive</span>
                <span><b className="num">{r.false_positive}</b> false positive</span>
                <span><b className="num">{r.benign}</b> benign</span>
                <span><b className="num">{r.duplicate}</b> duplicate</span>
              </div>
            </div>
          ))}
        </div>
      )}
      <p className="bm-obs-note">
        Benign and duplicate verdicts are counted but excluded from precision.
        Neither means the detector was wrong — benign is a real finding that
        needed no action, duplicate is the same real finding twice — so
        counting them as errors would make good triage look like a regression.
      </p>
    </section>
  );
}

export default function BenchmarksPage() {
  const [run, setRun] = useState<BenchmarkRun | null>(null);
  const [observed, setObserved] = useState<ObservedAccuracy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/benchmarks")
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("request failed"))))
      .then((d) => {
        if (cancelled) return;
        setRun(d.run ?? null);
        setObserved(Array.isArray(d.observed) ? d.observed : []);
        setError(null);
      })
      .catch(() => {
        if (!cancelled) setError("could not reach the benchmark ledger");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Group detectors by module, worst-detection first within each so the weakest
  // number is not buried.
  const byModule = useMemo(() => {
    const map: Record<string, BenchmarkDetector[]> = {};
    for (const d of run?.detectors ?? []) (map[d.module] ??= []).push(d);
    for (const m of Object.keys(map)) {
      map[m].sort((a, b) => a.metrics.detection_rate - b.metrics.detection_rate);
    }
    return map;
  }, [run]);

  return (
    <div className="frame">
      <div className="app two-col">
        <Rail />
        <main className="main">
          <div className="topbar">
            <div>
              <h1>Detection benchmarks</h1>
              <div className="crumb">
                {run
                  ? `${run.detectors.length} detectors scored · commit ${run.git_commit ?? "—"} · ${when(run.run_at_ms)}`
                  : "labelled-corpus accuracy per detector — detection rate, precision, recall, F1"}
              </div>
            </div>
            <div className="topbar-right">
              <OperatorBadge />
              <ThemeToggle />
            </div>
          </div>

          <div className="content-scroll">
            {error ? (
              <div className="empty">
                <div className="empty-ic"><IconGauge size={30} /></div>
                {error}
              </div>
            ) : loading ? (
              <div className="empty">Loading benchmark results…</div>
            ) : !run ? (
              <div className="empty">
                <div className="empty-ic"><IconGauge size={30} /></div>
                No benchmark run recorded yet — run <code>scripts/run_benchmarks.sh</code>.
              </div>
            ) : (
              KNOWN_MODULES.filter((m) => byModule[m]?.length).map((m) => (
                <section className="bm-section" key={m}>
                  <div className="bm-section-head" style={{ ["--accent-mod" as string]: MODULE_ACCENT[m] }}>
                    <span className="bm-sec-ic"><ModuleGlyph module={m} size={16} /></span>
                    <span className="bm-sec-name">{MODULE_LABELS[m]}</span>
                    <span className="bm-sec-layer">{MODULE_LAYER[m]}</span>
                  </div>
                  <div className="bm-grid">
                    {byModule[m].map((d) => (
                      <Scorecard key={d.detector} d={d} />
                    ))}
                  </div>
                </section>
              ))
            )}
            {!error && !loading ? <ObservedPanel rows={observed} /> : null}
          </div>
        </main>
      </div>
    </div>
  );
}
