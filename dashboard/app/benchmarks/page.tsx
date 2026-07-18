"use client";

import { useEffect, useMemo, useState } from "react";
import { KNOWN_MODULES, MODULE_ACCENT, MODULE_LABELS, MODULE_LAYER } from "@/lib/types";
import type { BenchmarkDetector, BenchmarkRun } from "@/lib/benchmark-store";
import { Rail } from "../components/Sidebar";
import ThemeToggle from "../components/ThemeToggle";
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

export default function BenchmarksPage() {
  const [run, setRun] = useState<BenchmarkRun | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/benchmarks")
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("request failed"))))
      .then((d) => {
        if (cancelled) return;
        setRun(d.run ?? null);
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
          </div>
        </main>
      </div>
    </div>
  );
}
