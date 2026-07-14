import type { MonolithEvent } from "@/lib/types";
import { KNOWN_MODULES, MODULE_LABELS } from "@/lib/types";

const SEV_COLOR: Record<string, string> = {
  info: "var(--sev-info)",
  warning: "var(--sev-warning)",
  critical: "var(--sev-critical)",
};

// "Attacks intercepted" = warning + critical detections (info events are
// lifecycle/among-normal activity, not interceptions).
function isInterception(e: MonolithEvent): boolean {
  return e.severity === "critical" || e.severity === "warning";
}

function avgLatency(events: MonolithEvent[]): number | null {
  const samples: number[] = [];
  for (const e of events) {
    const d = e.details ?? {};
    const v = d["detection_latency_ms"] ?? d["latency_ms"];
    if (typeof v === "number") samples.push(v);
  }
  if (samples.length === 0) return null;
  return samples.reduce((a, b) => a + b, 0) / samples.length;
}

export default function SessionSummary({ events }: { events: MonolithEvent[] }) {
  const total = events.length;
  const intercepted = events.filter(isInterception).length;
  const bySeverity = {
    critical: events.filter((e) => e.severity === "critical").length,
    warning: events.filter((e) => e.severity === "warning").length,
    info: events.filter((e) => e.severity === "info").length,
  };
  const latency = avgLatency(events);

  const total1 = Math.max(total, 1);

  return (
    <div className="panel">
      <div className="panel-title">Session summary</div>
      <div className="summary-grid">
        <div className="stat">
          <div className="k">Attacks intercepted</div>
          <div className="v">{intercepted}</div>
        </div>
        <div className="stat">
          <div className="k">Total events</div>
          <div className="v">{total}</div>
        </div>
        <div className="stat">
          <div className="k">Avg detection latency</div>
          <div className="v">{latency === null ? "—" : `${latency.toFixed(1)} ms`}</div>
        </div>
        <div className="stat">
          <div className="k">Critical</div>
          <div className="v" style={{ color: "var(--sev-critical)" }}>
            {bySeverity.critical}
          </div>
        </div>
      </div>

      {/* severity distribution bar */}
      <div className="bar">
        {(["critical", "warning", "info"] as const).map((s) =>
          bySeverity[s] > 0 ? (
            <span
              key={s}
              style={{
                width: `${(bySeverity[s] / total1) * 100}%`,
                background: SEV_COLOR[s],
              }}
            />
          ) : null,
        )}
      </div>

      {/* per-layer breakdown */}
      <div className="legend">
        {KNOWN_MODULES.map((m) => {
          const c = events.filter((e) => e.module === m).length;
          return (
            <span className="item" key={m}>
              <span
                className="swatch"
                style={{ background: `var(--mod-${m === "mcp-shield" ? "mcp" : m === "vector-anchor" ? "vector" : "trace"})` }}
              />
              {MODULE_LABELS[m]}: <b style={{ color: "var(--text)" }}>{c}</b>
            </span>
          );
        })}
      </div>
    </div>
  );
}
