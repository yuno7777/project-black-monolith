"use client";

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import type { MonolithEvent, Severity } from "@/lib/types";

// CSS variables rather than literals: SVG `fill` resolves var(), so the chart
// re-colours with the theme instead of staying frozen at one palette.
const SEGMENTS = [
  { key: "critical", label: "Critical", color: "var(--sev-critical)" },
  { key: "warning", label: "Warning", color: "var(--sev-warning)" },
  { key: "info", label: "Info", color: "var(--sev-info)" },
] as const;

function Tip({ active, payload }: { active?: boolean; payload?: { name: string; value: number }[] }) {
  if (!active || !payload?.length) return null;
  const p = payload[0];
  return (
    <div className="chart-tip">
      <span className="tip-k">{p.name}: </span>
      <b>{p.value}</b>
    </div>
  );
}

/** Each arc maps 1:1 onto a severity filter, so the chart doubles as the
 *  control for it — clicking a slice filters the feed, clicking it again
 *  clears. `selected` is the page's filter state, not the chart's: the chart
 *  stays a pure readout of it. */
export default function SeverityDonut({
  events,
  selected = "all",
  onSelect,
}: {
  events: MonolithEvent[];
  selected?: Severity | "all";
  onSelect?: (severity: Severity | "all") => void;
}) {
  const counts = {
    critical: events.filter((e) => e.severity === "critical").length,
    warning: events.filter((e) => e.severity === "warning").length,
    info: events.filter((e) => e.severity === "info").length,
  };
  const total = events.length;

  const data = SEGMENTS.map((s) => ({ key: s.key, name: s.label, value: counts[s.key], color: s.color }));
  const hasData = total > 0;
  const chartData = hasData
    ? data.filter((d) => d.value > 0)
    : [{ key: "none", name: "None", value: 1, color: "var(--chip)" }];

  const toggle = (key: string) => {
    if (!onSelect || key === "none") return;
    onSelect(selected === key ? "all" : (key as Severity));
  };

  return (
    <div className="chart-wrap">
      <div className="donut-holder">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius={47}
              outerRadius={68}
              paddingAngle={hasData ? 3 : 0}
              stroke="none"
              startAngle={90}
              endAngle={-270}
              isAnimationActive={false}
            >
              {chartData.map((d) => (
                <Cell
                  key={d.key}
                  fill={d.color}
                  // Dim what is filtered out rather than hiding it, so the
                  // proportions the donut is drawing stay honest.
                  opacity={selected === "all" || selected === d.key ? 1 : 0.28}
                  style={{ cursor: onSelect && hasData ? "pointer" : "default", outline: "none" }}
                  onClick={() => toggle(d.key)}
                />
              ))}
            </Pie>
            {hasData && <Tooltip content={<Tip />} />}
          </PieChart>
        </ResponsiveContainer>
        <div className="donut-center">
          <span className="dc-v num">{selected === "all" ? total : counts[selected]}</span>
          <span className="dc-k">{selected === "all" ? "events" : selected}</span>
        </div>
      </div>
      <div style={{ marginTop: 6 }}>
        {SEGMENTS.map((s) => (
          <button
            className={`legend-row${selected === s.key ? " on" : ""}`}
            key={s.key}
            onClick={() => toggle(s.key)}
            aria-pressed={selected === s.key}
          >
            <span className="lg-dot" style={{ background: s.color }} />
            {s.label}
            <b>{counts[s.key]}</b>
          </button>
        ))}
      </div>
    </div>
  );
}
