"use client";

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import type { MonolithEvent } from "@/lib/types";

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

export default function SeverityDonut({ events }: { events: MonolithEvent[] }) {
  const counts = {
    critical: events.filter((e) => e.severity === "critical").length,
    warning: events.filter((e) => e.severity === "warning").length,
    info: events.filter((e) => e.severity === "info").length,
  };
  const total = events.length;

  const data = SEGMENTS.map((s) => ({ name: s.label, value: counts[s.key], color: s.color }));
  const hasData = total > 0;
  const chartData = hasData ? data.filter((d) => d.value > 0) : [{ name: "None", value: 1, color: "var(--chip)" }];

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
              innerRadius={54}
              outerRadius={78}
              paddingAngle={hasData ? 3 : 0}
              stroke="none"
              startAngle={90}
              endAngle={-270}
              isAnimationActive={false}
            >
              {chartData.map((d, i) => (
                <Cell key={i} fill={d.color} />
              ))}
            </Pie>
            {hasData && <Tooltip content={<Tip />} />}
          </PieChart>
        </ResponsiveContainer>
        <div className="donut-center">
          <span className="dc-v num">{total}</span>
          <span className="dc-k">events</span>
        </div>
      </div>
      <div style={{ marginTop: 6 }}>
        {SEGMENTS.map((s) => (
          <div className="legend-row" key={s.key}>
            <span className="lg-dot" style={{ background: s.color }} />
            {s.label}
            <b>{counts[s.key]}</b>
          </div>
        ))}
      </div>
    </div>
  );
}
