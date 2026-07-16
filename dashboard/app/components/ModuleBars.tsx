"use client";

import {
  BarChart, Bar, Cell, XAxis, YAxis, ResponsiveContainer, Tooltip, LabelList,
} from "recharts";
import type { MonolithEvent } from "@/lib/types";
import { KNOWN_MODULES, MODULE_LABELS, MODULE_LAYER } from "@/lib/types";

// CSS variables rather than literals so the bars follow the active theme.
const COLOR: Record<string, string> = {
  "mcp-shield": "var(--mod-mcp)",
  "vector-anchor": "var(--mod-vector)",
  "trace-audit": "var(--mod-trace)",
};

function Tip({ active, payload }: { active?: boolean; payload?: { payload: { label: string; layer: string; value: number } }[] }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="chart-tip">
      <div><b>{p.label}</b></div>
      <div className="tip-k">{p.layer} · {p.value} events</div>
    </div>
  );
}

export default function ModuleBars({ byModule }: { byModule: Record<string, MonolithEvent[]> }) {
  const data = KNOWN_MODULES.map((m) => {
    const evs = byModule[m] ?? [];
    const last = evs[0];
    const live = evs.length > 0 && last ? Date.now() - (last.received_ms ?? last.timestamp_ms) < 120_000 : false;
    return { key: m, label: MODULE_LABELS[m], layer: MODULE_LAYER[m], value: evs.length, color: COLOR[m], live };
  });
  const max = Math.max(1, ...data.map((d) => d.value));

  const Tick = (props: { x?: number; y?: number; payload?: { value: string } }) => {
    const { x = 0, y = 0, payload } = props;
    const row = data.find((d) => d.label === payload?.value);
    return (
      <g transform={`translate(${x},${y})`}>
        <circle cx={-118} cy={0} r={3.5} fill={row?.live ? "var(--ok)" : "var(--ink-faint)"} />
        <text x={-108} y={0} dy={4} textAnchor="start" style={{ fontSize: 12, fontWeight: 600, fill: "var(--ink)" }}>
          {payload?.value}
        </text>
      </g>
    );
  };

  return (
    <div className="chart-wrap" style={{ padding: "16px 18px 14px" }}>
      <div style={{ height: data.length * 46 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 0, right: 26, bottom: 0, left: 126 }} barCategoryGap={14}>
            <XAxis type="number" hide domain={[0, max]} />
            <YAxis type="category" dataKey="label" tickLine={false} axisLine={false} width={0} tick={Tick as never} />
            <Tooltip content={<Tip />} cursor={{ fill: "color-mix(in srgb, var(--ink) 5%, transparent)" }} />
            <Bar dataKey="value" radius={[6, 6, 6, 6]} barSize={12} isAnimationActive={false}>
              {data.map((d) => (
                <Cell key={d.key} fill={d.color} />
              ))}
              <LabelList dataKey="value" position="right" style={{ fontSize: 12, fontWeight: 700, fill: "var(--ink)" }} />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
