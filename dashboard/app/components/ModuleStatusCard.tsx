import type { MonolithEvent } from "@/lib/types";
import { MODULE_LABELS, MODULE_LAYER } from "@/lib/types";

const MODULE_COLOR: Record<string, string> = {
  "mcp-shield": "var(--mod-mcp)",
  "vector-anchor": "var(--mod-vector)",
  "trace-audit": "var(--mod-trace)",
};

export default function ModuleStatusCard({
  module,
  events,
}: {
  module: string;
  events: MonolithEvent[];
}) {
  const count = events.length;
  const critical = events.filter((e) => e.severity === "critical").length;
  const last = events[0];
  const seenRecently =
    last && Date.now() - (last.received_ms ?? last.timestamp_ms) < 60_000;

  return (
    <div
      className="mod-card"
      style={{ ["--accent" as string]: MODULE_COLOR[module] ?? "var(--border-bright)" }}
    >
      <div className="mod-name">
        <span className={`dot${count > 0 || seenRecently ? " live" : ""}`} />
        {MODULE_LABELS[module] ?? module}
      </div>
      <div className="mod-layer">{MODULE_LAYER[module] ?? "—"}</div>
      <div className="mod-stats">
        <span>
          <b>{count}</b> events
        </span>
        <span>
          <b>{critical}</b> critical
        </span>
      </div>
    </div>
  );
}
