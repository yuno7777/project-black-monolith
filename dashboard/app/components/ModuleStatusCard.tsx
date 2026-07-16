import type { MonolithEvent } from "@/lib/types";
import { MODULE_ACCENT, MODULE_LABELS, MODULE_LAYER } from "@/lib/types";
import { ModuleGlyph } from "./Icons";

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
  const live =
    count > 0 && last
      ? Date.now() - (last.received_ms ?? last.timestamp_ms) < 120_000
      : false;

  return (
    <div className="mod-row" style={{ ["--accent-mod" as string]: MODULE_ACCENT[module] }}>
      <span className="mod-ic"><ModuleGlyph module={module} size={19} /></span>
      <div className="mod-main">
        <div className="mod-name">
          <span className={`mini-dot${live ? " live" : ""}`} />
          {MODULE_LABELS[module] ?? module}
        </div>
        <div className="mod-layer">{MODULE_LAYER[module] ?? "—"}</div>
      </div>
      <div className="mod-metric">
        <div className="mm-v num">{count}</div>
        <div className="mm-k">{critical} critical</div>
      </div>
    </div>
  );
}
