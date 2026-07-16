"use client";

import type { MonolithEvent } from "@/lib/types";
import { KNOWN_MODULES, MODULE_ACCENT, MODULE_LABELS, MODULE_LAYER } from "@/lib/types";
import { Logo, ModuleGlyph, IconActivity, IconGrid, IconLedger, IconGear } from "./Icons";

/** The narrow icon rail. Only the overview is wired up — the ledger and
 *  settings destinations do not exist yet, so they are not presented as if
 *  they do. */
export function Rail() {
  return (
    <nav className="rail" aria-label="Sections">
      <span className="rail-logo"><Logo size={30} /></span>
      <button className="rail-btn on" aria-label="Threat overview" aria-current="page" title="Threat overview">
        <IconGrid />
      </button>
      <button className="rail-btn" aria-label="Event ledger (coming soon)" title="Event ledger — not built yet" disabled>
        <IconLedger />
      </button>
      <div className="rail-foot">
        <button className="rail-btn" aria-label="Settings (coming soon)" title="Settings — not built yet" disabled>
          <IconGear />
        </button>
      </div>
    </nav>
  );
}

export default function Sidebar({
  byModule,
  filter,
  onFilter,
}: {
  byModule: Record<string, MonolithEvent[]>;
  filter: string | null;
  onFilter: (m: string | null) => void;
}) {
  const total = Object.values(byModule).reduce((a, b) => a + b.length, 0);

  return (
    <aside className="sidebar">
      <div className="brand">
        <div>
          <div className="brand-name">Black Monolith</div>
          <div className="brand-sub">Sleepers Research</div>
        </div>
      </div>

      <div className="nav-label">Overview</div>
      <button
        className={`nav-item${filter === null ? " active" : ""}`}
        onClick={() => onFilter(null)}
      >
        <span className="nav-ic"><IconActivity size={18} /></span>
        All detections
        <span className="nav-count num">{total}</span>
      </button>

      <div className="nav-label">Defense layers</div>
      {KNOWN_MODULES.map((m) => (
        <button
          key={m}
          className={`nav-item${filter === m ? " active" : ""}`}
          style={{ ["--accent-mod" as string]: MODULE_ACCENT[m] }}
          onClick={() => onFilter(filter === m ? null : m)}
          title={MODULE_LAYER[m]}
        >
          <span className="nav-ic"><ModuleGlyph module={m} size={18} /></span>
          {MODULE_LABELS[m]}
          <span className="nav-count num">{(byModule[m] ?? []).length}</span>
        </button>
      ))}

      <div className="sidebar-foot">
        Tool · Memory · Reasoning
        <br />
        defense-in-depth for AI agents
      </div>
    </aside>
  );
}
