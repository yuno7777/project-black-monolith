"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { MonolithEvent } from "@/lib/types";
import { KNOWN_MODULES, MODULE_ACCENT, MODULE_LABELS, MODULE_LAYER } from "@/lib/types";
import { Logo, ModuleGlyph, IconActivity, IconGrid, IconLedger, IconGauge, IconGear } from "./Icons";

/** The narrow icon rail. Settings does not exist yet, so it is not presented
 *  as if it does. */
export function Rail() {
  const path = usePathname();
  return (
    <nav className="rail" aria-label="Sections">
      <span className="rail-logo"><Logo size={40} /></span>
      <Link
        href="/"
        className={`rail-btn${path === "/" ? " on" : ""}`}
        aria-label="Threat overview"
        aria-current={path === "/" ? "page" : undefined}
        title="Threat overview"
      >
        <IconGrid />
      </Link>
      <Link
        href="/investigate"
        className={`rail-btn${path === "/investigate" ? " on" : ""}`}
        aria-label="Investigation queue"
        aria-current={path === "/investigate" ? "page" : undefined}
        title="Investigation queue"
      >
        <IconLedger />
      </Link>
      <Link
        href="/benchmarks"
        className={`rail-btn${path === "/benchmarks" ? " on" : ""}`}
        aria-label="Detection benchmarks"
        aria-current={path === "/benchmarks" ? "page" : undefined}
        title="Detection benchmarks"
      >
        <IconGauge />
      </Link>
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
        <span className="brand-logo"><Logo size={52} /></span>
        <div className="brand-name">
          <span className="brand-project">Project</span>
          Black Monolith
        </div>
        <div className="brand-sub">Sleepers Research</div>
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
