// Custom SVG icon set for Project Black Monolith — no icon fonts, no emojis.
// Every glyph is hand-drawn, inherits `currentColor`, and shares a 24px grid
// (the logo uses 32px). Stroke-based, rounded joints, minimal.

type IconProps = { size?: number; className?: string };

const base = (size: number): React.SVGProps<SVGSVGElement> => ({
  width: size,
  height: size,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.7,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
});

// Brand mark: the "black monolith" — a tall obelisk split into three layers
// (tool / memory / reasoning), washed with the tri-module gradient.
export function Logo({ size = 30 }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden>
      <defs>
        <linearGradient id="ml-grad" x1="6" y1="2" x2="26" y2="30" gradientUnits="userSpaceOnUse">
          <stop stopColor="#5b9dff" />
          <stop offset="0.5" stopColor="#22c3a6" />
          <stop offset="1" stopColor="#b088ff" />
        </linearGradient>
      </defs>
      <rect x="9.5" y="2.5" width="13" height="27" rx="3.2" fill="url(#ml-grad)" opacity="0.14" />
      <rect x="9.5" y="2.5" width="13" height="27" rx="3.2" stroke="url(#ml-grad)" strokeWidth="1.7" />
      <line x1="9.5" y1="11.5" x2="22.5" y2="11.5" stroke="url(#ml-grad)" strokeWidth="1.3" opacity="0.75" />
      <line x1="9.5" y1="20.5" x2="22.5" y2="20.5" stroke="url(#ml-grad)" strokeWidth="1.3" opacity="0.75" />
    </svg>
  );
}

// Tool layer (MCP-Shield): a shield guarding a tool node + connector.
export function IconTool({ size = 20, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <path d="M12 3l7 2.4v4.9c0 4.4-3 7.7-7 8.9-4-1.2-7-4.5-7-8.9V5.4L12 3z" />
      <circle cx="12" cy="10.4" r="1.9" />
      <path d="M12 12.3v3.1" />
    </svg>
  );
}

// Memory layer (VectorAnchor): stacked corpus layers.
export function IconMemory({ size = 20, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <path d="M12 3.5l8 4-8 4-8-4 8-4z" />
      <path d="M4 11.5l8 4 8-4" />
      <path d="M4 15.5l8 4 8-4" />
    </svg>
  );
}

// Reasoning layer (TraceAudit): a small reasoning graph of connected nodes.
export function IconReason({ size = 20, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <path d="M7 8.5l4.4 3M12.8 12.2l4-4.4M11 14.5l-3 3.2M13.4 13.8l3.2 2.7" opacity="0.85" />
      <circle cx="6" cy="7" r="1.9" />
      <circle cx="18" cy="6.5" r="1.9" />
      <circle cx="12" cy="12" r="2.1" />
      <circle cx="7" cy="18.5" r="1.7" />
      <circle cx="18" cy="17" r="1.7" />
    </svg>
  );
}

// KPI: attacks intercepted — shield with a check.
export function IconIntercept({ size = 18, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <path d="M12 3l7 2.4v4.9c0 4.4-3 7.7-7 8.9-4-1.2-7-4.5-7-8.9V5.4L12 3z" />
      <path d="M9 11.6l2.1 2.1L15 9.8" />
    </svg>
  );
}

// KPI: total events — activity pulse.
export function IconActivity({ size = 18, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <path d="M3 12h3.5l2-6 3.5 12 2.4-8 1.6 2H21" />
    </svg>
  );
}

// KPI: critical — alert (exclamation drawn as shapes, never as a glyph char).
export function IconAlert({ size = 18, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <path d="M12 4.2l8 13.8H4L12 4.2z" />
      <path d="M12 10v3.4" />
      <circle cx="12" cy="16.2" r="0.5" fill="currentColor" stroke="none" />
    </svg>
  );
}

// KPI: latency — bolt.
export function IconBolt({ size = 18, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <path d="M13 3L5 13h5l-1 8 9-11h-5l1.5-7z" />
    </svg>
  );
}

// Small severity glyphs for feed rows.
export function SevIcon({ severity, size = 13 }: { severity: string; size?: number }) {
  if (severity === "critical") {
    return (
      <svg {...base(size)} strokeWidth={1.9} aria-hidden>
        <path d="M12 3l9 15.5H3L12 3z" />
        <path d="M12 9.5v3.6" />
        <circle cx="12" cy="15.8" r="0.6" fill="currentColor" stroke="none" />
      </svg>
    );
  }
  if (severity === "warning") {
    return (
      <svg {...base(size)} strokeWidth={1.9} aria-hidden>
        <circle cx="12" cy="12" r="8.5" />
        <path d="M12 8v4.5" />
        <circle cx="12" cy="15.6" r="0.6" fill="currentColor" stroke="none" />
      </svg>
    );
  }
  return (
    <svg {...base(size)} strokeWidth={1.9} aria-hidden>
      <circle cx="12" cy="12" r="8.5" />
      <circle cx="12" cy="12" r="2.4" fill="currentColor" stroke="none" />
    </svg>
  );
}

export function IconChevron({ size = 16, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <path d="M9 6l6 6-6 6" />
    </svg>
  );
}

// Theme toggle: a sun whose rays are drawn as discrete strokes.
export function IconSun({ size = 17, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <circle cx="12" cy="12" r="4.1" />
      <path d="M12 2.6v2.3M12 19.1v2.3M4.2 12H1.9M22.1 12h-2.3M6.5 6.5L4.9 4.9M19.1 19.1l-1.6-1.6M17.5 6.5l1.6-1.6M4.9 19.1l1.6-1.6" />
    </svg>
  );
}

// Theme toggle: crescent moon with a couple of stars.
export function IconMoon({ size = 17, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <path d="M20 14.3A8.3 8.3 0 019.5 3.9a8.6 8.6 0 106.9 12.6c1.4 0 2.6-.8 3.6-2.2z" />
      <path d="M17.5 3.2v2.4M16.3 4.4h2.4" opacity="0.75" />
    </svg>
  );
}

export function IconSearch({ size = 15, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <circle cx="10.8" cy="10.8" r="6.3" />
      <path d="M15.5 15.5L20.5 20.5" />
    </svg>
  );
}

// Rail: the overview grid.
export function IconGrid({ size = 18, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <rect x="3.6" y="3.6" width="7" height="7" rx="2.1" />
      <rect x="13.4" y="3.6" width="7" height="7" rx="2.1" />
      <rect x="3.6" y="13.4" width="7" height="7" rx="2.1" />
      <rect x="13.4" y="13.4" width="7" height="7" rx="2.1" />
    </svg>
  );
}

// Rail: the ledger / persisted event store.
export function IconLedger({ size = 18, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <ellipse cx="12" cy="6.2" rx="7.2" ry="2.9" />
      <path d="M4.8 6.2v11.6c0 1.6 3.2 2.9 7.2 2.9s7.2-1.3 7.2-2.9V6.2" />
      <path d="M4.8 12c0 1.6 3.2 2.9 7.2 2.9s7.2-1.3 7.2-2.9" />
    </svg>
  );
}

// Rail: settings.
export function IconGear({ size = 18, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <circle cx="12" cy="12" r="3.1" />
      <path d="M19.2 14.6a1.6 1.6 0 00.32 1.77l.06.06a1.94 1.94 0 11-2.75 2.75l-.06-.06a1.6 1.6 0 00-1.77-.32 1.6 1.6 0 00-.97 1.47v.17a1.94 1.94 0 01-3.88 0v-.09a1.6 1.6 0 00-1.05-1.47 1.6 1.6 0 00-1.77.32l-.06.06a1.94 1.94 0 11-2.75-2.75l.06-.06a1.6 1.6 0 00.32-1.77 1.6 1.6 0 00-1.47-.97h-.17a1.94 1.94 0 010-3.88h.09a1.6 1.6 0 001.47-1.05 1.6 1.6 0 00-.32-1.77l-.06-.06a1.94 1.94 0 112.75-2.75l.06.06a1.6 1.6 0 001.77.32h.08a1.6 1.6 0 00.97-1.47v-.17a1.94 1.94 0 013.88 0v.09a1.6 1.6 0 00.97 1.47 1.6 1.6 0 001.77-.32l.06-.06a1.94 1.94 0 112.75 2.75l-.06.06a1.6 1.6 0 00-.32 1.77v.08a1.6 1.6 0 001.47.97h.17a1.94 1.94 0 010 3.88h-.09a1.6 1.6 0 00-1.47.97z" />
    </svg>
  );
}

export function ModuleGlyph({ module, size = 20, className }: { module: string; size?: number; className?: string }) {
  if (module === "mcp-shield") return <IconTool size={size} className={className} />;
  if (module === "vector-anchor") return <IconMemory size={size} className={className} />;
  if (module === "trace-audit") return <IconReason size={size} className={className} />;
  return <IconActivity size={size} className={className} />;
}
