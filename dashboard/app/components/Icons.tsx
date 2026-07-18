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

// Brand mark: the PBM monogram. Two theme-specific artworks — a light glyph for
// the dark UI, a dark glyph for the light UI — keyed to transparent PNGs so they
// blend seamlessly on either canvas (no logo-square seam). Both are rendered and
// CSS shows the one matching the active theme, so there is no swap flash. `size`
// is the rendered HEIGHT in px; width follows the artwork's aspect ratio.
export function Logo({ size = 30 }: { size?: number }) {
  return (
    <span
      className="logo"
      style={{ ["--logo-h" as string]: `${size}px` }}
      role="img"
      aria-label="Project Black Monolith"
    >
      <img className="logo-img logo-dark" src="/logo-dark.png" alt="" aria-hidden />
      <img className="logo-img logo-light" src="/logo-light.png" alt="" aria-hidden />
    </span>
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

// Rail: benchmarks — a gauge/meter reading a measured value.
export function IconGauge({ size = 18, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <path d="M4 15.5a8 8 0 0116 0" />
      <path d="M4 15.5h1.6M18.4 15.5H20M12 5.6V7" />
      <path d="M12 15.5l4-3" />
      <circle cx="12" cy="15.5" r="1.3" fill="currentColor" stroke="none" />
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

// Triage: acknowledged — seen and taken, not yet closed.
export function IconEye({ size = 15, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <path d="M2.2 12S5.8 5.4 12 5.4 21.8 12 21.8 12 18.2 18.6 12 18.6 2.2 12 2.2 12z" />
      <circle cx="12" cy="12" r="2.9" />
    </svg>
  );
}

// Triage: resolved — closed out with a verdict.
export function IconCheck({ size = 15, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <path d="M4.6 12.4l4.8 4.8L19.4 7.2" />
    </svg>
  );
}

// Triage: the analyst an incident is assigned to.
export function IconUser({ size = 15, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <circle cx="12" cy="7.8" r="3.9" />
      <path d="M4.8 20.2a7.2 7.2 0 0114.4 0" />
    </svg>
  );
}

// The append-only audit trail.
export function IconHistory({ size = 15, className }: IconProps) {
  return (
    <svg {...base(size)} className={className} aria-hidden>
      <path d="M3.6 12a8.4 8.4 0 108.4-8.4A8.4 8.4 0 005.4 6.6" />
      <path d="M3.4 3.4v3.6h3.6" />
      <path d="M12 7.6V12l3 1.8" />
    </svg>
  );
}

export function ModuleGlyph({ module, size = 20, className }: { module: string; size?: number; className?: string }) {
  if (module === "mcp-shield") return <IconTool size={size} className={className} />;
  if (module === "vector-anchor") return <IconMemory size={size} className={className} />;
  if (module === "trace-audit") return <IconReason size={size} className={className} />;
  return <IconActivity size={size} className={className} />;
}
