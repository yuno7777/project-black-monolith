import type { MonolithEvent } from "@/lib/types";

// Render a single details value without ever showing a literal "undefined".
function renderValue(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

// Format a timestamp defensively — a malformed (non-numeric) timestamp must
// not throw inside render (new Date(NaN).toISOString() would).
function formatTs(ms: unknown): string {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return "unknown";
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? String(ms) : `${ms} · ${d.toISOString()}`;
}

// Expandable detail view for one event. Tolerant of malformed/incomplete
// events — missing or empty details render a placeholder, never "undefined".
export default function EventDetail({ event }: { event: MonolithEvent }) {
  const details =
    event.details && typeof event.details === "object" ? event.details : {};
  const entries = Object.entries(details);
  return (
    <div className="event-detail" onClick={(e) => e.stopPropagation()}>
      <div className="kv">
        <span className="kk">module</span>
        <span className="vv">{event.module || "unknown"}</span>
        <span className="kk">event_type</span>
        <span className="vv">{event.event_type || "unknown"}</span>
        <span className="kk">severity</span>
        <span className="vv">{event.severity || "info"}</span>
        <span className="kk">timestamp</span>
        <span className="vv">{formatTs(event.timestamp_ms)}</span>
        {entries.length === 0 ? (
          <>
            <span className="kk">details</span>
            <span className="vv" style={{ opacity: 0.6 }}>(no details)</span>
          </>
        ) : (
          entries.map(([k, v]) => (
            <span key={k} style={{ display: "contents" }}>
              <span className="kk">{k}</span>
              <span className="vv">{renderValue(v)}</span>
            </span>
          ))
        )}
      </div>
    </div>
  );
}
