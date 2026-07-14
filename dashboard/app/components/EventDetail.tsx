import type { MonolithEvent } from "@/lib/types";

// Expandable detail view for one event: full details payload + timestamps.
export default function EventDetail({ event }: { event: MonolithEvent }) {
  const entries = Object.entries(event.details ?? {});
  return (
    <div className="event-detail">
      <div className="kv">
        <span className="kk">module</span>
        <span className="vv">{event.module}</span>
        <span className="kk">event_type</span>
        <span className="vv">{event.event_type}</span>
        <span className="kk">severity</span>
        <span className="vv">{event.severity}</span>
        <span className="kk">timestamp_ms</span>
        <span className="vv">
          {event.timestamp_ms} ({new Date(event.timestamp_ms).toISOString()})
        </span>
        {entries.map(([k, v]) => (
          <span key={k} style={{ display: "contents" }}>
            <span className="kk">details.{k}</span>
            <span className="vv">
              {typeof v === "object" ? JSON.stringify(v) : String(v)}
            </span>
          </span>
        ))}
      </div>
    </div>
  );
}
