"use client";

import { useState } from "react";
import type { MonolithEvent } from "@/lib/types";
import { MODULE_ACCENT, MODULE_LABELS } from "@/lib/types";
import { ModuleGlyph, SevIcon, IconChevron, IconActivity } from "./Icons";
import EventDetail from "./EventDetail";

function previewOf(event: MonolithEvent): string {
  const d =
    event.details && typeof event.details === "object" ? event.details : {};
  for (const key of ["tool", "doc_id", "preview", "message", "label", "reason"]) {
    if (typeof d[key] === "string") return d[key] as string;
  }
  const first = Object.entries(d)[0];
  return first ? `${first[0]}: ${JSON.stringify(first[1])}` : "(no details)";
}

function timeOf(ms: unknown): string {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return "--:--:--";
  return new Date(ms).toLocaleTimeString([], {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function EventRow({ event }: { event: MonolithEvent }) {
  const [open, setOpen] = useState(false);
  const accent = MODULE_ACCENT[event.module] ?? "var(--ink-faint)";
  return (
    <button
      className={`event${event.severity === "critical" ? " critical-flash" : ""}`}
      style={{ ["--accent-mod" as string]: accent }}
      onClick={() => setOpen((o) => !o)}
    >
      <div className="event-row">
        <span className="badge">
          <ModuleGlyph module={event.module} size={13} />
          {MODULE_LABELS[event.module] ?? event.module}
        </span>
        <span className={`sev ${event.severity}`}>
          <SevIcon severity={event.severity} />
          {event.severity}
        </span>
        <span className="event-type">{event.event_type || "unknown"}</span>
        <span className="event-time">{timeOf(event.timestamp_ms)}</span>
        <span className={`chev${open ? " open" : ""}`}><IconChevron size={15} /></span>
      </div>
      {!open && <div className="event-preview">{previewOf(event)}</div>}
      {open && <EventDetail event={event} />}
    </button>
  );
}

/** The scrolling list only — the surrounding card and its header (title,
 *  severity tabs) are owned by the page, so the header can host controls that
 *  filter this list. */
export default function ThreatFeed({
  events,
  emptyHint,
}: {
  events: MonolithEvent[];
  emptyHint?: string;
}) {
  return (
    <div className="feed">
      {events.length === 0 ? (
        <div className="empty">
          <div className="empty-ic"><IconActivity size={30} /></div>
          {emptyHint ?? "Waiting for detection events — run a demo fixture to generate traffic."}
        </div>
      ) : (
        events.map((e) => <EventRow key={e.seq ?? e.timestamp_ms} event={e} />)
      )}
    </div>
  );
}
