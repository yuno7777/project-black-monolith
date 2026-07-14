"use client";

import { useState } from "react";
import type { MonolithEvent } from "@/lib/types";
import { MODULE_LABELS } from "@/lib/types";
import EventDetail from "./EventDetail";

const MODULE_COLOR: Record<string, string> = {
  "mcp-shield": "var(--mod-mcp)",
  "vector-anchor": "var(--mod-vector)",
  "trace-audit": "var(--mod-trace)",
};

function previewOf(event: MonolithEvent): string {
  const d = event.details ?? {};
  for (const key of ["tool", "doc_id", "preview", "message", "label", "reason"]) {
    if (typeof d[key] === "string") return d[key] as string;
  }
  const first = Object.entries(d)[0];
  return first ? `${first[0]}: ${JSON.stringify(first[1])}` : "";
}

function timeOf(ms: number): string {
  return new Date(ms).toLocaleTimeString([], {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function EventRow({ event }: { event: MonolithEvent }) {
  const [open, setOpen] = useState(false);
  const color = MODULE_COLOR[event.module] ?? "var(--border-bright)";
  return (
    <div
      className={`event${event.severity === "critical" ? " critical-flash" : ""}`}
      style={{ ["--accent" as string]: color }}
      onClick={() => setOpen((o) => !o)}
    >
      <div className="event-row">
        <span className="tag module" style={{ background: color }}>
          {MODULE_LABELS[event.module] ?? event.module}
        </span>
        <span className={`sev ${event.severity}`}>{event.severity}</span>
        <span className="event-type">{event.event_type}</span>
        <span className="event-time">{timeOf(event.timestamp_ms)}</span>
      </div>
      {!open && <div className="event-preview">{previewOf(event)}</div>}
      {open && <EventDetail event={event} />}
    </div>
  );
}

export default function ThreatFeed({ events }: { events: MonolithEvent[] }) {
  return (
    <div className="panel">
      <div className="panel-title">Live threat feed — newest first</div>
      <div className="feed">
        {events.length === 0 ? (
          <div className="empty">
            Waiting for detection events… run a demo fixture to generate traffic.
          </div>
        ) : (
          events.map((e) => <EventRow key={e.seq ?? e.timestamp_ms} event={e} />)
        )}
      </div>
    </div>
  );
}
