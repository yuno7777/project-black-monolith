"use client";

import { useState } from "react";
import Link from "next/link";
import type { IncidentStatus, MonolithEvent } from "@/lib/types";
import { MODULE_ACCENT, MODULE_LABELS, STATUS_LABELS } from "@/lib/types";
import { ModuleGlyph, SevIcon, IconChevron, IconActivity, IconLedger } from "./Icons";
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

function EventRow({ event, triage }: { event: MonolithEvent; triage?: IncidentStatus }) {
  const [open, setOpen] = useState(false);
  const accent = MODULE_ACCENT[event.module] ?? "var(--ink-faint)";
  return (
    // A div wrapping a button rather than one big button: the expanded panel
    // holds a link through to the queue, and a link nested inside a button is
    // invalid HTML (and unreachable by keyboard).
    <div
      className={`event${event.severity === "critical" ? " critical-flash" : ""}`}
      style={{ ["--accent-mod" as string]: accent }}
    >
      <button className="event-hit" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
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
          {/* Only events someone has acted on are badged. An unbadged row is
              untriaged, which is the common case and needs no decoration. */}
          {triage ? <span className={`status-pill ${triage}`}>{STATUS_LABELS[triage]}</span> : null}
          <span className="event-time">{timeOf(event.timestamp_ms)}</span>
          <span className={`chev${open ? " open" : ""}`}><IconChevron size={15} /></span>
        </div>
        {!open && <div className="event-preview">{previewOf(event)}</div>}
      </button>
      {open && (
        <div className="event-open">
          <EventDetail event={event} />
          {event.event_id ? (
            <Link className="event-link" href={`/investigate?event=${event.event_id}`}>
              <IconLedger size={13} />
              Open in the investigation queue
            </Link>
          ) : null}
        </div>
      )}
    </div>
  );
}

/** The scrolling list only — the surrounding card and its header (title,
 *  severity tabs) are owned by the page, so the header can host controls that
 *  filter this list. */
export default function ThreatFeed({
  events,
  emptyHint,
  triageByEvent,
}: {
  events: MonolithEvent[];
  emptyHint?: string;
  /** event_id -> triage status, for the events anyone has acted on. */
  triageByEvent?: Map<string, IncidentStatus>;
}) {
  return (
    <div className="feed">
      {events.length === 0 ? (
        <div className="empty">
          <div className="empty-ic"><IconActivity size={30} /></div>
          {emptyHint ?? "Waiting for detection events — run a demo fixture to generate traffic."}
        </div>
      ) : (
        events.map((e) => (
          <EventRow
            key={e.seq ?? e.timestamp_ms}
            event={e}
            triage={e.event_id ? triageByEvent?.get(e.event_id) : undefined}
          />
        ))
      )}
    </div>
  );
}
