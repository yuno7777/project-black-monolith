// The threat-overview page (route "/").
//
// WHAT THIS PAGE IS
// -----------------
// The main dashboard screen: a live threat feed plus KPIs, severity donut,
// and per-module bars. It is a CLIENT component ("use client") because it
// keeps a live EventSource open and updates state as events arrive.
//
// THE DATA FLOW (user opens the dashboard)
// ----------------------------------------
//   Browser loads "/"
//    -> EventSource("/api/events") opens            [app/api/events/route.ts]
//    -> server authenticates the session cookie (viewer+), starts the Postgres
//       listener if needed, replays the last 500 ledger events, then streams
//       new ones live
//    -> onmessage parses each event, dedupes by event_id (a `seen` Set), and
//       inserts it into the events array sorted by received time (capped at
//       500 rows so the browser doesn't grow unbounded)
//    -> all stats (KPIs, donut, bars, feed) are derived from that one array
//       with useMemo
//
// WHY DEDUPE + SORT
// -----------------
// The server sends the event_id in the SSE `id:` field and the client dedupes
// on it anyway: subscribe-before-replay means a just-committed live event can
// arrive before older replay frames, and after dedupe the array is re-sorted
// by received time so stale evidence can never sit above the latest event.
//
// WHY TRIAGE IS POLLED, NOT STREAMED
// ----------------------------------
// Triage state lives in the ledger (incident_triage), not on the event
// stream. The page polls GET /api/incidents?status=triaged&limit=500 every
// 15s — only the SMALL triaged set plus the counts, so the timer never ships
// the whole ledger just to render a few badges.

"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import type { Incident, IncidentStatus, MonolithEvent, Severity } from "@/lib/types";
import { KNOWN_MODULES, MODULE_LABELS } from "@/lib/types";
import Sidebar, { Rail } from "./components/Sidebar";
import ThreatFeed from "./components/ThreatFeed";
import ModuleBars from "./components/ModuleBars";
import SeverityDonut from "./components/SeverityDonut";
import ThemeToggle from "./components/ThemeToggle";
import OperatorBadge from "./components/OperatorBadge";
import { IconIntercept, IconActivity, IconAlert, IconBolt, IconSearch, IconLedger } from "./components/Icons";

// End-to-end latency, as reported by the detectors: this averages
// `details.detection_latency_ms`, which is wall-clock time INSIDE the detector
// path and so includes the wrapped operation (the model streaming, the vector
// query) — not the detector's own overhead. The isolated detector cost
// (microseconds) is measured separately on the Benchmarks page; labelling this
// "detection latency" outright would wrongly imply the defence is the slow part.
function avgEndToEndLatency(events: MonolithEvent[]): number | null {
  const s: number[] = [];
  for (const e of events) {
    const d = e.details ?? {};
    const v = d["detection_latency_ms"] ?? d["latency_ms"];
    if (typeof v === "number") s.push(v);
  }
  return s.length ? s.reduce((a, b) => a + b, 0) / s.length : null;
}

/** Free-text match across the fields an analyst would actually search by. */
function matches(event: MonolithEvent, q: string): boolean {
  if (!q) return true;
  const needle = q.toLowerCase();
  if (event.event_type?.toLowerCase().includes(needle)) return true;
  if (event.module?.toLowerCase().includes(needle)) return true;
  if (MODULE_LABELS[event.module]?.toLowerCase().includes(needle)) return true;
  if (event.severity?.toLowerCase().includes(needle)) return true;
  return JSON.stringify(event.details ?? {}).toLowerCase().includes(needle);
}

const SEVERITY_TABS: { key: Severity | "all"; label: string }[] = [
  { key: "all", label: "All" },
  { key: "critical", label: "Critical" },
  { key: "warning", label: "Warning" },
  { key: "info", label: "Info" },
];

export default function Page() {
  // ---- local state ------------------------------------------------------
  const [events, setEvents] = useState<MonolithEvent[]>([]); // the live feed buffer
  const [connected, setConnected] = useState(false);         // EventSource open?
  const [filter, setFilter] = useState<string | null>(null); // module filter
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [query, setQuery] = useState("");                    // search box
  const [now, setNow] = useState<string>("");                // clock display
  const [openIncidents, setOpenIncidents] = useState<number | null>(null);
  const [triageByEvent, setTriageByEvent] = useState<Map<string, IncidentStatus>>(new Map());
  const seen = useRef<Set<string>>(new Set()); // dedupe across re-renders

  // A 1-second clock for the topbar.
  useEffect(() => {
    const tick = () => setNow(new Date().toLocaleTimeString([], { hour12: false }));
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);

  // ---- the live feed -----------------------------------------------------
  // Opens the SSE stream. The server (app/api/events/route.ts +
  // sse-event-stream.ts) replays history then streams live. Every incoming
  // event is deduped by event_id and inserted sorted, capped at 500.
  useEffect(() => {
    const es = new EventSource("/api/events");
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.onmessage = (msg) => {
      try {
        const evt = JSON.parse(msg.data) as MonolithEvent;
        if (!evt.event_id || seen.current.has(evt.event_id)) return;
        seen.current.add(evt.event_id);
        // Subscribe-before-replay prevents gaps, but a just-committed live
        // event can arrive before older replay frames. Sort by collector time
        // after de-duplication so that safe ordering cannot put stale evidence
        // above the latest event.
        setEvents((prev) =>
          [evt, ...prev]
            .sort(
              (a, b) =>
                (b.received_ms ?? b.timestamp_ms) - (a.received_ms ?? a.timestamp_ms),
            )
            .slice(0, 500),
        );
      } catch {
        /* ignore malformed frame */
      }
    };
    return () => es.close();
  }, []);

  // Triage state lives in the ledger, not on the event stream, so the overview
  // polls for it. Only the triaged set is fetched (small, and the only rows
  // that get badged) plus the counts — "every event with its status" would mean
  // shipping the whole ledger on a timer just to render a handful of pills.
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const res = await fetch("/api/incidents?status=triaged&limit=500");
        if (!res.ok) return;
        const data = await res.json();
        if (cancelled) return;
        const map = new Map<string, IncidentStatus>();
        for (const i of (data.incidents ?? []) as Incident[]) {
          if (i.triage?.status) map.set(i.event_id, i.triage.status);
        }
        setTriageByEvent(map);
        setOpenIncidents(data.counts?.open ?? null);
      } catch {
        /* the feed is the primary surface; leave the badges off if this fails */
      }
    };
    load();
    const t = setInterval(load, 15_000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  // ---- derived stats (all from the single events array) ------------------
  const byModule = useMemo(() => {
    const map: Record<string, MonolithEvent[]> = {};
    for (const m of KNOWN_MODULES) map[m] = [];
    for (const e of events) (map[e.module] ??= []).push(e);
    return map;
  }, [events]);

  const shown = useMemo(
    () =>
      events
        .filter((e) => (filter ? e.module === filter : true))
        .filter((e) => (severity === "all" ? true : e.severity === severity))
        .filter((e) => matches(e, query)),
    [events, filter, severity, query],
  );

  const severityCounts = useMemo(
    () => ({
      all: events.length,
      critical: events.filter((e) => e.severity === "critical").length,
      warning: events.filter((e) => e.severity === "warning").length,
      info: events.filter((e) => e.severity === "info").length,
    }),
    [events],
  );

  const intercepted = severityCounts.critical + severityCounts.warning;
  const latency = avgEndToEndLatency(events);

  // The four KPI cards. Only cards that lead somewhere are links (the hover
  // affordance must never promise a destination that doesn't exist).
  const kpis = [
    {
      k: "Attacks intercepted",
      v: intercepted,
      sub: "warning + critical",
      icon: <IconIntercept />,
      accent: "var(--mod-vector)",
      chip: events.length ? `${Math.round((intercepted / events.length) * 100)}% of feed` : null,
    },
    // Replaces the old "Total events" card: that number is already the donut's
    // centre and the sidebar's count, whereas how much is still unhandled was
    // nowhere on this page.
    {
      k: "Open incidents",
      v: openIncidents ?? "—",
      sub: openIncidents === null ? "ledger unavailable" : "new + acknowledged",
      icon: <IconLedger />,
      accent: "var(--mod-mcp)",
      chip: null,
      href: "/investigate",
    },
    {
      k: "Critical",
      v: severityCounts.critical,
      sub: "stream-terminating",
      icon: <IconAlert />,
      accent: "var(--sev-critical)",
      chip: null,
    },
    {
      k: "Avg end-to-end latency",
      v: latency === null ? "—" : latency.toFixed(1),
      // Named honestly: this includes the wrapped operation, not just the
      // detector. The isolated detector overhead is on the Benchmarks page.
      sub: latency === null ? "no timing data" : "ms incl. wrapped op",
      icon: <IconBolt />,
      accent: "var(--mod-trace)",
      chip: null,
      href: "/benchmarks",
    },
  ];

  return (
    <div className="frame">
      <div className="app">
        <Rail />
        <Sidebar byModule={byModule} filter={filter} onFilter={setFilter} />

        <main className="main">
          <div className="topbar">
            <div>
              <h1>Threat overview</h1>
              <div className="crumb">Unified agent-security detection · tool · memory · reasoning</div>
            </div>

            <div className="search">
              <IconSearch />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search events, modules, details…"
                aria-label="Search events"
              />
            </div>

            <div className="topbar-right">
              <span className="clock num">{now}</span>
              <span className="conn">
                <span className={`dot${connected ? " live" : ""}`} />
                {connected ? "Live" : "Disconnected"}
              </span>
              <OperatorBadge />
              <ThemeToggle />
            </div>
          </div>

          <div className="kpis">
            {kpis.map((c) => {
              const body = (
                <>
                  <div className="kpi-top">
                    <span className="kpi-ic">{c.icon}</span>
                    {c.chip ? <span className="chip num">{c.chip}</span> : null}
                  </div>
                  <div className="kpi-k">{c.k}</div>
                  <div className="kpi-v num">{c.v}</div>
                  <div className="kpi-sub">{c.sub}</div>
                </>
              );
              const style = { ["--accent-mod" as string]: c.accent };
              // Only the card that leads somewhere is a link, so the hover
              // affordance never promises a destination that does not exist.
              return c.href ? (
                <Link className="kpi kpi-link" key={c.k} href={c.href} style={style}>
                  {body}
                </Link>
              ) : (
                <div className="kpi" key={c.k} style={style}>
                  {body}
                </div>
              );
            })}
          </div>

          <div className="content">
            <div className="card feed-card">
              <div className="card-head">
                <div>
                  <span className="card-title">Live threat feed</span>
                  <div className="card-meta" style={{ marginTop: 4 }}>
                    {filter ? `${MODULE_LABELS[filter]} · ` : "newest first · "}
                    {shown.length} event{shown.length === 1 ? "" : "s"}
                  </div>
                </div>
                <div className="seg" role="tablist" aria-label="Filter by severity">
                  {SEVERITY_TABS.map((t) => (
                    <button
                      key={t.key}
                      role="tab"
                      aria-selected={severity === t.key}
                      className={severity === t.key ? "on" : ""}
                      onClick={() => setSeverity(t.key)}
                    >
                      {t.label}
                      <span className="seg-n num">{severityCounts[t.key]}</span>
                    </button>
                  ))}
                </div>
              </div>
              <ThreatFeed
                events={shown}
                triageByEvent={triageByEvent}
                emptyHint={
                  events.length
                    ? "No events match these filters."
                    : "Waiting for detection events — run a demo fixture to generate traffic."
                }
              />
            </div>

            <div className="stack">
              <div className="card">
                <div className="card-head">
                  <span className="card-title">Detections by severity</span>
                  <span className="card-meta">{severity === "all" ? "click to filter" : "filtered"}</span>
                </div>
                <SeverityDonut events={events} selected={severity} onSelect={setSeverity} />
              </div>

              <div className="card">
                <div className="card-head">
                  <span className="card-title">Events by module</span>
                  <span className="card-meta">{filter ? "filtered" : "3 layers"}</span>
                </div>
                <ModuleBars byModule={byModule} selected={filter} onSelect={setFilter} />
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
