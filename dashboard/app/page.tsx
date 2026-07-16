"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { MonolithEvent, Severity } from "@/lib/types";
import { KNOWN_MODULES, MODULE_LABELS } from "@/lib/types";
import Sidebar, { Rail } from "./components/Sidebar";
import ThreatFeed from "./components/ThreatFeed";
import ModuleBars from "./components/ModuleBars";
import SeverityDonut from "./components/SeverityDonut";
import ThemeToggle from "./components/ThemeToggle";
import { IconIntercept, IconActivity, IconAlert, IconBolt, IconSearch } from "./components/Icons";

function avgLatency(events: MonolithEvent[]): number | null {
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
  const [events, setEvents] = useState<MonolithEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [filter, setFilter] = useState<string | null>(null);
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [query, setQuery] = useState("");
  const [now, setNow] = useState<string>("");
  const seen = useRef<Set<number>>(new Set());

  useEffect(() => {
    const tick = () => setNow(new Date().toLocaleTimeString([], { hour12: false }));
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const es = new EventSource("/api/events");
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.onmessage = (msg) => {
      try {
        const evt = JSON.parse(msg.data) as MonolithEvent;
        if (evt.seq !== undefined) {
          if (seen.current.has(evt.seq)) return;
          seen.current.add(evt.seq);
        }
        setEvents((prev) => [evt, ...prev].slice(0, 500));
      } catch {
        /* ignore malformed frame */
      }
    };
    return () => es.close();
  }, []);

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
  const latency = avgLatency(events);
  const activeModules = KNOWN_MODULES.filter((m) => byModule[m].length).length;

  const kpis = [
    {
      k: "Attacks intercepted",
      v: intercepted,
      sub: "warning + critical",
      icon: <IconIntercept />,
      accent: "var(--mod-vector)",
      chip: events.length ? `${Math.round((intercepted / events.length) * 100)}% of feed` : null,
    },
    {
      k: "Total events",
      v: events.length,
      sub: `${activeModules} of 3 modules active`,
      icon: <IconActivity />,
      accent: "var(--mod-mcp)",
      chip: null,
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
      k: "Avg detection latency",
      v: latency === null ? "—" : latency.toFixed(1),
      sub: latency === null ? "no timing data" : "milliseconds",
      icon: <IconBolt />,
      accent: "var(--mod-trace)",
      chip: null,
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
              <ThemeToggle />
            </div>
          </div>

          <div className="kpis">
            {kpis.map((c) => (
              <div
                className="kpi"
                key={c.k}
                style={{ ["--accent-mod" as string]: c.accent }}
              >
                <div className="kpi-top">
                  <span className="kpi-ic">{c.icon}</span>
                  {c.chip ? <span className="chip num">{c.chip}</span> : null}
                </div>
                <div className="kpi-k">{c.k}</div>
                <div className="kpi-v num">{c.v}</div>
                <div className="kpi-sub">{c.sub}</div>
              </div>
            ))}
          </div>

          <div className="content">
            <div className="card feed-card">
              <div className="card-head">
                <div>
                  <span className="card-title">Live threat feed</span>
                  <div className="card-meta" style={{ marginTop: 3 }}>
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
