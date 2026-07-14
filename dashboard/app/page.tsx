"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { MonolithEvent } from "@/lib/types";
import { KNOWN_MODULES } from "@/lib/types";
import ThreatFeed from "./components/ThreatFeed";
import ModuleStatusCard from "./components/ModuleStatusCard";
import SessionSummary from "./components/SessionSummary";

export default function Page() {
  const [events, setEvents] = useState<MonolithEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const seen = useRef<Set<number>>(new Set());

  useEffect(() => {
    const es = new EventSource("/api/events");
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.onmessage = (msg) => {
      try {
        const evt = JSON.parse(msg.data) as MonolithEvent;
        // De-dupe by seq (history replay + live can overlap on reconnect).
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
    for (const e of events) {
      (map[e.module] ??= []).push(e);
    }
    return map;
  }, [events]);

  return (
    <div className="app">
      <header className="header">
        <h1>
          Project Black Monolith
          <span className="sub">unified agent-security threat dashboard · Sleepers Research</span>
        </h1>
        <span className="conn">
          <span className={`dot${connected ? " live" : ""}`} />
          {connected ? "live — streaming events" : "disconnected"}
        </span>
      </header>

      <div className="grid">
        <div className="col">
          <SessionSummary events={events} />
          <div className="panel">
            <div className="panel-title">Modules</div>
            {KNOWN_MODULES.map((m) => (
              <ModuleStatusCard key={m} module={m} events={byModule[m] ?? []} />
            ))}
          </div>
        </div>
        <div className="col">
          <ThreatFeed events={events} />
        </div>
      </div>
    </div>
  );
}
