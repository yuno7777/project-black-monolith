"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import type { Incident, IncidentStatus, MonolithEvent, Severity } from "@/lib/types";
import { KNOWN_MODULES, MODULE_ACCENT, MODULE_LABELS, STATUS_LABELS } from "@/lib/types";
import Sidebar, { Rail } from "../components/Sidebar";
import ThemeToggle from "../components/ThemeToggle";
import IncidentPanel, { type TransitionRequest } from "../components/IncidentPanel";
import { useAnalyst } from "../components/useAnalyst";
import { ModuleGlyph, SevIcon, IconSearch, IconUser, IconLedger } from "../components/Icons";

type StatusTab = IncidentStatus | "open" | "all";

const STATUS_TABS: { key: StatusTab; label: string }[] = [
  { key: "open", label: "Open" },
  { key: "new", label: "New" },
  { key: "acknowledged", label: "Acked" },
  { key: "resolved", label: "Resolved" },
  { key: "all", label: "All" },
];

const SEVERITY_TABS: { key: Severity | "all"; label: string }[] = [
  { key: "all", label: "All" },
  { key: "critical", label: "Critical" },
  { key: "warning", label: "Warning" },
  { key: "info", label: "Info" },
];

const WINDOWS: { key: string; label: string; ms: number | null }[] = [
  { key: "1h", label: "1h", ms: 3_600_000 },
  { key: "24h", label: "24h", ms: 86_400_000 },
  { key: "7d", label: "7d", ms: 604_800_000 },
  { key: "all", label: "All time", ms: null },
];

function ago(ms: number): string {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function InvestigateConsole() {
  // Arriving from a feed row: /investigate?event=<id>. The default filters
  // (open, last 24h) would hide a resolved or older event and the panel would
  // silently never open, so a deep link widens them to "all".
  const deepLinkId = useSearchParams().get("event");

  const [analyst, setAnalyst] = useAnalyst();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [status, setStatus] = useState<StatusTab>(deepLinkId ? "all" : "open");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [module, setModule] = useState<string | null>(null);
  const [windowKey, setWindowKey] = useState(deepLinkId ? "all" : "24h");
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(deepLinkId);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Debounce the free-text box so typing does not fire a query per keystroke.
  const [debouncedQuery, setDebouncedQuery] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setDebouncedQuery(query), 250);
    return () => clearTimeout(t);
  }, [query]);

  // Guards against an older in-flight response overwriting a newer one when
  // filters change faster than the queries return.
  const requestSeq = useRef(0);

  const load = useCallback(async () => {
    const seq = ++requestSeq.current;
    const params = new URLSearchParams({ status, severity, limit: "300" });
    if (module) params.set("module", module);
    if (debouncedQuery) params.set("q", debouncedQuery);
    const win = WINDOWS.find((w) => w.key === windowKey);
    if (win?.ms) params.set("since_ms", String(Date.now() - win.ms));

    try {
      const res = await fetch(`/api/incidents?${params}`);
      if (!res.ok) throw new Error((await res.json()).error ?? "request failed");
      const data = await res.json();
      if (seq !== requestSeq.current) return;
      setIncidents(data.incidents ?? []);
      setCounts(data.counts ?? {});
      setError(null);
    } catch (e) {
      if (seq !== requestSeq.current) return;
      setError(e instanceof Error ? e.message : "could not reach the ledger");
    } finally {
      if (seq === requestSeq.current) setLoading(false);
    }
  }, [status, severity, module, windowKey, debouncedQuery]);

  useEffect(() => {
    load();
  }, [load]);

  // The queue is a working surface, not a live feed: re-sorting under an
  // analyst's cursor mid-triage would be hostile. Pick up new events on a slow
  // poll instead of subscribing to the SSE stream.
  useEffect(() => {
    const t = setInterval(load, 15_000);
    return () => clearInterval(t);
  }, [load]);

  const selected = useMemo(
    () => incidents.find((i) => i.event_id === selectedId) ?? null,
    [incidents, selectedId],
  );

  const byModule = useMemo(() => {
    const map: Record<string, MonolithEvent[]> = {};
    for (const m of KNOWN_MODULES) map[m] = [];
    for (const i of incidents) (map[i.module] ??= []).push(i);
    return map;
  }, [incidents]);

  const transition = useCallback(
    async (eventId: string, t: TransitionRequest): Promise<string | null> => {
      try {
        const res = await fetch("/api/incidents", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ...t, event_id: eventId, actor: analyst }),
        });
        const data = await res.json();
        if (!res.ok) return data.error ?? "the transition was rejected";
        // Patch in place so the row does not jump while the panel is open, then
        // reconcile with the server on the next poll.
        setIncidents((prev) =>
          prev.map((i) => (i.event_id === eventId ? { ...i, triage: data.triage } : i)),
        );
        setCounts((c) => ({ ...c }));
        load();
        return null;
      } catch {
        return "could not reach the ledger";
      }
    },
    [analyst, load],
  );

  const openCount = counts.open ?? 0;

  return (
    <div className="frame">
      <div className="app">
        <Rail />
        <Sidebar byModule={byModule} filter={module} onFilter={setModule} />

        <main className="main">
          <div className="topbar">
            <div>
              <h1>Investigation queue</h1>
              <div className="crumb">
                {openCount} open · triage, assign and resolve against the persisted ledger
              </div>
            </div>

            <div className="search">
              <IconSearch />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search type, assignee, correlation id, evidence…"
                aria-label="Search incidents"
              />
            </div>

            <div className="topbar-right">
              <span className="analyst">
                <IconUser size={13} />
                <input
                  value={analyst}
                  onChange={(e) => setAnalyst(e.target.value)}
                  aria-label="Your analyst name"
                  title="Recorded against your triage actions (not authentication)"
                  spellCheck={false}
                />
              </span>
              <ThemeToggle />
            </div>
          </div>

          <div className="filters">
            <div className="seg" role="tablist" aria-label="Filter by status">
              {STATUS_TABS.map((t) => (
                <button
                  key={t.key}
                  role="tab"
                  aria-selected={status === t.key}
                  className={status === t.key ? "on" : ""}
                  onClick={() => setStatus(t.key)}
                >
                  {t.label}
                  {counts[t.key] !== undefined ? (
                    <span className="seg-n num">{counts[t.key]}</span>
                  ) : null}
                </button>
              ))}
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
                </button>
              ))}
            </div>

            <div className="seg" role="tablist" aria-label="Filter by time window">
              {WINDOWS.map((w) => (
                <button
                  key={w.key}
                  role="tab"
                  aria-selected={windowKey === w.key}
                  className={windowKey === w.key ? "on" : ""}
                  onClick={() => setWindowKey(w.key)}
                >
                  {w.label}
                </button>
              ))}
            </div>
          </div>

          <div className={`content${selected ? "" : " content-wide"}`}>
            <div className="card feed-card">
              <div className="card-head">
                <div>
                  <span className="card-title">Queue</span>
                  <div className="card-meta" style={{ marginTop: 3 }}>
                    {module ? `${MODULE_LABELS[module]} · ` : "worst first · "}
                    {incidents.length} incident{incidents.length === 1 ? "" : "s"}
                  </div>
                </div>
              </div>

              <div className="feed">
                {error ? (
                  <div className="empty">
                    <div className="empty-ic"><IconLedger size={30} /></div>
                    {error}
                  </div>
                ) : loading ? (
                  <div className="empty">Loading the queue…</div>
                ) : incidents.length === 0 ? (
                  <div className="empty">
                    <div className="empty-ic"><IconLedger size={30} /></div>
                    {status === "open"
                      ? "Nothing open in this window — the queue is clear."
                      : "No incidents match these filters."}
                  </div>
                ) : (
                  incidents.map((i) => {
                    const st = i.triage?.status ?? "new";
                    return (
                      <button
                        key={i.event_id}
                        className={`event event-hit inc${selectedId === i.event_id ? " on" : ""}`}
                        style={{ ["--accent-mod" as string]: MODULE_ACCENT[i.module] ?? "var(--ink-faint)" }}
                        onClick={() => setSelectedId(selectedId === i.event_id ? null : i.event_id)}
                      >
                        <div className="event-row">
                          <span className="badge">
                            <ModuleGlyph module={i.module} size={13} />
                            {MODULE_LABELS[i.module] ?? i.module}
                          </span>
                          <span className={`sev ${i.severity}`}>
                            <SevIcon severity={i.severity} />
                            {i.severity}
                          </span>
                          <span className="event-type">{i.event_type}</span>
                          <span className={`status-pill ${st}`}>{STATUS_LABELS[st]}</span>
                          <span className="event-time">{ago(i.timestamp_ms)}</span>
                        </div>
                        <div className="event-preview">
                          {i.triage?.assignee ? `${i.triage.assignee} · ` : "unassigned · "}
                          {i.triage?.note ?? "no note"}
                        </div>
                      </button>
                    );
                  })
                )}
              </div>
            </div>

            {selected ? (
              <div className="stack">
                <IncidentPanel
                  incident={selected}
                  analyst={analyst}
                  onTransition={(t) => transition(selected.event_id, t)}
                  onClose={() => setSelectedId(null)}
                />
              </div>
            ) : null}
          </div>
        </main>
      </div>
    </div>
  );
}

// useSearchParams needs a Suspense boundary above it, otherwise this route
// opts out of static prerendering at build time.
export default function InvestigatePage() {
  return (
    <Suspense fallback={null}>
      <InvestigateConsole />
    </Suspense>
  );
}
