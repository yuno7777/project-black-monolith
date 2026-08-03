"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { MODULE_LABELS } from "@/lib/types";
import { Rail } from "../components/Sidebar";
import ThemeToggle from "../components/ThemeToggle";
import OperatorBadge from "../components/OperatorBadge";
import { IconActivity, IconAlert, IconBolt, ModuleGlyph } from "../components/Icons";

type Delivery = { pending?: number; dead?: number; worker_alive?: boolean; worker_error?: string | null };
type Operations = {
  generated_at_ms: number;
  ledger: {
    database_latency_ms: number;
    total_events: number;
    oldest_received_ms: number | null;
    newest_received_ms: number | null;
    alerts: { pending: number; dead: number; delivered_24h: number; oldest_pending_ms: number | null };
    modules: Array<{
      module: string;
      events_24h: number;
      critical_24h: number;
      latest_received_ms: number | null;
      policy_versions: string[];
    }>;
  };
  alerting: { enabled: boolean; error?: string };
  runtimes: Array<{
    module: string;
    configured: boolean;
    reachable: boolean;
    delivery?: Delivery | null;
    backend?: string | null;
    status?: number;
  }>;
};

function relativeTime(value: number | null): string {
  if (!value) return "No evidence received";
  const seconds = Math.max(0, Math.round((Date.now() - value) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default function OperationsPage() {
  const [data, setData] = useState<Operations | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    setRefreshing(true);
    try {
      const response = await fetch("/api/operations", { cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error ?? "operations request failed");
      setData(body);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "operations request failed");
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = setInterval(load, 15_000);
    return () => clearInterval(timer);
  }, [load]);

  const runtimeByModule = useMemo(
    () => new Map(data?.runtimes.map((runtime) => [runtime.module, runtime]) ?? []),
    [data],
  );
  const runtimeDeadLetters = data?.runtimes.reduce(
    (sum, runtime) => sum + Number(runtime.delivery?.dead ?? 0),
    0,
  ) ?? 0;
  const runtimePending = data?.runtimes.reduce(
    (sum, runtime) => sum + Number(runtime.delivery?.pending ?? 0),
    0,
  ) ?? 0;
  const deadLetters = runtimeDeadLetters + (data?.ledger.alerts.dead ?? 0);
  const pending = runtimePending + (data?.ledger.alerts.pending ?? 0);

  return (
    <div className="frame">
      <div className="app two-col">
        <Rail />
        <main className="main operations-page">
          <div className="topbar">
            <div>
              <h1>Operations</h1>
              <div className="crumb">Delivery health · policy coverage · evidence retention</div>
            </div>
            <div className="topbar-right">
              <button className="ghost-btn" onClick={() => void load()} disabled={refreshing}>
                {refreshing ? "Refreshing…" : "Refresh"}
              </button>
              <OperatorBadge />
              <ThemeToggle />
            </div>
          </div>

          <div className="content-scroll operations-scroll">
            {error ? <div className="ops-error">{error}</div> : null}
            {data?.alerting.error ? <div className="ops-error">Alerting: {data.alerting.error}</div> : null}
            <section className="ops-hero">
              <div>
                <span className="ops-eyebrow">Control plane</span>
                <h2>{deadLetters ? "Delivery needs attention" : "Evidence pipeline nominal"}</h2>
                <p>Live runtime queues are reconciled with the immutable tenant ledger every 15 seconds.</p>
              </div>
              <span className={`ops-state${deadLetters ? " warn" : ""}`}>
                <span className="dot live" /> {deadLetters ? `${deadLetters} dead-lettered` : "No dead letters"}
              </span>
            </section>

            <div className="ops-kpis">
              <div className="card ops-kpi"><IconActivity /><span>Ledger events</span><strong className="num">{data?.ledger.total_events ?? "—"}</strong></div>
              <div className="card ops-kpi"><IconBolt /><span>Database response</span><strong className="num">{data ? `${data.ledger.database_latency_ms} ms` : "—"}</strong></div>
              <div className="card ops-kpi"><IconActivity /><span>Queued delivery + alerts</span><strong className="num">{data ? pending : "—"}</strong></div>
              <div className="card ops-kpi"><IconAlert /><span>All dead letters</span><strong className="num">{data ? deadLetters : "—"}</strong></div>
            </div>

            <section className="card ops-table-card">
              <div className="card-head">
                <div><span className="card-title">Defense layer health</span><div className="card-meta">collector + runtime evidence</div></div>
                <span className="card-meta">Last refresh {data ? relativeTime(data.generated_at_ms) : "—"}</span>
              </div>
              <div className="ops-module-list">
                {data?.ledger.modules.map((module) => {
                  const runtime = runtimeByModule.get(module.module);
                  const stale = !module.latest_received_ms || Date.now() - module.latest_received_ms > 86_400_000;
                  return (
                    <article className="ops-module" key={module.module}>
                      <span className="ops-module-icon"><ModuleGlyph module={module.module} size={20} /></span>
                      <div className="ops-module-main">
                        <strong>{MODULE_LABELS[module.module] ?? module.module}</strong>
                        <span>{module.policy_versions.length ? module.policy_versions.join(" · ") : "Policy version not yet reported"}</span>
                      </div>
                      <div className="ops-cell"><span>24h events</span><strong className="num">{module.events_24h}</strong></div>
                      <div className="ops-cell"><span>Critical</span><strong className="num">{module.critical_24h}</strong></div>
                      <div className="ops-cell"><span>Last evidence</span><strong className={stale ? "warn-text" : ""}>{relativeTime(module.latest_received_ms)}</strong></div>
                      <div className="ops-cell"><span>Runtime</span><strong>{runtime ? (runtime.reachable ? "Reachable" : runtime.configured ? "Unavailable" : "Not configured") : "Ledger only"}</strong></div>
                    </article>
                  );
                })}
                {!data?.ledger.modules.length ? <div className="ops-empty">Waiting for the first ledger event.</div> : null}
              </div>
            </section>
          </div>
        </main>
      </div>
    </div>
  );
}
