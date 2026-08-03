import { performance } from "node:perf_hooks";
import { withTenantDb } from "@/lib/db";
import { KNOWN_MODULES } from "@/lib/types";

export type ModuleLedgerHealth = {
  module: string;
  events_24h: number;
  critical_24h: number;
  latest_received_ms: number | null;
  policy_versions: string[];
};

export type LedgerHealth = {
  database_latency_ms: number;
  total_events: number;
  oldest_received_ms: number | null;
  newest_received_ms: number | null;
  modules: ModuleLedgerHealth[];
  alerts: {
    pending: number;
    dead: number;
    delivered_24h: number;
    oldest_pending_ms: number | null;
  };
};

type ModuleHealthRow = {
  module: string;
  events_24h: string;
  critical_24h: string;
  latest_ms: string | null;
  policy_versions: string[] | null;
};

export function normalizeModuleLedgerHealth(rows: ModuleHealthRow[]): ModuleLedgerHealth[] {
  const byModule = new Map(rows.map((row) => [row.module, row]));
  return KNOWN_MODULES.map((module) => {
    const row = byModule.get(module);
    return {
      module,
      events_24h: Number(row?.events_24h ?? 0),
      critical_24h: Number(row?.critical_24h ?? 0),
      latest_received_ms: row?.latest_ms ? Number(row.latest_ms) : null,
      policy_versions: row?.policy_versions ?? [],
    };
  });
}

export async function readLedgerHealth(tenantId: string): Promise<LedgerHealth> {
  const started = performance.now();
  return withTenantDb(tenantId, async (client) => {
    const [summary, modules, alerts] = await Promise.all([
      client.query<{
        total: string;
        oldest_ms: string | null;
        newest_ms: string | null;
      }>(`
        select count(*)::text as total,
               (extract(epoch from min(received_at)) * 1000)::bigint::text as oldest_ms,
               (extract(epoch from max(received_at)) * 1000)::bigint::text as newest_ms
          from monolith.security_events
      `),
      client.query<ModuleHealthRow>(`
        select module,
               count(*) filter (where received_at >= now() - interval '24 hours')::text as events_24h,
               count(*) filter (
                 where received_at >= now() - interval '24 hours' and severity = 'critical'
               )::text as critical_24h,
               (extract(epoch from max(received_at)) * 1000)::bigint::text as latest_ms,
               array_remove(array_agg(distinct policy_version), null) as policy_versions
          from monolith.security_events
         group by module
         order by module
      `),
      client.query<{
        pending: string;
        dead: string;
        delivered_24h: string;
        oldest_pending_ms: string | null;
      }>(`
        select count(*) filter (where status = 'pending')::text as pending,
               count(*) filter (where status = 'dead')::text as dead,
               count(*) filter (
                 where status = 'delivered' and delivered_at >= now() - interval '24 hours'
               )::text as delivered_24h,
               (extract(epoch from min(created_at) filter (where status = 'pending')) * 1000)
                 ::bigint::text as oldest_pending_ms
          from monolith.alert_outbox
      `),
    ]);
    const row = summary.rows[0];
    const alertRow = alerts.rows[0];
    return {
      database_latency_ms: Math.round((performance.now() - started) * 10) / 10,
      total_events: Number(row?.total ?? 0),
      oldest_received_ms: row?.oldest_ms ? Number(row.oldest_ms) : null,
      newest_received_ms: row?.newest_ms ? Number(row.newest_ms) : null,
      modules: normalizeModuleLedgerHealth(modules.rows),
      alerts: {
        pending: Number(alertRow?.pending ?? 0),
        dead: Number(alertRow?.dead ?? 0),
        delivered_24h: Number(alertRow?.delivered_24h ?? 0),
        oldest_pending_ms: alertRow?.oldest_pending_ms
          ? Number(alertRow.oldest_pending_ms)
          : null,
      },
    };
  });
}
