import { performance } from "node:perf_hooks";
import { withTenantDb } from "@/lib/db";

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
};

export async function readLedgerHealth(tenantId: string): Promise<LedgerHealth> {
  const started = performance.now();
  return withTenantDb(tenantId, async (client) => {
    const [summary, modules] = await Promise.all([
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
      client.query<{
        module: string;
        events_24h: string;
        critical_24h: string;
        latest_ms: string | null;
        policy_versions: string[] | null;
      }>(`
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
    ]);
    const row = summary.rows[0];
    return {
      database_latency_ms: Math.round((performance.now() - started) * 10) / 10,
      total_events: Number(row?.total ?? 0),
      oldest_received_ms: row?.oldest_ms ? Number(row.oldest_ms) : null,
      newest_received_ms: row?.newest_ms ? Number(row.newest_ms) : null,
      modules: modules.rows.map((module) => ({
        module: module.module,
        events_24h: Number(module.events_24h),
        critical_24h: Number(module.critical_24h),
        latest_received_ms: module.latest_ms ? Number(module.latest_ms) : null,
        policy_versions: module.policy_versions ?? [],
      })),
    };
  });
}
