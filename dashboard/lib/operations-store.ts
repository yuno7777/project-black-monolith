import { performance } from "node:perf_hooks";
import { isBearerToken } from "@/lib/credentials";
import { withTenantDb } from "@/lib/db";
import { getMemoryEventsForTenant } from "@/lib/event-store";
import { KNOWN_MODULES } from "@/lib/types";

export const MODULE_RUNTIME_ENV = [
  { module: "mcp-shield", env: "MCP_SHIELD_INTERNAL_URL" },
  { module: "vector-anchor", env: "VECTOR_ANCHOR_INTERNAL_URL" },
  { module: "trace-audit", env: "TRACE_AUDIT_INTERNAL_URL" },
] as const;

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export type ModuleRuntimeDelivery = {
  pending: number;
  dead: number;
  outbox_pending: number;
  outbox_dead_letter: number;
  worker_alive?: boolean;
  worker_error?: string | null;
  [key: string]: unknown;
};

export type ModuleRuntimeHealth = {
  module: string;
  configured: boolean;
  reachable: boolean;
  delivery?: ModuleRuntimeDelivery | null;
  outbox_pending: number;
  outbox_dead_letter: number;
  backend?: unknown;
  status?: number;
  error?: string;
};

export type ModuleLedgerHealth = {
  module: string;
  events_24h: number;
  critical_24h: number;
  latest_received_ms: number | null;
  policy_versions: string[];
  outbox_pending: number;
  outbox_dead_letter: number;
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

export type DeadLetterReplayResult = {
  tenant_id: string;
  alerts_replayed: number;
  total_replayed: number;
  modules: Array<{
    module: string;
    configured: boolean;
    ok: boolean;
    replayed: number;
    status?: number;
    error?: string;
  }>;
};

type ModuleHealthRow = {
  module: string;
  events_24h: string;
  critical_24h: string;
  latest_ms: string | null;
  policy_versions: string[] | null;
};

export function moduleAdminUrl(
  baseUrl: string,
  pathname: string,
  allowInsecureHttp: boolean,
): URL | null {
  try {
    const url = new URL(baseUrl);
    if (url.username || url.password || url.hash) return null;
    if (
      url.protocol !== "https:"
      && !(url.protocol === "http:" && (LOOPBACK_HOSTS.has(url.hostname) || allowInsecureHttp))
    ) {
      return null;
    }
    return new URL(pathname, url);
  } catch {
    return null;
  }
}

export function moduleStatsUrl(baseUrl: string, allowInsecureHttp: boolean): URL | null {
  return moduleAdminUrl(baseUrl, "/stats", allowInsecureHttp);
}

export async function moduleRuntimeHealth(
  module: string,
  baseUrl: string | undefined,
  token: string | undefined,
): Promise<ModuleRuntimeHealth> {
  if (!baseUrl) {
    return {
      module,
      configured: false,
      reachable: false,
      outbox_pending: 0,
      outbox_dead_letter: 0,
    };
  }
  const target = moduleStatsUrl(
    baseUrl,
    process.env.MONOLITH_ALLOW_INSECURE_MODULE_HEALTH === "true",
  );
  if (!target || (token && !isBearerToken(token))) {
    return {
      module,
      configured: true,
      reachable: false,
      outbox_pending: 0,
      outbox_dead_letter: 0,
      error: "unsafe configuration",
    };
  }
  try {
    const headers: Record<string, string> = {};
    if (token) headers.authorization = `Bearer ${token}`;
    const response = await fetch(target, {
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(1_500),
    });
    if (!response.ok) {
      return {
        module,
        configured: true,
        reachable: false,
        outbox_pending: 0,
        outbox_dead_letter: 0,
        status: response.status,
      };
    }
    const body = (await response.json()) as Record<string, unknown>;
    const deliveryRaw =
      body.delivery && typeof body.delivery === "object" && !Array.isArray(body.delivery)
        ? (body.delivery as Record<string, unknown>)
        : null;
    const pending = Number(
      deliveryRaw?.pending
        ?? deliveryRaw?.outbox_pending
        ?? body.outbox_pending
        ?? body.pending
        ?? 0,
    );
    const dead = Number(
      deliveryRaw?.dead
        ?? deliveryRaw?.outbox_dead_letter
        ?? body.outbox_dead_letter
        ?? body.dead
        ?? 0,
    );
    const delivery: ModuleRuntimeDelivery | null =
      deliveryRaw
      || body.outbox_pending !== undefined
      || body.outbox_dead_letter !== undefined
      || body.pending !== undefined
      || body.dead !== undefined
        ? {
            ...(deliveryRaw ?? {}),
            pending: Number.isFinite(pending) ? pending : 0,
            dead: Number.isFinite(dead) ? dead : 0,
            outbox_pending: Number.isFinite(pending) ? pending : 0,
            outbox_dead_letter: Number.isFinite(dead) ? dead : 0,
          }
        : null;
    return {
      module,
      configured: true,
      reachable: true,
      delivery,
      outbox_pending: delivery?.outbox_pending ?? 0,
      outbox_dead_letter: delivery?.outbox_dead_letter ?? 0,
      backend: body.backend ?? null,
    };
  } catch (error) {
    return {
      module,
      configured: true,
      reachable: false,
      outbox_pending: 0,
      outbox_dead_letter: 0,
      error: error instanceof Error ? error.name : "request failed",
    };
  }
}

export async function probeModuleRuntimes(): Promise<ModuleRuntimeHealth[]> {
  const token =
    process.env.MONOLITH_MODULE_ADMIN_TOKEN ?? process.env.MONOLITH_ADMIN_TOKEN;
  return Promise.all(
    MODULE_RUNTIME_ENV.map(({ module, env }) =>
      moduleRuntimeHealth(module, process.env[env], token),
    ),
  );
}

export function normalizeModuleLedgerHealth(
  rows: ModuleHealthRow[],
  runtimes: ModuleRuntimeHealth[] = [],
): ModuleLedgerHealth[] {
  const byModule = new Map(rows.map((row) => [row.module, row]));
  const runtimeByModule = new Map(runtimes.map((r) => [r.module, r]));
  return KNOWN_MODULES.map((module) => {
    const row = byModule.get(module);
    const runtime = runtimeByModule.get(module);
    return {
      module,
      events_24h: Number(row?.events_24h ?? 0),
      critical_24h: Number(row?.critical_24h ?? 0),
      latest_received_ms: row?.latest_ms ? Number(row.latest_ms) : null,
      policy_versions: row?.policy_versions ?? [],
      outbox_pending: Number(runtime?.outbox_pending ?? 0),
      outbox_dead_letter: Number(runtime?.outbox_dead_letter ?? 0),
    };
  });
}

export async function readLedgerHealth(tenantId: string): Promise<LedgerHealth> {
  const started = performance.now();
  const runtimes = await probeModuleRuntimes();

  if (!process.env.DATABASE_URL) {
    const events = getMemoryEventsForTenant(tenantId);
    const now = Date.now();
    const cutoff = now - 86_400_000;
    const rows: ModuleHealthRow[] = KNOWN_MODULES.map((module) => {
      const modEvents = events.filter((e) => e.module === module);
      const recent = modEvents.filter((e) => (e.received_ms ?? e.timestamp_ms) >= cutoff);
      const latest = modEvents.length
        ? Math.max(...modEvents.map((e) => e.received_ms ?? e.timestamp_ms))
        : null;
      const policies = Array.from(
        new Set(modEvents.map((e) => e.policy_version).filter((v): v is string => Boolean(v))),
      );
      return {
        module,
        events_24h: String(recent.length),
        critical_24h: String(recent.filter((e) => e.severity === "critical").length),
        latest_ms: latest !== null ? String(latest) : null,
        policy_versions: policies,
      };
    });
    const receivedTimes = events.map((e) => e.received_ms ?? e.timestamp_ms);
    return {
      database_latency_ms: Math.round((performance.now() - started) * 10) / 10,
      total_events: events.length,
      oldest_received_ms: receivedTimes.length ? Math.min(...receivedTimes) : null,
      newest_received_ms: receivedTimes.length ? Math.max(...receivedTimes) : null,
      modules: normalizeModuleLedgerHealth(rows, runtimes),
      alerts: {
        pending: 0,
        dead: 0,
        delivered_24h: 0,
        oldest_pending_ms: null,
      },
    };
  }

  return withTenantDb(tenantId, async (client) => {
    // Run queries sequentially on the single PoolClient to avoid concurrent
    // query execution on the same connection.
    const summary = await client.query<{
      total: string;
      oldest_ms: string | null;
      newest_ms: string | null;
    }>(`
      select count(*)::text as total,
             (extract(epoch from min(received_at)) * 1000)::bigint::text as oldest_ms,
             (extract(epoch from max(received_at)) * 1000)::bigint::text as newest_ms
        from monolith.security_events
    `);

    const modules = await client.query<ModuleHealthRow>(`
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
    `);

    const alerts = await client.query<{
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
    `);

    const row = summary.rows[0];
    const alertRow = alerts.rows[0];
    return {
      database_latency_ms: Math.round((performance.now() - started) * 10) / 10,
      total_events: Number(row?.total ?? 0),
      oldest_received_ms: row?.oldest_ms ? Number(row.oldest_ms) : null,
      newest_received_ms: row?.newest_ms ? Number(row.newest_ms) : null,
      modules: normalizeModuleLedgerHealth(modules.rows, runtimes),
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

export async function replayDeadLetters(tenantId: string): Promise<DeadLetterReplayResult> {
  const token =
    process.env.MONOLITH_MODULE_ADMIN_TOKEN ?? process.env.MONOLITH_ADMIN_TOKEN;
  const allowInsecure = process.env.MONOLITH_ALLOW_INSECURE_MODULE_HEALTH === "true";

  const moduleResults = await Promise.all(
    MODULE_RUNTIME_ENV.map(async ({ module, env }) => {
      const baseUrl = process.env[env];
      if (!baseUrl) {
        return { module, configured: false, ok: false, replayed: 0 };
      }
      const target = moduleAdminUrl(baseUrl, "/admin/replay-dead-letters", allowInsecure);
      if (!target || (token && !isBearerToken(token))) {
        return {
          module,
          configured: true,
          ok: false,
          replayed: 0,
          error: "unsafe configuration",
        };
      }
      try {
        const headers: Record<string, string> = {};
        if (token) headers.authorization = `Bearer ${token}`;
        const response = await fetch(target, {
          method: "POST",
          headers,
          cache: "no-store",
          signal: AbortSignal.timeout(3_000),
        });
        if (!response.ok) {
          return {
            module,
            configured: true,
            ok: false,
            replayed: 0,
            status: response.status,
          };
        }
        const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
        const replayed = Number(
          body.replayed ?? body.requeued ?? body.outbox_replayed ?? 0,
        );
        return {
          module,
          configured: true,
          ok: true,
          replayed: Number.isFinite(replayed) ? replayed : 0,
        };
      } catch (error) {
        return {
          module,
          configured: true,
          ok: false,
          replayed: 0,
          error: error instanceof Error ? error.name : "request failed",
        };
      }
    }),
  );

  let alertsReplayed = 0;
  if (process.env.DATABASE_URL) {
    alertsReplayed = await withTenantDb(tenantId, async (client) => {
      const res = await client.query(
        `update monolith.alert_outbox
            set status = 'pending',
                attempts = 0,
                next_attempt_at = now(),
                last_error = null
          where tenant_id = $1 and status = 'dead'`,
        [tenantId],
      );
      return res.rowCount ?? 0;
    });
  }

  const totalReplayed =
    alertsReplayed + moduleResults.reduce((sum, item) => sum + item.replayed, 0);

  return {
    tenant_id: tenantId,
    alerts_replayed: alertsReplayed,
    total_replayed: totalReplayed,
    modules: moduleResults,
  };
}
