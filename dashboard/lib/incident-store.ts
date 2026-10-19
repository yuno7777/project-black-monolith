import { createHash, createHmac } from "node:crypto";
import { withTenantDb } from "@/lib/db";
import { getMemoryEventsForTenant } from "@/lib/event-store";
import type {
  AuditEntry,
  EvidenceBundle,
  EvidenceIntegrity,
  Incident,
  IncidentStatus,
  MonolithEvent,
  Resolution,
  SessionLayer,
  SessionRevocation,
  SessionView,
  Severity,
  Triage,
} from "@/lib/types";
import { INCIDENT_STATUSES, RESOLUTIONS } from "@/lib/types";

const KNOWN_MODULES = new Set(["mcp-shield", "vector-anchor", "trace-audit"]);
const SEVERITIES = new Set<Severity>(["info", "warning", "critical"]);
const CIRCUIT_BREAKER_SEVERITIES = new Set(["warning", "high", "critical"]);
const MAX_ASSIGNEE = 128;
const MAX_NOTE = 2000;
const MAX_ACTOR = 128;

export class IncidentInputError extends Error {}

// --- In-memory fallback stores for unit tests when DATABASE_URL is unset ----

const memoryIncidentRef = globalThis as unknown as {
  __monolithRevokedSessions?: Map<string, SessionRevocation>;
  __monolithSessionModules?: Map<string, Set<string>>;
  __monolithMemoryTriage?: Map<string, Triage>;
  __monolithMemoryAudit?: Map<string, AuditEntry[]>;
  __monolithNextAuditId?: number;
};

function revokedSessionMap(): Map<string, SessionRevocation> {
  if (!memoryIncidentRef.__monolithRevokedSessions) {
    memoryIncidentRef.__monolithRevokedSessions = new Map<string, SessionRevocation>();
  }
  return memoryIncidentRef.__monolithRevokedSessions;
}

function sessionModulesMap(): Map<string, Set<string>> {
  if (!memoryIncidentRef.__monolithSessionModules) {
    memoryIncidentRef.__monolithSessionModules = new Map<string, Set<string>>();
  }
  return memoryIncidentRef.__monolithSessionModules;
}

function memoryTriageMap(): Map<string, Triage> {
  if (!memoryIncidentRef.__monolithMemoryTriage) {
    memoryIncidentRef.__monolithMemoryTriage = new Map<string, Triage>();
  }
  return memoryIncidentRef.__monolithMemoryTriage;
}

function memoryAuditMap(): Map<string, AuditEntry[]> {
  if (!memoryIncidentRef.__monolithMemoryAudit) {
    memoryIncidentRef.__monolithMemoryAudit = new Map<string, AuditEntry[]>();
  }
  return memoryIncidentRef.__monolithMemoryAudit;
}

function sessionKey(tenantId: string, agentId: string, sessionId: string): string {
  return `${tenantId}\u0000${agentId}\u0000${sessionId}`;
}

export function clearMemoryRevocations(): void {
  revokedSessionMap().clear();
  sessionModulesMap().clear();
  memoryTriageMap().clear();
  memoryAuditMap().clear();
}

// --- reads -----------------------------------------------------------------

type IncidentRow = {
  event_id: string;
  schema_version: number;
  occurred_at_ms: string;
  received_ms: string;
  module: string;
  event_type: string;
  severity: Severity;
  details: Record<string, unknown>;
  tenant_id: string;
  correlation_id: string | null;
  session_id: string | null;
  trace_id: string | null;
  agent_id: string | null;
  outcome: string | null;
  status: IncidentStatus | null;
  assignee: string | null;
  note: string | null;
  resolution: Resolution | null;
  updated_ms: string | null;
  updated_by: string | null;
};

function toIncident(row: IncidentRow): Incident {
  // An event with no triage row has never been looked at. That is different
  // from "new" only in provenance, but the queue treats them alike, so the
  // status is synthesized on read rather than back-filled on ingest — which
  // would put a write on the detection path for every event.
  const triage: Triage | undefined = row.status
    ? {
        status: row.status,
        assignee: row.assignee ?? undefined,
        note: row.note ?? undefined,
        resolution: row.resolution ?? undefined,
        updated_ms: Number(row.updated_ms),
        updated_by: row.updated_by ?? "unknown",
      }
    : undefined;

  return {
    event_id: row.event_id,
    schema_version: row.schema_version === 2 ? 2 : 1,
    timestamp_ms: Number(row.occurred_at_ms),
    received_ms: Number(row.received_ms),
    module: row.module,
    event_type: row.event_type,
    severity: row.severity,
    details: row.details ?? {},
    tenant_id: row.tenant_id,
    correlation_id: row.correlation_id ?? undefined,
    session_id: row.session_id ?? undefined,
    trace_id: row.trace_id ?? undefined,
    agent_id: row.agent_id ?? undefined,
    outcome: row.outcome ?? undefined,
    triage,
  };
}

export interface IncidentQuery {
  tenant_id: string;
  status?: IncidentStatus | "open" | "all" | "triaged";
  severity?: Severity | "all";
  module?: string | "all";
  /** Exact agent session — the cross-layer key. */
  session?: string;
  agent?: string;
  q?: string;
  since_ms?: number;
  limit?: number;
  cursor?: string;
}

interface IncidentCursor {
  severity_rank: number;
  received_ms: number;
  event_id: string;
}

export interface IncidentPage {
  incidents: Incident[];
  next_cursor?: string;
}

const INCIDENT_UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function decodeIncidentCursor(cursor: string): IncidentCursor {
  try {
    const value = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as Record<string, unknown>;
    if (
      !Number.isInteger(value.severity_rank)
      || Number(value.severity_rank) < 0
      || Number(value.severity_rank) > 2
      || !Number.isSafeInteger(value.received_ms)
      || Number(value.received_ms) < 1
      || typeof value.event_id !== "string"
      || !INCIDENT_UUID_PATTERN.test(value.event_id)
    ) {
      throw new Error("invalid fields");
    }
    return {
      severity_rank: Number(value.severity_rank),
      received_ms: Number(value.received_ms),
      event_id: value.event_id,
    };
  } catch {
    throw new IncidentInputError("cursor is invalid or expired");
  }
}

function encodeIncidentCursor(incident: Incident): string {
  const severityRank = incident.severity === "critical" ? 0 : incident.severity === "warning" ? 1 : 2;
  return Buffer.from(JSON.stringify({
    severity_rank: severityRank,
    received_ms: incident.received_ms,
    event_id: incident.event_id,
  })).toString("base64url");
}

export async function listIncidents(query: IncidentQuery): Promise<IncidentPage> {
  const where: string[] = [];
  const params: unknown[] = [];
  const add = (value: unknown) => `$${params.push(value)}`;
  where.push(`e.tenant_id = ${add(query.tenant_id)}`);

  const status = query.status ?? "open";
  if (status === "open") {
    // Untriaged events have no row at all, so "open" must include the null.
    where.push("coalesce(t.status, 'new') in ('new', 'acknowledged')");
  } else if (status === "triaged") {
    // Events someone has actually acted on. The overview uses this to badge
    // its live feed: the triaged set is small, so it can be pulled whole,
    // whereas "everything, with its status" would mean shipping the ledger.
    where.push("t.status is not null");
  } else if (status !== "all") {
    where.push(`coalesce(t.status, 'new') = ${add(status)}`);
  }

  if (query.severity && query.severity !== "all") {
    where.push(`e.severity = ${add(query.severity)}`);
  }
  if (query.module && query.module !== "all") {
    where.push(`e.module = ${add(query.module)}`);
  }
  if (query.since_ms !== undefined) {
    where.push(`e.occurred_at_ms >= ${add(query.since_ms)}`);
  }
  if (query.session) {
    where.push(`e.session_id = ${add(query.session)}`);
  }
  if (query.agent) {
    where.push(`e.agent_id = ${add(query.agent)}`);
  }
  if (query.q) {
    // Free text across the fields an analyst would actually search by. The
    // details cast lets a search hit inside the payload (e.g. a tool name),
    // and the correlation ids are here because pasting a session id into the
    // search box is the most obvious way to ask "what else did this agent do?".
    const needle = add(`%${query.q}%`);
    const searchQuery = add(query.q);
    where.push(`(
      e.event_type ilike ${needle}
      or e.module ilike ${needle}
      or e.severity ilike ${needle}
      or coalesce(t.assignee, '') ilike ${needle}
      or coalesce(e.session_id, '') ilike ${needle}
      or coalesce(e.agent_id, '') ilike ${needle}
      or coalesce(e.trace_id, '') ilike ${needle}
      or coalesce(e.correlation_id, '') ilike ${needle}
      or to_tsvector('simple', coalesce(e.details::text, ''))
         @@ plainto_tsquery('simple', ${searchQuery})
    )`);
  }

  const limit = Math.max(1, Math.min(query.limit ?? 200, 1_000));
  const cursor = query.cursor ? decodeIncidentCursor(query.cursor) : null;
  const severityRank = "case e.severity when 'critical' then 0 when 'warning' then 1 else 2 end";
  if (cursor) {
    const rank = add(cursor.severity_rank);
    const received = add(cursor.received_ms);
    const eventId = add(cursor.event_id);
    where.push(`(
      ${severityRank} > ${rank}
      or (
        ${severityRank} = ${rank}
        and (e.received_at, e.event_id) < (
          to_timestamp(${received}::double precision / 1000), ${eventId}::uuid
        )
      )
    )`);
  }

  return withTenantDb(query.tenant_id, async (db) => {
    const result = await db.query<IncidentRow>(
      `select
         e.event_id, e.schema_version, e.occurred_at_ms,
         (extract(epoch from e.received_at) * 1000)::bigint as received_ms,
         e.module, e.event_type, e.severity, e.details, e.tenant_id,
         e.correlation_id, e.session_id, e.trace_id, e.agent_id, e.outcome,
         t.status, t.assignee, t.note, t.resolution,
         (extract(epoch from t.updated_at) * 1000)::bigint as updated_ms,
         t.updated_by
       from monolith.security_events e
       left join monolith.incident_triage t using (event_id)
       ${where.length ? `where ${where.join(" and ")}` : ""}
       order by
         -- Worst-first, then newest-first: the queue should open on the thing
         -- that matters most, not merely the thing that happened last.
         ${severityRank},
         e.received_at desc,
         e.event_id desc
       limit ${add(limit + 1)}`,
      params,
    );
    const hasMore = result.rows.length > limit;
    const incidents = result.rows.slice(0, limit).map(toIncident);
    return {
      incidents,
      next_cursor: hasMore && incidents.length
        ? encodeIncidentCursor(incidents[incidents.length - 1])
        : undefined,
    };
  });
}

export async function getIncident(eventId: string, tenantId: string): Promise<Incident | null> {
  if (!process.env.DATABASE_URL) {
    const found = getMemoryEventsForTenant(tenantId).find((e) => e.event_id === eventId);
    if (!found) return null;
    const triage = memoryTriageMap().get(eventId);
    return { ...found, triage };
  }
  return withTenantDb(tenantId, async (db) => {
    const result = await db.query<IncidentRow>(
      `select
         e.event_id, e.schema_version, e.occurred_at_ms,
         (extract(epoch from e.received_at) * 1000)::bigint as received_ms,
         e.module, e.event_type, e.severity, e.details, e.tenant_id,
         e.correlation_id, e.session_id, e.trace_id, e.agent_id, e.outcome,
         t.status, t.assignee, t.note, t.resolution,
         (extract(epoch from t.updated_at) * 1000)::bigint as updated_ms,
         t.updated_by
       from monolith.security_events e
       left join monolith.incident_triage t using (event_id)
       where e.event_id = $1 and e.tenant_id = $2
       limit 1`,
      [eventId, tenantId],
    );
    return result.rows[0] ? toIncident(result.rows[0]) : null;
  });
}

export async function getAuditTrail(eventId: string, tenantId: string): Promise<AuditEntry[]> {
  if (!process.env.DATABASE_URL) {
    const found = getMemoryEventsForTenant(tenantId).find((e) => e.event_id === eventId);
    if (!found) return [];
    return [...(memoryAuditMap().get(eventId) ?? [])];
  }
  return withTenantDb(tenantId, async (db) => {
    const result = await db.query<{
      audit_id: string;
      at_ms: string;
      actor: string;
      from_status: IncidentStatus | null;
      to_status: IncidentStatus;
      assignee: string | null;
      resolution: Resolution | null;
      note: string | null;
    }>(
      `select audit_id, (extract(epoch from at) * 1000)::bigint as at_ms,
              actor, from_status, to_status, assignee, resolution, note
       from monolith.incident_audit a
       join monolith.security_events e using (event_id)
       where a.event_id = $1 and e.tenant_id = $2
       order by at desc, audit_id desc`,
      [eventId, tenantId],
    );
    return result.rows.map((r) => ({
      audit_id: Number(r.audit_id),
      at_ms: Number(r.at_ms),
      actor: r.actor,
      from_status: r.from_status ?? undefined,
      to_status: r.to_status,
      assignee: r.assignee ?? undefined,
      resolution: r.resolution ?? undefined,
      note: r.note ?? undefined,
    }));
  });
}

export type { SessionLayer, SessionRevocation, SessionView };

// --- Cross-layer session revocation & circuit breaker (DASH-1) -------------

type RevokedSessionRow = {
  tenant_id: string;
  agent_id: string;
  session_id: string;
  revoked_at: Date | string;
  reason: string;
  triggered_by: string;
  layers: string[] | null;
};

function toSessionRevocation(row: RevokedSessionRow): SessionRevocation {
  return {
    tenant_id: row.tenant_id,
    agent_id: row.agent_id,
    session_id: row.session_id,
    revoked_at:
      row.revoked_at instanceof Date ? row.revoked_at.toISOString() : String(row.revoked_at),
    reason: row.reason,
    triggered_by: row.triggered_by,
    layers: row.layers ?? [],
  };
}

export async function listRevokedSessions(tenantId: string): Promise<SessionRevocation[]> {
  if (!process.env.DATABASE_URL) {
    const out: SessionRevocation[] = [];
    for (const entry of revokedSessionMap().values()) {
      if (entry.tenant_id === tenantId) out.push(entry);
    }
    return out.sort((a, b) => b.revoked_at.localeCompare(a.revoked_at));
  }
  return withTenantDb(tenantId, async (db) => {
    const result = await db.query<RevokedSessionRow>(
      `select tenant_id, agent_id, session_id, revoked_at, reason, triggered_by, layers
         from monolith.revoked_sessions
        where tenant_id = $1
        order by revoked_at desc`,
      [tenantId],
    );
    return result.rows.map(toSessionRevocation);
  });
}

export async function revokeSession(
  tenantId: string,
  agentId: string,
  sessionId: string,
  reason: string,
  triggeredBy: string,
  layers: string[] = [],
): Promise<SessionRevocation> {
  const cleanTenant = text(tenantId, 128, "tenant_id");
  const cleanAgent = text(agentId, 128, "agent_id");
  const cleanSession = text(sessionId, 128, "session_id");
  const cleanReason = text(reason, 512, "reason") ?? "Session quarantined";
  const cleanTrigger = text(triggeredBy, 128, "triggered_by") ?? "operator";
  if (!cleanTenant || !cleanAgent || !cleanSession) {
    throw new IncidentInputError("tenant_id, agent_id, and session_id are required");
  }
  const normalizedLayers = Array.from(new Set(layers.filter((l) => KNOWN_MODULES.has(l)))).sort();
  const key = sessionKey(cleanTenant, cleanAgent, cleanSession);
  const existing = revokedSessionMap().get(key);
  const mergedLayers = normalizedLayers.length
    ? normalizedLayers
    : (existing?.layers ?? []);

  const entry: SessionRevocation = {
    tenant_id: cleanTenant,
    agent_id: cleanAgent,
    session_id: cleanSession,
    revoked_at: new Date().toISOString(),
    reason: cleanReason,
    triggered_by: cleanTrigger,
    layers: mergedLayers,
  };
  revokedSessionMap().set(key, entry);

  if (!process.env.DATABASE_URL) {
    return entry;
  }

  return withTenantDb(cleanTenant, async (db) => {
    const result = await db.query<RevokedSessionRow>(
      `insert into monolith.revoked_sessions
         (tenant_id, agent_id, session_id, reason, triggered_by, layers, revoked_at)
       values ($1, $2, $3, $4, $5, $6::text[], now())
       on conflict (tenant_id, agent_id, session_id) do update set
         reason = excluded.reason,
         triggered_by = excluded.triggered_by,
         layers = case
           when coalesce(array_length(excluded.layers, 1), 0) > 0 then excluded.layers
           else monolith.revoked_sessions.layers
         end,
         revoked_at = now()
       returning tenant_id, agent_id, session_id, revoked_at, reason, triggered_by, layers`,
      [cleanTenant, cleanAgent, cleanSession, cleanReason, cleanTrigger, mergedLayers],
    );
    const saved = toSessionRevocation(result.rows[0]);
    revokedSessionMap().set(key, saved);
    return saved;
  });
}

export async function restoreSession(
  tenantId: string,
  agentId: string,
  sessionId: string,
): Promise<boolean> {
  const cleanTenant = text(tenantId, 128, "tenant_id");
  const cleanAgent = text(agentId, 128, "agent_id");
  const cleanSession = text(sessionId, 128, "session_id");
  if (!cleanTenant || !cleanAgent || !cleanSession) {
    throw new IncidentInputError("tenant_id, agent_id, and session_id are required");
  }
  const key = sessionKey(cleanTenant, cleanAgent, cleanSession);
  const hadMemory = revokedSessionMap().delete(key);
  sessionModulesMap().delete(key);

  if (!process.env.DATABASE_URL) {
    return hadMemory;
  }

  return withTenantDb(cleanTenant, async (db) => {
    const result = await db.query(
      `delete from monolith.revoked_sessions
        where tenant_id = $1 and agent_id = $2 and session_id = $3`,
      [cleanTenant, cleanAgent, cleanSession],
    );
    return (result.rowCount ?? 0) > 0 || hadMemory;
  });
}

export async function evaluateSessionCircuitBreaker(
  events: MonolithEvent[],
): Promise<string[]> {
  if (!events.length) return [];
  const tenantId = events[0].tenant_id;

  // Track candidate (agent_id, session_id) pairs in this ingest batch.
  const candidates = new Map<string, { agentId: string; sessionId: string }>();
  for (const event of events) {
    if (!event.agent_id || !event.session_id) continue;
    const key = sessionKey(tenantId, event.agent_id, event.session_id);
    candidates.set(key, { agentId: event.agent_id, sessionId: event.session_id });
    if (CIRCUIT_BREAKER_SEVERITIES.has(String(event.severity)) && KNOWN_MODULES.has(event.module)) {
      const set = sessionModulesMap().get(key) ?? new Set<string>();
      set.add(event.module);
      sessionModulesMap().set(key, set);
    }
  }

  if (!process.env.DATABASE_URL) {
    for (const [key, { agentId, sessionId }] of candidates) {
      const modules = new Set<string>(sessionModulesMap().get(key) ?? []);
      for (const e of getMemoryEventsForTenant(tenantId)) {
        if (
          e.agent_id === agentId
          && e.session_id === sessionId
          && CIRCUIT_BREAKER_SEVERITIES.has(String(e.severity))
          && KNOWN_MODULES.has(e.module)
        ) {
          modules.add(e.module);
        }
      }
      if (modules.size >= 2 && !revokedSessionMap().has(key)) {
        const layers = Array.from(modules).sort();
        await revokeSession(
          tenantId,
          agentId,
          sessionId,
          `Cross-layer circuit breaker tripped across ${layers.join(", ")}`,
          "auto-circuit-breaker",
          layers,
        );
      }
    }
    const revoked = await listRevokedSessions(tenantId);
    return Array.from(new Set(revoked.map((r) => r.session_id)));
  }

  for (const { agentId, sessionId } of candidates.values()) {
    const layers = await withTenantDb(tenantId, async (db) => {
      const res = await db.query<{ module: string }>(
        `select distinct module
           from monolith.security_events
          where tenant_id = $1
            and agent_id = $2
            and session_id = $3
            and severity in ('warning', 'critical')`,
        [tenantId, agentId, sessionId],
      );
      return res.rows.map((r) => r.module).sort();
    });
    if (layers.length >= 2) {
      await revokeSession(
        tenantId,
        agentId,
        sessionId,
        `Cross-layer circuit breaker tripped across ${layers.join(", ")}`,
        "auto-circuit-breaker",
        layers,
      );
    }
  }

  const revoked = await listRevokedSessions(tenantId);
  return Array.from(new Set(revoked.map((r) => r.session_id)));
}

/**
 * What else happened in this event's agent session.
 *
 * This is the query the whole correlation effort exists for. One module firing
 * is a detection; the same session tripping the tool, memory *and* reasoning
 * layers is a compromised agent, and no single module can see that.
 */
export async function sessionForEvent(eventId: string, tenantId: string): Promise<SessionView | null> {
  if (!process.env.DATABASE_URL) {
    const tenantEvents = getMemoryEventsForTenant(tenantId);
    const target = tenantEvents.find((e) => e.event_id === eventId);
    if (!target || !target.session_id || !target.agent_id) return null;
    const sessionEvents = tenantEvents.filter(
      (e) => e.agent_id === target.agent_id && e.session_id === target.session_id,
    );
    if (!sessionEvents.length) return null;
    const byModule = new Map<string, { events: number; worst: Severity }>();
    const rank = (s: Severity) => (s === "critical" ? 0 : s === "warning" ? 1 : 2);
    for (const e of sessionEvents) {
      const current = byModule.get(e.module);
      if (!current) {
        byModule.set(e.module, { events: 1, worst: e.severity });
      } else {
        current.events += 1;
        if (rank(e.severity) < rank(current.worst)) current.worst = e.severity;
      }
    }
    const layers: SessionLayer[] = Array.from(byModule.entries()).map(([module, v]) => ({
      module,
      events: v.events,
      worst: v.worst,
    }));
    const rev = revokedSessionMap().get(sessionKey(tenantId, target.agent_id, target.session_id));
    return {
      tenant_id: tenantId,
      session_id: target.session_id,
      agent_id: target.agent_id,
      layers,
      total: layers.reduce((sum, l) => sum + l.events, 0),
      cross_layer: layers.length > 1,
      first_ms: Math.min(...sessionEvents.map((e) => e.timestamp_ms)),
      last_ms: Math.max(...sessionEvents.map((e) => e.timestamp_ms)),
      revoked: Boolean(rev),
      revocation: rev
        ? {
            revoked_at: rev.revoked_at,
            reason: rev.reason,
            triggered_by: rev.triggered_by,
            layers: rev.layers,
          }
        : undefined,
    };
  }

  return withTenantDb(tenantId, async (db) => {
    const owner = await db.query<{ session_id: string | null; agent_id: string | null }>(
      `select session_id, agent_id from monolith.security_events
       where event_id = $1 and tenant_id = $2`,
      [eventId, tenantId],
    );
    const session = owner.rows[0]?.session_id;
    const agent = owner.rows[0]?.agent_id;
    // An event with no session cannot be correlated — say so rather than
    // inventing a grouping.
    if (!session || !agent) return null;

    const result = await db.query<{
      module: string;
      events: string;
      worst: Severity;
      first_ms: string;
      last_ms: string;
    }>(
      `select
         module,
         count(*)::bigint as events,
         -- "worst" must be by severity rank, not alphabetical: 'critical' < 'info'
         -- as text would quietly report a critical session as informational.
         (array_agg(severity order by case severity
            when 'critical' then 0 when 'warning' then 1 else 2 end))[1] as worst,
         min(occurred_at_ms)::bigint as first_ms,
         max(occurred_at_ms)::bigint as last_ms
       from monolith.security_events
       where tenant_id = $1 and agent_id = $2 and session_id = $3
       group by module`,
      [tenantId, agent, session],
    );
    if (!result.rows.length) return null;

    const revocationResult = await db.query<RevokedSessionRow>(
      `select tenant_id, agent_id, session_id, revoked_at, reason, triggered_by, layers
         from monolith.revoked_sessions
        where tenant_id = $1 and agent_id = $2 and session_id = $3
        limit 1`,
      [tenantId, agent, session],
    );
    const revRow = revocationResult.rows[0] ? toSessionRevocation(revocationResult.rows[0]) : null;

    const layers = result.rows.map((r) => ({
      module: r.module,
      events: Number(r.events),
      worst: r.worst,
    }));
    return {
      tenant_id: tenantId,
      session_id: session,
      agent_id: agent,
      layers,
      total: layers.reduce((sum, l) => sum + l.events, 0),
      cross_layer: layers.length > 1,
      first_ms: Math.min(...result.rows.map((r) => Number(r.first_ms))),
      last_ms: Math.max(...result.rows.map((r) => Number(r.last_ms))),
      revoked: Boolean(revRow),
      revocation: revRow
        ? {
            revoked_at: revRow.revoked_at,
            reason: revRow.reason,
            triggered_by: revRow.triggered_by,
            layers: revRow.layers,
          }
        : undefined,
    };
  });
}

// --- Cryptographically signed forensic evidence bundles (DASH-4) ------------

export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((key) => obj[key] !== undefined)
    .sort();
  const entries = keys.map((key) => `${JSON.stringify(key)}:${canonicalizeJson(obj[key])}`);
  return `{${entries.join(",")}}`;
}

export function computeEvidenceIntegrity(
  bundleWithoutIntegrity: Record<string, unknown>,
  env: NodeJS.ProcessEnv = process.env,
): EvidenceIntegrity {
  const canonical = canonicalizeJson(bundleWithoutIntegrity);
  const canonicalSha256 = createHash("sha256").update(canonical, "utf8").digest("hex");
  const secret =
    env.MONOLITH_EVIDENCE_SIGNING_SECRET?.trim()
    || env.MONOLITH_ALERT_WEBHOOK_SECRET?.trim()
    || "";
  if (secret.length >= 32 && !/[\r\n\0]/.test(secret)) {
    const signature = createHmac("sha256", secret).update(canonical, "utf8").digest("hex");
    return {
      algorithm: "HMAC-SHA256",
      canonical_sha256: canonicalSha256,
      signature,
    };
  }
  return {
    algorithm: "SHA-256",
    canonical_sha256: canonicalSha256,
    signature: null,
  };
}

export async function exportIncidentEvidence(
  eventId: string,
  tenantId: string,
  actor = "system",
  env: NodeJS.ProcessEnv = process.env,
): Promise<EvidenceBundle | null> {
  const [incident, audit, session] = await Promise.all([
    getIncident(eventId, tenantId),
    getAuditTrail(eventId, tenantId),
    sessionForEvent(eventId, tenantId),
  ]);
  if (!incident) return null;

  const basePayload = {
    format: "project-black-monolith/evidence-bundle@1" as const,
    exported_at: new Date().toISOString(),
    exported_by: actor,
    tenant_id: tenantId,
    incident,
    audit,
    session,
  };
  const integrity = computeEvidenceIntegrity(basePayload, env);
  return {
    ...basePayload,
    integrity,
  };
}

/** Sessions that more than one defense layer has flagged. */
export async function crossLayerSessionCount(tenantId: string): Promise<number> {
  return withTenantDb(tenantId, async (db) => {
    const result = await db.query<{ n: string }>(
      `select count(*)::bigint as n from (
         select agent_id, session_id from monolith.security_events
         where tenant_id = $1 and agent_id is not null and session_id is not null
         group by agent_id, session_id
         having count(distinct module) > 1
       ) s`,
      [tenantId],
    );
    return Number(result.rows[0]?.n ?? 0);
  });
}

export interface ObservedAccuracy {
  module: string;
  true_positive: number;
  false_positive: number;
  benign: number;
  duplicate: number;
  /** Verdicts counted toward precision (true + false positives only). */
  scored: number;
  /** null until at least one incident has been resolved as true or false. */
  precision: number | null;
}

/**
 * Precision as observed in operation, derived from analysts' resolution
 * verdicts.
 *
 * This is the reason resolving an incident requires a verdict at all: a
 * benchmark measures a detector against a corpus we wrote, whereas this
 * measures it against whatever actually happened, judged by whoever handled
 * it. The two belong side by side — agreement is evidence the corpus is
 * representative, and divergence is a finding either way.
 *
 * `benign` and `duplicate` are counted and reported but deliberately excluded
 * from the denominator. Neither says the detector was wrong: "benign" means it
 * saw a real thing that needed no action, and "duplicate" means it saw the same
 * real thing twice. Folding either into precision would let good triage hygiene
 * look like a detector regression.
 */
export async function observedAccuracy(tenantId: string): Promise<ObservedAccuracy[]> {
  return withTenantDb(tenantId, async (db) => {
    const result = await db.query<{
      module: string;
      tp: string;
      fp: string;
      benign: string;
      duplicate: string;
    }>(
      `select e.module,
              count(*) filter (where t.resolution = 'true_positive')::bigint  as tp,
              count(*) filter (where t.resolution = 'false_positive')::bigint as fp,
              count(*) filter (where t.resolution = 'benign')::bigint         as benign,
              count(*) filter (where t.resolution = 'duplicate')::bigint      as duplicate
         from monolith.security_events e
         join monolith.incident_triage t using (event_id)
        where e.tenant_id = $1
          and t.status = 'resolved'
          and t.resolution is not null
        group by e.module
        order by e.module`,
      [tenantId],
    );
    return result.rows.map((row) => {
      const truePositive = Number(row.tp);
      const falsePositive = Number(row.fp);
      const scored = truePositive + falsePositive;
      return {
        module: row.module,
        true_positive: truePositive,
        false_positive: falsePositive,
        benign: Number(row.benign),
        duplicate: Number(row.duplicate),
        scored,
        precision: scored === 0 ? null : truePositive / scored,
      };
    });
  });
}

/** Counts for the queue's status tabs, in one round trip. */
export async function incidentCounts(tenantId: string): Promise<Record<string, number>> {
  return withTenantDb(tenantId, async (db) => {
    const result = await db.query<{ status: string; n: string }>(
      `select coalesce(t.status, 'new') as status, count(*)::bigint as n
       from monolith.security_events e
       left join monolith.incident_triage t using (event_id)
       where e.tenant_id = $1
       group by 1`,
      [tenantId],
    );
    const counts: Record<string, number> = { new: 0, acknowledged: 0, resolved: 0 };
    for (const row of result.rows) counts[row.status] = Number(row.n);
    counts.open = counts.new + counts.acknowledged;
    counts.all = counts.open + counts.resolved;
    return counts;
  });
}

// --- writes ----------------------------------------------------------------

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function text(value: unknown, max: number, field: string): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") throw new IncidentInputError(`${field} must be a string`);
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  if (trimmed.length > max) {
    throw new IncidentInputError(`${field} must be at most ${max} characters`);
  }
  return trimmed;
}

export interface TransitionInput {
  event_id: unknown;
  status: unknown;
  assignee?: unknown;
  /** Assign to the authenticated operator. The client cannot name itself, so
   *  "take this" has to be a request rather than a value it supplies. */
  assign_to_me?: unknown;
  note?: unknown;
  resolution?: unknown;
}

export interface Transition {
  event_id: string;
  tenant_id: string;
  status: IncidentStatus;
  actor: string;
  assignee?: string;
  note?: string;
  resolution?: Resolution;
}

/**
 * Validate a triage transition.
 *
 * `actor` is supplied by the caller from the authenticated credential and is
 * deliberately NOT read from the request body: a self-declared actor records
 * only what the caller wished to be called, which is worse than no audit trail,
 * because it looks like evidence.
 */
export function normalizeTransition(raw: unknown, actor: string, tenantId: string): Transition {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new IncidentInputError("body must be a JSON object");
  }
  const value = raw as TransitionInput;

  const eventId = text(value.event_id, 64, "event_id");
  if (!eventId || !UUID_PATTERN.test(eventId)) {
    throw new IncidentInputError("event_id must be a UUID");
  }
  if (!INCIDENT_STATUSES.includes(value.status as IncidentStatus)) {
    throw new IncidentInputError(`status must be one of ${INCIDENT_STATUSES.join(", ")}`);
  }
  const status = value.status as IncidentStatus;

  const resolvedActor = text(actor, MAX_ACTOR, "actor");
  if (!resolvedActor) throw new IncidentInputError("actor is required");

  const resolution = text(value.resolution, 32, "resolution") as Resolution | undefined;
  if (resolution && !RESOLUTIONS.includes(resolution)) {
    throw new IncidentInputError(`resolution must be one of ${RESOLUTIONS.join(", ")}`);
  }
  // Mirrors the CHECK constraint, so a bad request is a 422 from the app
  // rather than a 500 surfacing a raw constraint violation.
  if (status === "resolved" && !resolution) {
    throw new IncidentInputError("resolving an incident requires a resolution");
  }
  if (status !== "resolved" && resolution) {
    throw new IncidentInputError("resolution only applies when resolving");
  }

  // "Take this" resolves to the authenticated operator server-side, for the
  // same reason `actor` does: the client has no trustworthy name for itself.
  const assignToMe = value.assign_to_me === true;
  const explicitAssignee = text(value.assignee, MAX_ASSIGNEE, "assignee");
  if (assignToMe && explicitAssignee) {
    throw new IncidentInputError("assign_to_me and assignee are mutually exclusive");
  }

  return {
    event_id: eventId,
    tenant_id: tenantId,
    status,
    actor: resolvedActor,
    assignee: assignToMe ? resolvedActor : explicitAssignee,
    note: text(value.note, MAX_NOTE, "note"),
    resolution,
  };
}

export class UnknownEventError extends Error {}

/**
 * Apply a triage transition and record it in the append-only audit trail, in
 * one transaction — a state change that is not accounted for in the trail
 * would defeat the point of having one.
 */
export async function applyTransition(t: Transition): Promise<{ triage: Triage }> {
  if (!process.env.DATABASE_URL) {
    const found = getMemoryEventsForTenant(t.tenant_id).find((e) => e.event_id === t.event_id);
    if (!found) throw new UnknownEventError(t.event_id);
    const prev = memoryTriageMap().get(t.event_id);
    const triage: Triage = {
      status: t.status,
      assignee: t.assignee ?? prev?.assignee,
      note: t.note ?? prev?.note,
      resolution: t.resolution,
      updated_ms: Date.now(),
      updated_by: t.actor,
    };
    memoryTriageMap().set(t.event_id, triage);
    const trail = memoryAuditMap().get(t.event_id) ?? [];
    const nextId = (memoryIncidentRef.__monolithNextAuditId = (memoryIncidentRef.__monolithNextAuditId ?? 0) + 1);
    trail.unshift({
      audit_id: nextId,
      at_ms: triage.updated_ms,
      actor: t.actor,
      from_status: prev?.status,
      to_status: t.status,
      assignee: triage.assignee,
      resolution: t.resolution,
      note: t.note,
    });
    memoryAuditMap().set(t.event_id, trail);
    return { triage };
  }

  return withTenantDb(t.tenant_id, async (client) => {
    // Serialize all transitions for this event, including the first one before
    // a triage row exists. A shared event-row lock does not serialize two
    // writers, and granting UPDATE on immutable evidence merely to take an
    // exclusive row lock would violate the runtime role boundary. The
    // transaction-scoped advisory lock gives us one writer per event without
    // expanding table privileges. A hash collision can only over-serialize.
    await client.query(
      "select pg_advisory_xact_lock(hashtextextended($1, 0))",
      [t.event_id],
    );

    // Scope existence to the authenticated tenant so an event id from another
    // tenant is indistinguishable from an unknown id.
    const exists = await client.query(
      `select 1 from monolith.security_events
       where event_id = $1 and tenant_id = $2`,
      [t.event_id, t.tenant_id],
    );
    if (!exists.rowCount) throw new UnknownEventError(t.event_id);

    const previous = await client.query<{ status: IncidentStatus }>(
      "select status from monolith.incident_triage where event_id = $1 for update",
      [t.event_id],
    );
    const fromStatus = previous.rows[0]?.status ?? null;

    const upserted = await client.query<{
      status: IncidentStatus;
      assignee: string | null;
      note: string | null;
      resolution: Resolution | null;
      updated_ms: string;
      updated_by: string;
    }>(
      `insert into monolith.incident_triage
         (event_id, status, assignee, note, resolution, updated_by, updated_at)
       values ($1, $2, $3, $4, $5, $6, now())
       on conflict (event_id) do update set
         status = excluded.status,
         -- Omitting a field means "leave it alone", not "clear it". Without
         -- the coalesce, resolving an incident without restating the assignee
         -- would silently unassign it and lose who owned the call.
         assignee = coalesce(excluded.assignee, monolith.incident_triage.assignee),
         note = coalesce(excluded.note, monolith.incident_triage.note),
         -- Resolution is the exception: it is scoped to the resolved state, and
         -- normalizeTransition rejects it on any other status, so reopening
         -- must clear the old verdict rather than carry it forward.
         resolution = excluded.resolution,
         updated_by = excluded.updated_by,
         updated_at = now()
       returning status, assignee, note, resolution,
                 (extract(epoch from updated_at) * 1000)::bigint as updated_ms,
                 updated_by`,
      [t.event_id, t.status, t.assignee ?? null, t.note ?? null, t.resolution ?? null, t.actor],
    );
    const row = upserted.rows[0];

    // Record the *resulting* assignee, not the one supplied on this request:
    // the trail should read as the state each transition left behind.
    await client.query(
      `insert into monolith.incident_audit
         (event_id, actor, from_status, to_status, assignee, resolution, note)
       values ($1, $2, $3, $4, $5, $6, $7)`,
      [t.event_id, t.actor, fromStatus, t.status, row.assignee, t.resolution ?? null, t.note ?? null],
    );

    return {
      triage: {
        status: row.status,
        assignee: row.assignee ?? undefined,
        note: row.note ?? undefined,
        resolution: row.resolution ?? undefined,
        updated_ms: Number(row.updated_ms),
        updated_by: row.updated_by,
      },
    };
  });
}

export function isKnownModule(module: string): boolean {
  return KNOWN_MODULES.has(module);
}

export function isSeverity(value: string): value is Severity {
  return SEVERITIES.has(value as Severity);
}
