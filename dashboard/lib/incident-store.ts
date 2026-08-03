import { withTenantDb } from "@/lib/db";
import type {
  AuditEntry,
  Incident,
  IncidentStatus,
  Resolution,
  Severity,
  Triage,
} from "@/lib/types";
import { INCIDENT_STATUSES, RESOLUTIONS } from "@/lib/types";

const KNOWN_MODULES = new Set(["mcp-shield", "vector-anchor", "trace-audit"]);
const SEVERITIES = new Set<Severity>(["info", "warning", "critical"]);
const MAX_ASSIGNEE = 128;
const MAX_NOTE = 2000;
const MAX_ACTOR = 128;

export class IncidentInputError extends Error {}

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

export interface SessionLayer {
  module: string;
  events: number;
  worst: Severity;
}

export interface SessionView {
  tenant_id: string;
  session_id: string;
  agent_id: string;
  layers: SessionLayer[];
  total: number;
  /** True once more than one defense layer has flagged the same session. */
  cross_layer: boolean;
  first_ms: number;
  last_ms: number;
}

/**
 * What else happened in this event's agent session.
 *
 * This is the query the whole correlation effort exists for. One module firing
 * is a detection; the same session tripping the tool, memory *and* reasoning
 * layers is a compromised agent, and no single module can see that.
 */
export async function sessionForEvent(eventId: string, tenantId: string): Promise<SessionView | null> {
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
    };
  });
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
