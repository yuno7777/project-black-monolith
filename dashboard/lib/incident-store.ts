import { getDb } from "@/lib/db";
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
  correlation_id: string | null;
  session_id: string | null;
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
    correlation_id: row.correlation_id ?? undefined,
    session_id: row.session_id ?? undefined,
    agent_id: row.agent_id ?? undefined,
    outcome: row.outcome ?? undefined,
    triage,
  };
}

export interface IncidentQuery {
  status?: IncidentStatus | "open" | "all" | "triaged";
  severity?: Severity | "all";
  module?: string | "all";
  q?: string;
  since_ms?: number;
  limit?: number;
}

export async function listIncidents(query: IncidentQuery = {}): Promise<Incident[]> {
  const where: string[] = [];
  const params: unknown[] = [];
  const add = (value: unknown) => `$${params.push(value)}`;

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
  if (query.q) {
    // Free text across the fields an analyst would actually search by. The
    // details cast lets a search hit inside the payload (e.g. a tool name).
    const needle = add(`%${query.q}%`);
    where.push(`(
      e.event_type ilike ${needle}
      or e.module ilike ${needle}
      or e.severity ilike ${needle}
      or coalesce(t.assignee, '') ilike ${needle}
      or coalesce(e.correlation_id, '') ilike ${needle}
      or e.details::text ilike ${needle}
    )`);
  }

  const limit = Math.max(1, Math.min(query.limit ?? 200, 1_000));

  const result = await getDb().query<IncidentRow>(
    `select
       e.event_id, e.schema_version, e.occurred_at_ms,
       (extract(epoch from e.received_at) * 1000)::bigint as received_ms,
       e.module, e.event_type, e.severity, e.details,
       e.correlation_id, e.session_id, e.agent_id, e.outcome,
       t.status, t.assignee, t.note, t.resolution,
       (extract(epoch from t.updated_at) * 1000)::bigint as updated_ms,
       t.updated_by
     from monolith.security_events e
     left join monolith.incident_triage t using (event_id)
     ${where.length ? `where ${where.join(" and ")}` : ""}
     order by
       -- Worst-first, then newest-first: the queue should open on the thing
       -- that matters most, not merely the thing that happened last.
       case e.severity when 'critical' then 0 when 'warning' then 1 else 2 end,
       e.received_at desc
     limit ${add(limit)}`,
    params,
  );
  return result.rows.map(toIncident);
}

export async function getAuditTrail(eventId: string): Promise<AuditEntry[]> {
  const result = await getDb().query<{
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
     from monolith.incident_audit
     where event_id = $1
     order by at desc, audit_id desc`,
    [eventId],
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
}

/** Counts for the queue's status tabs, in one round trip. */
export async function incidentCounts(): Promise<Record<string, number>> {
  const result = await getDb().query<{ status: string; n: string }>(
    `select coalesce(t.status, 'new') as status, count(*)::bigint as n
     from monolith.security_events e
     left join monolith.incident_triage t using (event_id)
     group by 1`,
  );
  const counts: Record<string, number> = { new: 0, acknowledged: 0, resolved: 0 };
  for (const row of result.rows) counts[row.status] = Number(row.n);
  counts.open = counts.new + counts.acknowledged;
  counts.all = counts.open + counts.resolved;
  return counts;
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
  actor: unknown;
  assignee?: unknown;
  note?: unknown;
  resolution?: unknown;
}

export interface Transition {
  event_id: string;
  status: IncidentStatus;
  actor: string;
  assignee?: string;
  note?: string;
  resolution?: Resolution;
}

export function normalizeTransition(raw: unknown): Transition {
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

  const actor = text(value.actor, MAX_ACTOR, "actor");
  if (!actor) throw new IncidentInputError("actor is required");

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

  return {
    event_id: eventId,
    status,
    actor,
    assignee: text(value.assignee, MAX_ASSIGNEE, "assignee"),
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
  const db = getDb();
  const client = await db.connect();
  try {
    await client.query("begin");

    // Lock the event row so two concurrent transitions serialize, and so a
    // transition against an unknown event_id is a clean 404 rather than a
    // foreign-key 500.
    const exists = await client.query(
      "select 1 from monolith.security_events where event_id = $1 for share",
      [t.event_id],
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

    await client.query("commit");

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
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

export function isKnownModule(module: string): boolean {
  return KNOWN_MODULES.has(module);
}

export function isSeverity(value: string): value is Severity {
  return SEVERITIES.has(value as Severity);
}
