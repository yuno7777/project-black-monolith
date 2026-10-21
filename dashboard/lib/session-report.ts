// The session report: everything one agent run did, and what it cost.
//
// The agent gateway mints a session id per run and hands it to all three
// layers, so the tool-layer, memory-layer and reasoning-layer detections for
// a run are filed under one key. This is the read side of that key.
//
// Two pieces, deliberately separate:
//
//   listSessionIncidents  a read, so it needs the ledger
//   summarizeSession      arithmetic over the result, so it does not
//
// The split means the interesting half — what counts as a detection, what
// counts as a block, what a run cost the agent — is a pure function that can
// be tested without a database, and the durable half stays a plain query.

import { withTenantDb } from "@/lib/db";
import { isDetectionEvent } from "@/lib/event-classification";
import { getMemoryEventsForTenant } from "@/lib/event-store";
import type { Incident, Severity } from "@/lib/types";

/** How many events one session report may carry. */
export const MAX_SESSION_EVENTS = 1_000;

/**
 * Outcomes that mean something did not reach the agent intact.
 *
 * The distinction is the one an operator cares about: a detection that was
 * reported but not enforced cost the agent nothing. The set is drawn from
 * the vocabulary the three modules actually emit —
 *
 *   blocked / blocked_first_contact   mcp-shield refused the tool call
 *   rewritten                         mcp-shield replaced a poisoned schema
 *   withheld / withheld_revoked /      mcp-shield and vector-anchor held
 *     withheld_pending_approval /       something back
 *     withheld_malformed
 *   filtered                          vector-anchor served the next clean hit
 *   quarantined                       vector-anchor quarantined a document
 *   terminated / refused              trace-audit cut the stream short
 *   denied / revoked                  an administrative decision
 *
 * Deliberately *not* in it: "redacted" (the answer was sanitized but still
 * delivered), "detected" (reported, no action taken), "served", "forwarded"
 * and "completed" (nothing was stopped).
 */
const BLOCKING_OUTCOMES = new Set([
  "blocked",
  "blocked_first_contact",
  "rewritten",
  "withheld",
  "withheld_revoked",
  "withheld_pending_approval",
  "withheld_malformed",
  "filtered",
  "quarantined",
  "terminated",
  "refused",
  "denied",
  "revoked",
]);

const QUARANTINE_EVENTS = new Set(["corpus_poison_quarantine"]);
const REVOCATION_EVENTS = new Set(["session_quarantined"]);

// What counts as a detection is decided in one place —
// `@/lib/event-classification` — because the console's headline number and
// this report both answer the same question and must answer it the same
// way. The rule, and the reason lifecycle and operational events are not
// findings, live with the list of every event type the layers emit.
//
// The short version: `retrieval` and `generation_completed` are the two an
// operator sees most of and would otherwise have to read past every time,
// and the operational failures — `upstream_stream_error` (the model provider
// broke), `generation_truncated` (the provider cut the answer short),
// `analysis_error` (mcp-shield could not analyse a message and forwarded it
// unmodified) and the rest — are all warnings, but a warning that means "the
// defense did not run" is not a warning that means "the defense found
// something". They stay in the report's event list, so nothing is hidden;
// and `generation_truncated` still counts as a block, because the agent did
// not get its answer.

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

export interface SessionSummary {
  /**
   * How many events the session has.
   *
   * Equal to the number of events counted unless the report was truncated,
   * in which case it is the session's true size and every other count here
   * is a lower bound.
   */
  total: number;
  /**
   * How many events the counts below were computed from.
   *
   * Equal to `total` unless the report was truncated, in which case the
   * counts cover this many events and `total` is the session's true size.
   * A reader that wants the ratio of detections to events needs this
   * number, not `total`.
   */
  counted: number;
  /** True when the cap dropped events, so the counts are a lower bound. */
  truncated: boolean;
  detections: number;
  blocks: number;
  quarantines: number;
  revocations: number;
  by_severity: Record<string, number>;
  by_module: Record<string, number>;
  by_event_type: Record<string, number>;
}

/** One page of a session's events, and how many the session really has. */
export interface SessionIncidentPage {
  /** The events, worst first, up to the cap. */
  incidents: Incident[];
  /** Every event the session produced, including the ones not returned. */
  total: number;
}

/** Worst-first, then newest-first — the order an operator reads a queue in. */
function orderIncidents(incidents: Incident[]): Incident[] {
  return [...incidents].sort((left, right) => {
    const rank = SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity];
    if (rank !== 0) return rank;
    const received = (right.received_ms ?? right.timestamp_ms) - (left.received_ms ?? left.timestamp_ms);
    if (received !== 0) return received;
    return left.event_id < right.event_id ? 1 : left.event_id > right.event_id ? -1 : 0;
  });
}

/**
 * Every event one agent session produced.
 *
 * A session is bounded by the run that created it, so there is no cursor
 * here: the whole session fits in one page. The cap is a safety net for
 * the session that does not, and a report that silently dropped its oldest
 * events would understate exactly the run an operator wants to look at —
 * so the page carries the session's true size alongside the events, and the
 * caller says so when the two differ.
 */
export async function listSessionIncidents(
  tenantId: string,
  sessionId: string,
  limit: number = MAX_SESSION_EVENTS,
): Promise<SessionIncidentPage> {
  const safeLimit = Math.max(1, Math.min(Math.trunc(limit), MAX_SESSION_EVENTS));

  if (!process.env.DATABASE_URL) {
    const matching: Incident[] = getMemoryEventsForTenant(tenantId)
      .filter((event) => event.session_id === sessionId)
      .map((event) => ({
        ...event,
        received_ms: event.received_ms ?? event.timestamp_ms,
      }));
    return { incidents: orderIncidents(matching).slice(0, safeLimit), total: matching.length };
  }

  return withTenantDb(tenantId, async (db) => {
    const result = await db.query<{
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
      source: string | null;
      resource_type: string | null;
      resource_id: string | null;
      policy_version: string | null;
      status: string | null;
      assignee: string | null;
      note: string | null;
      resolution: string | null;
      updated_ms: string | null;
      updated_by: string | null;
      total_count: string;
    }>(
      `select
         e.event_id, e.schema_version, e.occurred_at_ms,
         (extract(epoch from e.received_at) * 1000)::bigint as received_ms,
         e.module, e.event_type, e.severity, e.details, e.tenant_id,
         e.correlation_id, e.session_id, e.trace_id, e.agent_id, e.outcome,
         e.source, e.resource_type, e.resource_id, e.policy_version,
         t.status, t.assignee, t.note, t.resolution,
         (extract(epoch from t.updated_at) * 1000)::bigint as updated_ms,
         t.updated_by,
         (count(*) over ())::bigint as total_count
       from monolith.security_events e
       left join monolith.incident_triage t using (event_id)
       where e.tenant_id = $1 and e.session_id = $2
       order by
         case e.severity when 'critical' then 0 when 'warning' then 1 else 2 end,
         e.received_at desc,
         e.event_id desc
       limit $3`,
      [tenantId, sessionId, safeLimit],
    );
    const incidents: Incident[] = result.rows.map((row) => ({
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
      // The ledger carries these four and the in-memory path returns them,
      // so the Postgres path has to select them too: a report whose shape
      // depends on whether a database is configured is a report whose
      // fields go missing in exactly the deployment that stores the ledger.
      source: row.source ?? undefined,
      resource_type: row.resource_type ?? undefined,
      resource_id: row.resource_id ?? undefined,
      policy_version: row.policy_version ?? undefined,
      triage: row.status
        ? {
            status: row.status as never,
            assignee: row.assignee ?? undefined,
            note: row.note ?? undefined,
            resolution: (row.resolution ?? undefined) as never,
            updated_ms: Number(row.updated_ms),
            updated_by: row.updated_by ?? "unknown",
          }
        : undefined,
    }));
    // count(*) over () counts the whole session, not the page: it is
    // evaluated before the limit is applied.
    const total = result.rows.length > 0 ? Number(result.rows[0].total_count) : 0;
    return { incidents, total };
  });
}

/**
 * Reduce a session's events to the numbers a run is judged by.
 *
 * A *detection* is a finding: a warning or a critical that some defence
 * actually looked for and found, as decided by `@/lib/event-classification`.
 * A *block* is a finding that actually stopped something. The gap between
 * the two is the interesting number: a defense that detects a lot and blocks
 * nothing is a defense the agent walks straight through.
 */
export function summarizeSession(incidents: Incident[], sessionTotal?: number): SessionSummary {
  const bySeverity: Record<string, number> = { critical: 0, warning: 0, info: 0 };
  const byModule: Record<string, number> = {};
  const byEventType: Record<string, number> = {};
  let detections = 0;
  let blocks = 0;
  let quarantines = 0;
  let revocations = 0;

  for (const incident of incidents) {
    bySeverity[incident.severity] = (bySeverity[incident.severity] ?? 0) + 1;
    byModule[incident.module] = (byModule[incident.module] ?? 0) + 1;
    byEventType[incident.event_type] = (byEventType[incident.event_type] ?? 0) + 1;

    if (QUARANTINE_EVENTS.has(incident.event_type)) quarantines += 1;
    if (REVOCATION_EVENTS.has(incident.event_type)) revocations += 1;

    if (isDetectionEvent(incident)) {
      detections += 1;
    }

    if (
      BLOCKING_OUTCOMES.has(incident.outcome ?? "")
      || QUARANTINE_EVENTS.has(incident.event_type)
      || REVOCATION_EVENTS.has(incident.event_type)
    ) {
      blocks += 1;
    }
  }

  // When the page did not hold the whole session, the counts above are a
  // lower bound and the summary says so rather than reading as complete.
  const total =
    sessionTotal !== undefined && sessionTotal > incidents.length ? sessionTotal : incidents.length;
  return {
    total,
    counted: incidents.length,
    truncated: total > incidents.length,
    detections,
    blocks,
    quarantines,
    revocations,
    by_severity: bySeverity,
    by_module: byModule,
    by_event_type: byEventType,
  };
}
