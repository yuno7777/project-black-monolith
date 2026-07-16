import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { getDb } from "@/lib/db";
import type { MonolithEvent, Severity } from "@/lib/types";

const knownModules = new Set(["mcp-shield", "vector-anchor", "trace-audit"]);
const severities = new Set<Severity>(["info", "warning", "critical"]);
const MAX_TEXT_LENGTH = 512;
// security_events.event_id is a Postgres `uuid`. A supplied id that is not a
// UUID would fail the insert with 22P02, surface as a 503, and be retried
// forever by the module outboxes (which correctly treat 5xx as transient) —
// a poison pill that blocks the spool behind it. Reject it as a permanent
// 422 instead. A malformed id is not silently replaced with a fresh one:
// event_id is the idempotency key, so regenerating it on every retry would
// let a redelivered event insert duplicates.
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function optionalText(value: unknown): string | undefined {
  return typeof value === "string" && value.length <= MAX_TEXT_LENGTH && value.length > 0
    ? value
    : undefined;
}

function isDetails(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function normalizeEvent(raw: unknown): MonolithEvent {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("each event must be a JSON object");
  }
  const value = raw as Record<string, unknown>;
  const module = optionalText(value.module);
  if (!module || !knownModules.has(module)) {
    throw new Error("event.module must identify a known module");
  }
  const eventType = optionalText(value.event_type);
  if (!eventType) throw new Error("event.event_type is required");

  const severity = severities.has(value.severity as Severity)
    ? (value.severity as Severity)
    : "info";
  const timestamp = typeof value.timestamp_ms === "number" && Number.isFinite(value.timestamp_ms)
    ? Math.trunc(value.timestamp_ms)
    : Date.now();
  const suppliedEventId = optionalText(value.event_id);
  if (suppliedEventId !== undefined && !UUID_PATTERN.test(suppliedEventId)) {
    throw new Error("event.event_id must be a UUID");
  }

  return {
    event_id: suppliedEventId ?? randomUUID(),
    schema_version: value.schema_version === 2 ? 2 : 1,
    timestamp_ms: timestamp,
    module,
    event_type: eventType,
    severity,
    details: isDetails(value.details) ? value.details : {},
    agent_id: optionalText(value.agent_id),
    session_id: optionalText(value.session_id),
    trace_id: optionalText(value.trace_id),
    correlation_id: optionalText(value.correlation_id),
    resource_type: optionalText(value.resource_type),
    resource_id: optionalText(value.resource_id),
    outcome: optionalText(value.outcome),
    policy_version: optionalText(value.policy_version),
    source: optionalText(value.source) ?? "module",
  };
}

type EventRow = {
  event_id: string;
  schema_version: number;
  occurred_at_ms: string;
  received_ms: string;
  module: string;
  event_type: string;
  severity: Severity;
  details: Record<string, unknown>;
  agent_id: string | null;
  session_id: string | null;
  trace_id: string | null;
  correlation_id: string | null;
  resource_type: string | null;
  resource_id: string | null;
  outcome: string | null;
  policy_version: string | null;
  source: string;
};

function fromRow(row: EventRow): MonolithEvent {
  return {
    event_id: row.event_id,
    schema_version: row.schema_version === 2 ? 2 : 1,
    timestamp_ms: Number(row.occurred_at_ms),
    received_ms: Number(row.received_ms),
    module: row.module,
    event_type: row.event_type,
    severity: row.severity,
    details: row.details ?? {},
    agent_id: row.agent_id ?? undefined,
    session_id: row.session_id ?? undefined,
    trace_id: row.trace_id ?? undefined,
    correlation_id: row.correlation_id ?? undefined,
    resource_type: row.resource_type ?? undefined,
    resource_id: row.resource_id ?? undefined,
    outcome: row.outcome ?? undefined,
    policy_version: row.policy_version ?? undefined,
    source: row.source,
  };
}

const returningColumns = `
  event_id, schema_version, occurred_at_ms,
  (extract(epoch from received_at) * 1000)::bigint as received_ms,
  module, event_type, severity, details, agent_id, session_id, trace_id,
  correlation_id, resource_type, resource_id, outcome, policy_version, source
`;

async function insertWithClient(client: PoolClient, event: MonolithEvent) {
  const result = await client.query<EventRow>(
    `insert into monolith.security_events (
      event_id, schema_version, occurred_at_ms, module, event_type, severity, details,
      agent_id, session_id, trace_id, correlation_id, resource_type, resource_id,
      outcome, policy_version, source
    ) values (
      $1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12, $13, $14, $15, $16
    ) on conflict (event_id) do nothing returning ${returningColumns}`,
    [
      event.event_id, event.schema_version, event.timestamp_ms, event.module,
      event.event_type, event.severity, JSON.stringify(event.details), event.agent_id ?? null,
      event.session_id ?? null, event.trace_id ?? null, event.correlation_id ?? null,
      event.resource_type ?? null, event.resource_id ?? null, event.outcome ?? null,
      event.policy_version ?? null, event.source ?? "module",
    ],
  );
  return result.rows[0] ? { inserted: true, event: fromRow(result.rows[0]) } : { inserted: false, event };
}

export async function persistEvents(events: MonolithEvent[]) {
  const db = getDb();
  const client = await db.connect();
  try {
    await client.query("begin");
    const results = [];
    for (const event of events) results.push(await insertWithClient(client, event));
    await client.query("commit");
    return results;
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

export async function listRecentEvents(limit = 500): Promise<MonolithEvent[]> {
  const safeLimit = Math.max(1, Math.min(limit, 1_000));
  const result = await getDb().query<EventRow>(
    `select ${returningColumns} from monolith.security_events
     order by received_at desc limit $1`,
    [safeLimit],
  );
  return result.rows.map(fromRow);
}

export async function checkDatabase() {
  await getDb().query("select 1");
}
