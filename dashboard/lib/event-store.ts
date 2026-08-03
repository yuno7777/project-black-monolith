import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { getDb, withTenantDb } from "@/lib/db";
import type { MonolithEvent, Severity } from "@/lib/types";

const knownModules = new Set(["mcp-shield", "vector-anchor", "trace-audit"]);
const severities = new Set<Severity>(["info", "warning", "critical"]);
const MAX_TEXT_LENGTH = 512;
const MAX_ID_LENGTH = 128;
const MAX_EVENT_TIMESTAMP_MS = 32_503_680_000_000; // 3000-01-01 UTC
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;
// security_events.event_id is a Postgres `uuid`. A supplied id that is not a
// UUID would fail the insert with 22P02, surface as a 503, and be retried
// forever by the module outboxes (which correctly treat 5xx as transient) —
// a poison pill that blocks the spool behind it. Reject it as a permanent
// 422 instead. A malformed id is not silently replaced with a fresh one:
// event_id is the idempotency key, so regenerating it on every retry would
// let a redelivered event insert duplicates.
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function optionalText(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") throw new Error("event text fields must be strings");
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > MAX_TEXT_LENGTH || CONTROL_CHARACTERS.test(trimmed)) {
    throw new Error(`event text fields must be printable and at most ${MAX_TEXT_LENGTH} characters`);
  }
  return trimmed;
}

function identityText(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") {
    throw new Error(`event.${field} must be a string`);
  }
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > MAX_ID_LENGTH) {
    throw new Error(`event.${field} must be between 1 and ${MAX_ID_LENGTH} characters`);
  }
  return trimmed;
}

function isDetails(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function normalizeEvent(raw: unknown): MonolithEvent {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("each event must be a JSON object");
  }
  const value = raw as Record<string, unknown>;
  const moduleName = optionalText(value.module);
  if (!moduleName || !knownModules.has(moduleName)) {
    throw new Error("event.module must identify a known module");
  }
  const eventType = optionalText(value.event_type);
  if (!eventType) throw new Error("event.event_type is required");

  let severity: Severity = "info";
  if (value.severity !== undefined) {
    if (!severities.has(value.severity as Severity)) {
      throw new Error("event.severity must be info, warning, or critical");
    }
    severity = value.severity as Severity;
  }
  let timestamp = Date.now();
  if (value.timestamp_ms !== undefined) {
    if (
      typeof value.timestamp_ms !== "number"
      || !Number.isSafeInteger(value.timestamp_ms)
      || value.timestamp_ms < 1
      || value.timestamp_ms > MAX_EVENT_TIMESTAMP_MS
    ) {
      throw new Error("event.timestamp_ms must be a supported positive Unix timestamp");
    }
    timestamp = value.timestamp_ms;
  }
  if (value.schema_version !== undefined && value.schema_version !== 1 && value.schema_version !== 2) {
    throw new Error("event.schema_version must be 1 or 2");
  }
  if (value.details !== undefined && !isDetails(value.details)) {
    throw new Error("event.details must be a JSON object");
  }
  let eventId: string = randomUUID();
  if (value.event_id !== undefined && value.event_id !== null) {
    if (typeof value.event_id !== "string" || !UUID_PATTERN.test(value.event_id)) {
      throw new Error("event.event_id must be a UUID");
    }
    eventId = value.event_id;
  }

  return {
    event_id: eventId,
    schema_version: value.schema_version === 2 ? 2 : 1,
    timestamp_ms: timestamp,
    module: moduleName,
    event_type: eventType,
    severity,
    details: value.details ?? {},
    tenant_id: identityText(value.tenant_id, "tenant_id") ?? "default",
    agent_id: identityText(value.agent_id, "agent_id"),
    session_id: identityText(value.session_id, "session_id"),
    trace_id: identityText(value.trace_id, "trace_id"),
    correlation_id: identityText(value.correlation_id, "correlation_id"),
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
  tenant_id: string;
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
    tenant_id: row.tenant_id,
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
  correlation_id, resource_type, resource_id, outcome, policy_version, source,
  tenant_id
`;

async function insertWithClient(client: PoolClient, event: MonolithEvent) {
  const result = await client.query<EventRow>(
    `insert into monolith.security_events (
      event_id, schema_version, occurred_at_ms, module, event_type, severity, details,
      agent_id, session_id, trace_id, correlation_id, resource_type, resource_id,
      outcome, policy_version, source, tenant_id
    ) values (
      $1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
    ) on conflict (event_id) do nothing returning ${returningColumns}`,
    [
      event.event_id, event.schema_version, event.timestamp_ms, event.module,
      event.event_type, event.severity, JSON.stringify(event.details), event.agent_id ?? null,
      event.session_id ?? null, event.trace_id ?? null, event.correlation_id ?? null,
      event.resource_type ?? null, event.resource_id ?? null, event.outcome ?? null,
      event.policy_version ?? null, event.source ?? "module",
      event.tenant_id,
    ],
  );
  return result.rows[0] ? { inserted: true, event: fromRow(result.rows[0]) } : { inserted: false, event };
}

export async function persistEvents(events: MonolithEvent[]) {
  if (!events.length) return [];
  const tenantId = events[0].tenant_id;
  if (events.some((event) => event.tenant_id !== tenantId)) {
    throw new Error("one database transaction cannot span tenants");
  }
  return withTenantDb(tenantId, async (client) => {
    const results = [];
    for (const event of events) results.push(await insertWithClient(client, event));
    return results;
  });
}

export async function listRecentEvents(
  tenantId: string,
  limit = 500,
  afterEventId?: string,
): Promise<MonolithEvent[]> {
  const safeLimit = Math.max(1, Math.min(limit, 1_000));
  const cursor = afterEventId && UUID_PATTERN.test(afterEventId) ? afterEventId : null;
  return withTenantDb(tenantId, async (db) => {
    const result = await db.query<EventRow>(
      `with cursor as (
         select received_at, event_id from monolith.security_events
         where tenant_id = $1 and event_id = $3::uuid
       )
       select ${returningColumns} from monolith.security_events e
       where e.tenant_id = $1
         and (
           $3::uuid is null
           or not exists (select 1 from cursor)
           or (e.received_at, e.event_id) > (
             select received_at, event_id from cursor
           )
         )
       order by e.received_at desc, e.event_id desc limit $2`,
      [tenantId, safeLimit, cursor],
    );
    return result.rows.map(fromRow);
  });
}

export async function findEventById(
  tenantId: string,
  eventId: string,
): Promise<MonolithEvent | null> {
  if (!UUID_PATTERN.test(eventId)) return null;
  return withTenantDb(tenantId, async (db) => {
    const result = await db.query<EventRow>(
      `select ${returningColumns} from monolith.security_events
       where tenant_id = $1 and event_id = $2::uuid limit 1`,
      [tenantId, eventId],
    );
    return result.rows[0] ? fromRow(result.rows[0]) : null;
  });
}

export async function checkDatabase() {
  await getDb().query("select 1");
}
