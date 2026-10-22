import type { PoolClient } from "pg";
import { getDb, withTenantDb } from "@/lib/db";
import type { MonolithEvent, Severity } from "@/lib/types";
import { alertConfigStatus } from "@/lib/alert-config";

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
//
// A *missing* id is refused for the same reason, and the published contract
// already says so: `contracts/schemas/event-envelope.v2.schema.json` lists
// `event_id` as required. Minting one here would be the dashboard inventing
// an identity the module is supposed to own, and it would invent a different
// one on every redelivery — so a delivery whose answer was lost would be
// filed twice, under two identities, and the ledger's `on conflict
// (event_id) do nothing` would not catch it. The id is the module's.
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const memoryRef = globalThis as unknown as {
  __monolithMemoryEvents?: Map<string, MonolithEvent>;
};

function memoryEventMap(): Map<string, MonolithEvent> {
  if (!memoryRef.__monolithMemoryEvents) {
    memoryRef.__monolithMemoryEvents = new Map<string, MonolithEvent>();
  }
  return memoryRef.__monolithMemoryEvents;
}

export function getMemoryEventsForTenant(tenantId: string): MonolithEvent[] {
  const result: MonolithEvent[] = [];
  for (const event of memoryEventMap().values()) {
    if (event.tenant_id === tenantId) result.push(event);
  }
  return result;
}

export function clearMemoryEvents(): void {
  memoryEventMap().clear();
}

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
  if (!trimmed || trimmed.length > MAX_ID_LENGTH || CONTROL_CHARACTERS.test(trimmed)) {
    throw new Error(
      `event.${field} must be printable and between 1 and ${MAX_ID_LENGTH} characters`,
    );
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
  let eventId: string;
  if (typeof value.event_id !== "string" || !UUID_PATTERN.test(value.event_id)) {
    throw new Error("event.event_id must be a UUID");
  }
  eventId = value.event_id;

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

/**
 * Write the alert job for a critical event, without letting a failure there
 * roll back the evidence it was raised for.
 *
 * The job and the detection used to share one transaction, so a transient
 * `alert_outbox` error — a missing table after a partial migration, an RLS
 * check mismatch, a payload-size failure — aborted the transaction and
 * destroyed the detection instead of delaying the notification. The ingest
 * route then answered 503, and the module retried an event that was
 * perfectly valid until it dead-lettered it.
 *
 * A savepoint keeps the two together when both succeed — the job and the
 * evidence still commit as one — and separates them when the job cannot be
 * written. The alert is a reaction to the evidence, not a precondition for
 * accepting it; the same reasoning the ingest route already applies to the
 * circuit breaker.
 */
async function enqueueAlertJob(client: PoolClient, event: MonolithEvent): Promise<boolean> {
  await client.query("savepoint monolith_alert_job");
  try {
    await client.query(
      `insert into monolith.alert_outbox (event_id, tenant_id, payload)
       values ($1::uuid, $2, $3::jsonb)
       on conflict (event_id) do nothing`,
      [event.event_id, event.tenant_id, JSON.stringify(event)],
    );
    await client.query("release savepoint monolith_alert_job");
    return true;
  } catch (error) {
    try {
      await client.query("rollback to savepoint monolith_alert_job");
    } catch {
      // The connection is unusable, so the caller will roll the whole
      // transaction back anyway. There is nothing left to preserve.
    }
    console.error("alert job could not be written; the detection is preserved", error);
    return false;
  }
}

export async function insertEventWithClient(client: PoolClient, event: MonolithEvent) {
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
  if (!result.rows[0]) return { inserted: false, event };
  const persisted = fromRow(result.rows[0]);
  if (persisted.severity === "critical" && alertConfigStatus().enabled) {
    await enqueueAlertJob(client, persisted);
  }
  return { inserted: true, event: persisted };
}

export async function persistEvents(events: MonolithEvent[]) {
  if (!events.length) return [];
  const tenantId = events[0].tenant_id;
  if (events.some((event) => event.tenant_id !== tenantId)) {
    throw new Error("one database transaction cannot span tenants");
  }
  if (!process.env.DATABASE_URL) {
    const store = memoryEventMap();
    return events.map((event) => {
      if (store.has(event.event_id)) {
        return { inserted: false, event: store.get(event.event_id)! };
      }
      const stored: MonolithEvent = {
        ...event,
        received_ms: event.received_ms ?? Date.now(),
      };
      store.set(stored.event_id, stored);
      return { inserted: true, event: stored };
    });
  }
  return withTenantDb(tenantId, async (client) => {
    const results = [];
    for (const event of events) results.push(await insertEventWithClient(client, event));
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
  if (!process.env.DATABASE_URL) {
    const events = getMemoryEventsForTenant(tenantId).sort(
      (a, b) => (b.received_ms ?? b.timestamp_ms) - (a.received_ms ?? a.timestamp_ms),
    );
    return events.slice(0, safeLimit);
  }
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
  if (!process.env.DATABASE_URL) {
    const found = memoryEventMap().get(eventId);
    return found && found.tenant_id === tenantId ? found : null;
  }
  return withTenantDb(tenantId, async (db) => {
    const result = await db.query<EventRow>(
      `select ${returningColumns} from monolith.security_events
       where tenant_id = $1 and event_id = $2::uuid limit 1`,
      [tenantId, eventId],
    );
    return result.rows[0] ? fromRow(result.rows[0]) : null;
  });
}

export async function findEventsByIds(
  tenantId: string,
  eventIds: string[],
): Promise<MonolithEvent[]> {
  const validIds = Array.from(new Set(eventIds.filter((id) => UUID_PATTERN.test(id))));
  if (!validIds.length) return [];
  if (validIds.length === 1) {
    const single = await findEventById(tenantId, validIds[0]);
    return single ? [single] : [];
  }
  if (!process.env.DATABASE_URL) {
    const store = memoryEventMap();
    return validIds
      .map((id) => store.get(id))
      .filter((event): event is MonolithEvent => Boolean(event && event.tenant_id === tenantId));
  }
  return withTenantDb(tenantId, async (db) => {
    const result = await db.query<EventRow>(
      `select ${returningColumns} from monolith.security_events
       where tenant_id = $1 and event_id = any($2::uuid[])
       order by received_at asc, event_id asc`,
      [tenantId, validIds],
    );
    return result.rows.map(fromRow);
  });
}

export async function checkDatabase() {
  await getDb().query("select 1");
}
