// Event validation, persistence, and reads — the dashboard's "event ledger"
// data-access module.
//
// WHAT THIS FILE IS
// -----------------
// The receiver side of the shared event contract. When a module's outbox
// POSTs an event to /api/ingest, this file is what:
//   1. normalizeEvent() — strictly validates the envelope, field by field,
//      turning raw JSON into a typed MonolithEvent.
//   2. persistEvents() — inserts it into Postgres (idempotently), and if the
//      event is critical and a webhook is configured, queues an alert row in
//      the SAME transaction.
//   3. listRecentEvents() / findEventById() — read paths used by the SSE
//      replay and the live-event listener.
//
// THE REJECT-DON'T-COERCE POLICY (the most important design decision here)
// ------------------------------------------------------------------------
// Validation is deliberately STRICT. An unknown severity, a non-object
// `details`, or a malformed `event_id` is REJECTED with a 422 — never coerced
// to a "safe" value. Why: coercing an unknown severity to `info` would
// silently DOWNGRADE a finding, and coercing non-object details would discard
// the evidence the detection exists to carry. Only genuinely ABSENT optional
// fields are defaulted server-side (severity->info, timestamp->now,
// event_id->fresh UUID, tenant->"default").
//
// THE POISON-PILL FIX (know this for interviews)
// ----------------------------------------------
// security_events.event_id is a Postgres `uuid` column. A supplied non-UUID
// would fail the insert with error 22P02, surface as a 503, and be retried
// FOREVER by the module outboxes (which correctly treat 5xx as transient) —
// a "poison pill" that blocks the whole spool behind it. That is why a
// malformed supplied id is rejected as a permanent 422 here, and why it is
// NOT silently replaced with a fresh UUID: event_id is the idempotency key,
// and regenerating it on every retry would let a redelivered event insert
// duplicates.
//
// IDEMPOTENT REDELIVERY
// ---------------------
// The insert uses `on conflict (event_id) do nothing`. If a module redelivers
// an event after a timeout, the second insert is a no-op and the response
// reports it as a duplicate. This is what makes the whole "at-least-once"
// delivery contract safe.

import { randomUUID } from "node:crypto";
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
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function optionalText(value: unknown): string | undefined {
  // Text fields (event_type, resource_type, outcome, source, ...): must be
  // strings, printable (no control chars — protects logs and the SSE feed
  // from injection), and at most 512 chars.
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") throw new Error("event text fields must be strings");
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > MAX_TEXT_LENGTH || CONTROL_CHARACTERS.test(trimmed)) {
    throw new Error(`event text fields must be printable and at most ${MAX_TEXT_LENGTH} characters`);
  }
  return trimmed;
}

function identityText(value: unknown, field: string): string | undefined {
  // Correlation ids (tenant/agent/session/trace/correlation): must be
  // non-blank strings of at most 128 chars, mirroring the modules' own clamp
  // (python-common _clean_id).
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
  // Validate one raw event envelope. Called from: /api/ingest route
  // (route.ts) for every event in the batch. Throws on anything invalid —
  // the route catches and answers 422.
  //
  // Field-by-field rules (matching contracts/schemas/event-envelope.v2):
  //   module        required, must be a known module.
  //   event_type    required, printable text.
  //   severity      optional -> "info"; INVALID values rejected.
  //   timestamp_ms  optional -> now; INVALID (non-integer, out of range)
  //                 rejected.
  //   schema_version optional; must be 1 or 2 if present.
  //   details       optional -> {}; must be a JSON object if present.
  //   event_id      optional -> fresh UUID; a SUPPLIED non-UUID is rejected
  //                 (the poison-pill case above).
  //   tenant_id     optional -> "default"; bounded like the ids below.
  //   correlation fields: bounded strings when present.
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

// The DB row shape (received_at is a Postgres timestamptz, converted to ms).
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
  // Map a DB row back to the API shape (nulls -> undefined).
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

// Reused SELECT column list (with received_at converted to ms).
const returningColumns = `
  event_id, schema_version, occurred_at_ms,
  (extract(epoch from received_at) * 1000)::bigint as received_ms,
  module, event_type, severity, details, agent_id, session_id, trace_id,
  correlation_id, resource_type, resource_id, outcome, policy_version, source,
  tenant_id
`;

async function insertWithClient(client: PoolClient, event: MonolithEvent) {
  // Insert one event. `on conflict (event_id) do nothing` makes redelivery
  // idempotent: a duplicate insert returns no row, so `inserted` is false.
  //
  // If the event is critical AND a webhook is configured, the alert job is
  // queued in the SAME transaction (alert_outbox row) — critical evidence and
  // its notification are committed together, so a crash cannot separate them.
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
    await client.query(
      `insert into monolith.alert_outbox (event_id, tenant_id, payload)
       values ($1::uuid, $2, $3::jsonb)
       on conflict (event_id) do nothing`,
      [persisted.event_id, persisted.tenant_id, JSON.stringify(persisted)],
    );
  }
  return { inserted: true, event: persisted };
}

export async function persistEvents(events: MonolithEvent[]) {
  // Insert a batch in ONE tenant-scoped transaction. A batch must not span
  // tenants (one transaction sets one RLS context), so mixed batches are
  // rejected before any SQL runs. Called from: /api/ingest route.
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
  // The SSE replay query: the most recent events, optionally AFTER a cursor
  // event (for Last-Event-ID resume). The cursor is compared as a Postgres
  // tuple (received_at, event_id) so ordering is stable even for events with
  // identical timestamps.
  // Called from: sse-event-stream.ts createEventStream().
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
  // Load ONE event by id, scoped to the tenant. Called from:
  // live-event-listener.ts — when Postgres LISTEN/NOTIFY reports a new event,
  // the listener loads the full row with this and pushes it into the broker.
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
  // Liveness probe for GET /api/ingest (used by the Compose healthcheck).
  await getDb().query("select 1");
}
