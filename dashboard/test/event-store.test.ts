import assert from "node:assert/strict";
import test from "node:test";
import type { PoolClient } from "pg";
import { insertEventWithClient } from "../lib/event-store";
import type { MonolithEvent } from "../lib/types";

/**
 * A critical detection and the alert job it raises are evidence and
 * notification. They must not share a failure mode: a notification that
 * cannot be written must not destroy the evidence it was raised for.
 *
 * These tests drive the real insert path with a stand-in database client, so
 * the statements the code issues are what is asserted — not a mock of them.
 */

const ALERT_ENV = {
  MONOLITH_ALERT_WEBHOOK_URL: "https://alerts.example/hook",
  MONOLITH_ALERT_WEBHOOK_SECRET: "s".repeat(40),
};

const CRITICAL_EVENT: MonolithEvent = {
  event_id: "11111111-1111-4111-8111-111111111111",
  schema_version: 2,
  timestamp_ms: 1_770_000_000_000,
  module: "mcp-shield",
  event_type: "schema_mismatch",
  severity: "critical",
  details: { tool: "read_file" },
  tenant_id: "tenant-alert",
  source: "module",
};

const STORED_ROW = {
  event_id: CRITICAL_EVENT.event_id,
  schema_version: 2,
  occurred_at_ms: "1770000000000",
  received_ms: "1770000000001",
  module: CRITICAL_EVENT.module,
  event_type: CRITICAL_EVENT.event_type,
  severity: CRITICAL_EVENT.severity,
  details: CRITICAL_EVENT.details,
  tenant_id: CRITICAL_EVENT.tenant_id,
  agent_id: null,
  session_id: null,
  trace_id: null,
  correlation_id: null,
  resource_type: null,
  resource_id: null,
  outcome: null,
  policy_version: null,
  source: "module",
};

/**
 * Run a body with environment variables set, then put them back.
 */
async function withEnv(
  vars: Record<string, string | undefined>,
  body: () => void | Promise<void>,
): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(vars)) {
    saved[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    await body();
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

type QueryCall = { sql: string; params: unknown[] };

/**
 * A stand-in for a pooled client that records the statements it is given.
 *
 * The insert echoes back the row it was asked to store, the way a real
 * `returning` clause does, so the code under test reads its own severity
 * rather than a constant. `failAlertInsert` makes the alert job
 * unwritable, the way a missing table after a partial migration or an RLS
 * check mismatch would.
 */
function fakeClient(options: { failAlertInsert?: boolean } = {}) {
  const calls: QueryCall[] = [];
  const client = {
    async query(sql: string, params: unknown[] = []) {
      calls.push({ sql, params });
      if (options.failAlertInsert && sql.includes("monolith.alert_outbox")) {
        throw new Error('relation "monolith.alert_outbox" does not exist');
      }
      if (sql.includes("monolith.security_events")) {
        const [eventId, schemaVersion, timestamp, module, eventType, severity, details] = params;
        return {
          rows: [
            {
              ...STORED_ROW,
              event_id: eventId,
              schema_version: schemaVersion,
              occurred_at_ms: String(timestamp),
              module,
              event_type: eventType,
              severity,
              details: JSON.parse(String(details)),
            },
          ],
        };
      }
      return { rows: [] };
    },
  };
  return { client: client as unknown as PoolClient, calls };
}

function statement(calls: QueryCall[], needle: string): QueryCall | undefined {
  return calls.find((call) => call.sql.trim() === needle);
}

test("a critical detection and its alert job are committed together", async () => {
  await withEnv(ALERT_ENV, async () => {
    const { client, calls } = fakeClient();
    const result = await insertEventWithClient(client, CRITICAL_EVENT);

    assert.equal(result.inserted, true);
    assert.ok(
      calls.some((call) => call.sql.includes("monolith.alert_outbox")),
      "a critical detection must raise an alert job",
    );
    assert.ok(
      statement(calls, "release savepoint monolith_alert_job"),
      "the savepoint is released when the job is written",
    );
  });
});

test("a failed alert job does not roll back the detection it was raised for", async () => {
  await withEnv(ALERT_ENV, async () => {
    const { client, calls } = fakeClient({ failAlertInsert: true });

    // Before the fix this threw, which aborted the transaction and took the
    // security event with it: a 503 to the module, a retry, and eventually a
    // dead-lettered event that was perfectly valid.
    const result = await insertEventWithClient(client, CRITICAL_EVENT);

    assert.equal(result.inserted, true, "the detection must survive a failed notification");
    assert.equal(result.event.event_id, CRITICAL_EVENT.event_id);
    assert.ok(
      statement(calls, "rollback to savepoint monolith_alert_job"),
      "the failed job is rolled back on its own, not on the whole transaction",
    );
  });
});

test("a non-critical detection raises no alert job", async () => {
  await withEnv(ALERT_ENV, async () => {
    const { client, calls } = fakeClient();
    const result = await insertEventWithClient(client, {
      ...CRITICAL_EVENT,
      severity: "warning",
    });

    assert.equal(result.inserted, true);
    assert.ok(
      !calls.some((call) => call.sql.includes("monolith.alert_outbox")),
      "only a critical detection raises an alert",
    );
  });
});
