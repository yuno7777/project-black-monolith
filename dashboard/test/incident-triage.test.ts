import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { POST } from "../app/api/incidents/route";
import {
  applyTransition,
  clearMemoryRevocations,
  IncidentInputError,
  normalizeTransition,
  UnknownEventError,
} from "../lib/incident-store";
import { clearMemoryEvents } from "../lib/event-store";
import type { MonolithEvent } from "../lib/types";

/**
 * The incident queue's write path: a triage transition, the state change it
 * makes, and the audit trail that accounts for it.
 *
 * The trail is the point. A detection is evidence, an analyst's decision about
 * a detection is evidence, and evidence that can be lost — or attributed to
 * the wrong person — is worse than no trail at all, because it looks like
 * proof. So three things have to hold together here, and each is a separate
 * failure the queue could have:
 *
 *  1. The request is validated *before* anything is written. A transition
 *     that is refused must leave no state and no trail entry behind.
 *  2. The actor is the credential, never the body. A caller that names
 *     itself in the request writes a name into the trail that nobody signed.
 *  3. The state change and the trail entry are written in one transaction.
 *     A trail that can be lost while the state change survives is the worst
 *     of both: the incident looks handled and nothing accounts for it.
 *
 * The memory path is used where the code has one, and a stand-in pool where
 * it does not, so the statements the code issues are what is asserted.
 */

const EVENT_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_TENANT_EVENT_ID = "22222222-2222-4222-8222-222222222222";

const ANALYST_TOKEN = "analyst-token-000000";
const VIEWER_TOKEN = "viewer-token-000000";

const OPERATOR_ENV = JSON.stringify({
  alice: { token: ANALYST_TOKEN, role: "analyst", tenant_id: "tenant-a" },
  bob: { token: VIEWER_TOKEN, role: "viewer", tenant_id: "tenant-a" },
});

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

/**
 * Seed the in-memory ledger with one event.
 *
 * The memory stores live on `globalThis` so they survive the module reload a
 * dev server does; the same place the tests reach them.
 */
function seedEvent(overrides: Partial<MonolithEvent> = {}): MonolithEvent {
  const event: MonolithEvent = {
    event_id: EVENT_ID,
    schema_version: 2,
    timestamp_ms: 1_770_000_000_000,
    module: "mcp-shield",
    event_type: "schema_mismatch",
    severity: "critical",
    details: { tool: "read_file" },
    tenant_id: "tenant-a",
    source: "module",
    ...overrides,
  };
  const memoryRef = globalThis as unknown as {
    __monolithMemoryEvents?: Map<string, MonolithEvent>;
  };
  if (!memoryRef.__monolithMemoryEvents) {
    memoryRef.__monolithMemoryEvents = new Map<string, MonolithEvent>();
  }
  memoryRef.__monolithMemoryEvents.set(event.event_id, event);
  return event;
}

type Statement = { sql: string; params: unknown[] };

/**
 * A stand-in for the pooled client, recording the statements it is given.
 *
 * It answers the queries the code issues, so the assertions are about the
 * statements that were really run rather than about a mock of them.
 */
function standInPool(options: { failOn?: string } = {}): {
  pool: unknown;
  statements: Statement[];
} {
  const statements: Statement[] = [];
  const pool = {
    connect: async () => ({
      query: async (sql: string, params: unknown[] = []) => {
        statements.push({ sql, params });
        if (options.failOn && sql.includes(options.failOn)) {
          throw new Error("the audit trail could not be written");
        }
        if (sql.includes("security_events")) {
          return { rows: [{ "?column?": 1 }], rowCount: 1 };
        }
        if (sql.includes("incident_triage") && sql.trimStart().startsWith("select")) {
          // No previous triage row: this is the first transition on the event.
          return { rows: [], rowCount: 0 };
        }
        if (sql.includes("insert into monolith.incident_triage")) {
          return {
            rows: [
              {
                status: "acknowledged",
                assignee: null,
                note: null,
                resolution: null,
                updated_ms: "1770000000000",
                updated_by: "alice",
              },
            ],
            rowCount: 1,
          };
        }
        return { rows: [], rowCount: 0 };
      },
      release: () => {},
    }),
  };
  return { pool, statements };
}

/** A ledger row, as the queue's query returns it. */
function ledgerRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    event_id: EVENT_ID,
    schema_version: 2,
    occurred_at_ms: "1770000000000",
    received_ms: "1770000000100",
    module: "mcp-shield",
    event_type: "schema_mismatch",
    severity: "critical",
    details: { tool: "read_file" },
    tenant_id: "tenant-a",
    correlation_id: null,
    session_id: "sess-a",
    trace_id: null,
    agent_id: "agent-a",
    outcome: "blocked",
    status: null,
    assignee: null,
    note: null,
    resolution: null,
    updated_ms: null,
    updated_by: null,
    ...overrides,
  };
}

function transitionRequest(body: unknown, token = ANALYST_TOKEN): Request {
  return new Request("http://localhost/api/incidents", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

beforeEach(() => {
  clearMemoryEvents();
  clearMemoryRevocations();
});

test("a triage transition must name a real event and a real state", () => {
  // Not an object at all.
  assert.throws(() => normalizeTransition(null, "alice", "tenant-a"), IncidentInputError);
  assert.throws(() => normalizeTransition([], "alice", "tenant-a"), IncidentInputError);
  assert.throws(() => normalizeTransition("resolved", "alice", "tenant-a"), IncidentInputError);

  // A plausible-looking id that is not a UUID would fail the insert with
  // 22P02 and surface as a 503 — a permanent error dressed as a transient
  // one, which the module outboxes would then retry forever.
  assert.throws(
    () => normalizeTransition({ event_id: "not-a-uuid", status: "acknowledged" }, "alice", "tenant-a"),
    /event_id must be a UUID/,
  );
  assert.throws(
    () => normalizeTransition({ event_id: EVENT_ID, status: "escalated" }, "alice", "tenant-a"),
    /status must be one of/,
  );
  // The actor is the credential's; without one there is nobody to attribute
  // the transition to.
  assert.throws(
    () => normalizeTransition({ event_id: EVENT_ID, status: "acknowledged" }, "", "tenant-a"),
    /actor is required/,
  );
});

test("an incident cannot be resolved without a verdict, nor verdicted without resolving", () => {
  assert.throws(
    () => normalizeTransition({ event_id: EVENT_ID, status: "resolved" }, "alice", "tenant-a"),
    /requires a resolution/,
  );
  assert.throws(
    () =>
      normalizeTransition(
        { event_id: EVENT_ID, status: "acknowledged", resolution: "true_positive" },
        "alice",
        "tenant-a",
      ),
    /only applies when resolving/,
  );
  assert.throws(
    () =>
      normalizeTransition(
        { event_id: EVENT_ID, status: "resolved", resolution: "probably" },
        "alice",
        "tenant-a",
      ),
    /resolution must be one of/,
  );

  // The one shape that is allowed.
  const resolved = normalizeTransition(
    { event_id: EVENT_ID, status: "resolved", resolution: "true_positive" },
    "alice",
    "tenant-a",
  );
  assert.equal(resolved.resolution, "true_positive");
});

test("the audit trail records the operator, not the caller", () => {
  // The body names someone else. The credential wins, or the trail is a
  // record of what the caller wished to be called.
  const transition = normalizeTransition(
    { event_id: EVENT_ID, status: "acknowledged", actor: "not-alice" },
    "alice",
    "tenant-a",
  );
  assert.equal(transition.actor, "alice");

  // "Take this" is a request, not a value: the client has no trustworthy
  // name for itself, so the server resolves it.
  const mine = normalizeTransition(
    { event_id: EVENT_ID, status: "acknowledged", assign_to_me: true },
    "alice",
    "tenant-a",
  );
  assert.equal(mine.assignee, "alice");

  // And the two ways of assigning are not both allowed at once, because then
  // which one won would be a detail of the implementation.
  assert.throws(
    () =>
      normalizeTransition(
        { event_id: EVENT_ID, status: "acknowledged", assign_to_me: true, assignee: "bob" },
        "alice",
        "tenant-a",
      ),
    /mutually exclusive/,
  );
});

test("a note is bounded, and a note that is not text is refused", () => {
  assert.throws(
    () =>
      normalizeTransition(
        { event_id: EVENT_ID, status: "acknowledged", note: "n".repeat(2001) },
        "alice",
        "tenant-a",
      ),
    /note must be at most 2000 characters/,
  );
  assert.throws(
    () =>
      normalizeTransition(
        { event_id: EVENT_ID, status: "acknowledged", note: { text: "hello" } },
        "alice",
        "tenant-a",
      ),
    /note must be a string/,
  );
});

test("a transition changes the incident's state", async () => {
  seedEvent();
  await withEnv({ DATABASE_URL: undefined }, async () => {
    const { triage } = await applyTransition({
      event_id: EVENT_ID,
      tenant_id: "tenant-a",
      status: "acknowledged",
      actor: "alice",
      assignee: "alice",
      note: "the tool was poisoned at first contact",
    });
    assert.equal(triage.status, "acknowledged");
    assert.equal(triage.assignee, "alice");
    assert.equal(triage.note, "the tool was poisoned at first contact");
    assert.equal(triage.updated_by, "alice");
  });
});

test("every transition is accounted for in the trail", async () => {
  seedEvent();
  await withEnv({ DATABASE_URL: undefined }, async () => {
    await applyTransition({
      event_id: EVENT_ID,
      tenant_id: "tenant-a",
      status: "acknowledged",
      actor: "alice",
    });
    await applyTransition({
      event_id: EVENT_ID,
      tenant_id: "tenant-a",
      status: "resolved",
      actor: "bob",
      resolution: "true_positive",
    });

    const memoryRef = globalThis as unknown as {
      __monolithMemoryAudit?: Map<string, unknown[]>;
    };
    const trail = memoryRef.__monolithMemoryAudit?.get(EVENT_ID) ?? [];
    assert.equal(trail.length, 2, "both transitions must be accounted for");
    // Newest first, and each entry says who acted and what it changed.
    const [latest, first] = trail as Array<Record<string, unknown>>;
    assert.equal(latest.actor, "bob");
    assert.equal(latest.from_status, "acknowledged");
    assert.equal(latest.to_status, "resolved");
    assert.equal(latest.resolution, "true_positive");
    assert.equal(first.actor, "alice");
    assert.equal(first.from_status, undefined);
    assert.equal(first.to_status, "acknowledged");
  });
});

test("a transition for an event that never happened is refused", async () => {
  await withEnv({ DATABASE_URL: undefined }, async () => {
    await assert.rejects(
      applyTransition({
        event_id: EVENT_ID,
        tenant_id: "tenant-a",
        status: "acknowledged",
        actor: "alice",
      }),
      UnknownEventError,
    );
  });
});

test("an event in another tenant is indistinguishable from one that never happened", async () => {
  // The ledger is multi-tenant, and an event id is a UUID an operator can
  // learn from another tenant's console. If a transition on it succeeded,
  // the response would confirm that the id exists — a slow leak of one
  // tenant's ledger into another's.
  seedEvent({ event_id: OTHER_TENANT_EVENT_ID, tenant_id: "tenant-b" });
  await withEnv({ DATABASE_URL: undefined }, async () => {
    await assert.rejects(
      applyTransition({
        event_id: OTHER_TENANT_EVENT_ID,
        tenant_id: "tenant-a",
        status: "acknowledged",
        actor: "alice",
      }),
      UnknownEventError,
    );
  });
});

test("the state change and the trail entry are written in one transaction", async () => {
  const { pool, statements } = standInPool();
  const globalRef = globalThis as unknown as { __monolithPool?: unknown };
  const previousPool = globalRef.__monolithPool;
  globalRef.__monolithPool = pool;

  try {
    await withEnv({ DATABASE_URL: "postgresql://unused/unused" }, async () => {
      await applyTransition({
        event_id: EVENT_ID,
        tenant_id: "tenant-a",
        status: "acknowledged",
        actor: "alice",
      });
    });

    const sql = statements.map((statement) => statement.sql);
    const indexOf = (fragment: string) => sql.findIndex((text) => text.includes(fragment));

    assert.ok(indexOf("begin") >= 0, "the transition must run in a transaction");
    assert.ok(indexOf("incident_triage") >= 0, "the state change was never written");
    const audit = indexOf("insert into monolith.incident_audit");
    assert.ok(audit >= 0, "the trail entry was never written");
    assert.ok(indexOf("commit") >= 0, "the transaction was never committed");
    assert.ok(
      indexOf("rollback") < 0,
      "a committed transition must not have been rolled back",
    );
    // The trail entry is written inside the same transaction as the state
    // change, not after it: an entry appended by a second transaction could
    // be lost while the state change stood.
    assert.ok(
      indexOf("incident_triage") < audit,
      "the state change must be written before the trail entry, in the same transaction",
    );

    // The existence check is scoped to the tenant, so an event id from
    // another tenant is indistinguishable from one that never happened.
    const existence = statements.find((statement) =>
      statement.sql.includes("from monolith.security_events"),
    );
    assert.ok(existence, "the transition never checked that the event exists");
    assert.match(
      existence.sql,
      /event_id\s*=\s*\$1\s+and\s+tenant_id\s*=\s*\$2/,
      "the existence check must be scoped to the tenant",
    );
    assert.deepEqual(existence.params, [EVENT_ID, "tenant-a"]);
  } finally {
    globalRef.__monolithPool = previousPool;
  }
});

test("a trail that cannot be written takes the state change with it", async () => {
  const { pool, statements } = standInPool({ failOn: "insert into monolith.incident_audit" });
  const globalRef = globalThis as unknown as { __monolithPool?: unknown };
  const previousPool = globalRef.__monolithPool;
  globalRef.__monolithPool = pool;

  try {
    await withEnv({ DATABASE_URL: "postgresql://unused/unused" }, async () => {
      await assert.rejects(
        applyTransition({
          event_id: EVENT_ID,
          tenant_id: "tenant-a",
          status: "acknowledged",
          actor: "alice",
        }),
        /the audit trail could not be written/,
      );
    });

    const sql = statements.map((statement) => statement.sql);
    assert.ok(
      sql.some((text) => text.includes("rollback")),
      "a failed trail entry must roll the state change back",
    );
    assert.ok(
      !sql.some((text) => text.includes("commit")),
      "a transition without a trail entry must not be committed",
    );
  } finally {
    globalRef.__monolithPool = previousPool;
  }
});

test("a viewer cannot triage an incident", async () => {
  seedEvent();
  await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV, DATABASE_URL: undefined }, async () => {
    const response = await POST(
      transitionRequest({ event_id: EVENT_ID, status: "acknowledged" }, VIEWER_TOKEN),
    );
    assert.equal(response.status, 403);
    const body = (await response.json()) as { error?: string };
    assert.match(body.error ?? "", /analyst role is required/);
  });
});

test("an unauthenticated caller learns nothing about the incident", async () => {
  await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV, DATABASE_URL: undefined }, async () => {
    const response = await POST(
      new Request("http://localhost/api/incidents", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ event_id: EVENT_ID, status: "acknowledged" }),
      }),
    );
    assert.equal(response.status, 401);
  });
});

test("an invalid transition is a 422, not a 500", async () => {
  await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV, DATABASE_URL: undefined }, async () => {
    const response = await POST(
      transitionRequest({ event_id: "not-a-uuid", status: "acknowledged" }),
    );
    assert.equal(response.status, 422);
    const body = (await response.json()) as { error?: string };
    assert.match(body.error ?? "", /event_id must be a UUID/);
  });
});

test("a transition for an event that never happened is a 404", async () => {
  await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV, DATABASE_URL: undefined }, async () => {
    const response = await POST(
      transitionRequest({ event_id: EVENT_ID, status: "acknowledged" }),
    );
    assert.equal(response.status, 404);
    const body = (await response.json()) as { error?: string };
    assert.match(body.error ?? "", /no such event/);
  });
});

test("a transition is applied and the trail names the credential's operator", async () => {
  seedEvent();
  await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV, DATABASE_URL: undefined }, async () => {
    const response = await POST(
      transitionRequest({
        event_id: EVENT_ID,
        status: "acknowledged",
        actor: "not-alice",
        assign_to_me: true,
      }),
    );
    assert.equal(response.status, 200);
    const body = (await response.json()) as {
      event_id?: string;
      triage?: { status?: string; assignee?: string; updated_by?: string };
    };
    assert.equal(body.event_id, EVENT_ID);
    assert.equal(body.triage?.status, "acknowledged");
    // The name in the trail is the one the credential carries, not the one
    // the request asked for.
    assert.equal(body.triage?.assignee, "alice");
    assert.equal(body.triage?.updated_by, "alice");

    const memoryRef = globalThis as unknown as {
      __monolithMemoryAudit?: Map<string, Array<Record<string, unknown>>>;
    };
    const trail = memoryRef.__monolithMemoryAudit?.get(EVENT_ID) ?? [];
    assert.equal(trail.length, 1);
    assert.equal(trail[0]?.actor, "alice");
  });
});
