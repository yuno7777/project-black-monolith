import assert from "node:assert/strict";
import { test } from "node:test";
import { GET } from "../app/api/incidents/route";
import {
  crossLayerSessionCount,
  decodeIncidentCursor,
  incidentCounts,
  IncidentInputError,
  listIncidents,
} from "../lib/incident-store";

/**
 * The incident queue's read path: which events the operator is shown, in
 * what order, how the page is cut, and the counts beside it.
 *
 * Three things have to hold, and each is a way the queue could quietly
 * under-report:
 *
 *  1. **The order.** The queue opens on the worst thing, not merely the
 *     newest. A critical detection that arrives behind a stream of
 *     informational ones is a detection nobody reads.
 *  2. **The page.** It is a keyset, not an offset: the cursor names the
 *     last row of the previous page, so a page boundary cannot shift under
 *     a new event and make the operator miss a row or see one twice.
 *  3. **The counts.** They are the numbers the overview is built from, and
 *     they are counted per tenant — a count that includes another tenant's
 *     events is a number nobody can act on.
 *
 * The stand-in pool answers the queries the code issues, so the assertions
 * are about the statements that were really run.
 */

const ANALYST_TOKEN = "analyst-token-000000";

const OPERATOR_ENV = JSON.stringify({
  alice: { token: ANALYST_TOKEN, role: "analyst", tenant_id: "tenant-a" },
});

const EVENT_ID = "11111111-1111-4111-8111-111111111111";

type Statement = { sql: string; params: unknown[] };

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

/**
 * A page of ledger rows, oldest-first, each one distinct enough that the
 * cursor can be checked against it.
 */
function ledgerRows(count: number): Record<string, unknown>[] {
  return Array.from({ length: count }, (_, index) =>
    ledgerRow({
      event_id: `11111111-1111-4111-8111-1111111111${index.toString().padStart(2, "0")}`,
      received_ms: String(1770000000100 + index * 100),
    }),
  );
}

/**
 * A stand-in for the pooled client.
 *
 * `incidentRows` is what the queue's select returns; the counts and
 * cross-layer queries answer with their own shapes.
 */
function standInPool(options: { incidentRows?: Record<string, unknown>[] } = {}): {
  pool: unknown;
  statements: Statement[];
} {
  const statements: Statement[] = [];
  const pool = {
    connect: async () => ({
      query: async (sql: string, params: unknown[] = []) => {
        statements.push({ sql, params });
        if (sql.includes("group by 1")) {
          return {
            rows: [
              { status: "new", n: "4" },
              { status: "acknowledged", n: "2" },
              { status: "resolved", n: "1" },
            ],
            rowCount: 3,
          };
        }
        if (sql.includes("having count(distinct module) > 1")) {
          return { rows: [{ n: "3" }], rowCount: 1 };
        }
        if (sql.includes("from monolith.security_events e")) {
          return { rows: options.incidentRows ?? [ledgerRow()], rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
      },
      release: () => {},
    }),
  };
  return { pool, statements };
}

/** Install a stand-in pool for the duration of a body. */
async function withPool(
  options: { incidentRows?: Record<string, unknown>[] },
  body: (statements: Statement[]) => void | Promise<void>,
): Promise<void> {
  const { pool, statements } = standInPool(options);
  const globalRef = globalThis as unknown as { __monolithPool?: unknown };
  const previousPool = globalRef.__monolithPool;
  globalRef.__monolithPool = pool;
  try {
    await withEnv({ DATABASE_URL: "postgresql://unused/unused" }, async () => {
      await body(statements);
    });
  } finally {
    globalRef.__monolithPool = previousPool;
  }
}

/**
 * The statement that selects the queue's rows — the last one issued, so a
 * test that pages twice reads the page it asked for last.
 */
function queueSelect(statements: Statement[]): Statement {
  const matches = statements.filter(
    (statement) =>
      statement.sql.includes("from monolith.security_events e") &&
      statement.sql.includes("left join monolith.incident_triage"),
  );
  const found = matches.at(-1);
  assert.ok(found, "the queue never ran its select");
  return found;
}

test("the queue opens on the worst thing, not the newest", async () => {
  await withPool({}, async (statements) => {
    await listIncidents({ tenant_id: "tenant-a" });
    const select = queueSelect(statements).sql;
    // Worst-first: the severity rank is ordered ascending, so a critical
    // event is above a warning and a warning above an informational one.
    assert.match(
      select,
      /case e\.severity when 'critical' then 0 when 'warning' then 1 else 2 end\s*,\s*e\.received_at desc\s*,\s*e\.event_id desc/i,
    );
    // And the rank is what the ordering turns on — not merely something
    // the statement mentions.
    const orderIndex = select.toLowerCase().lastIndexOf("order by");
    const rankIndex = select.toLowerCase().indexOf("case e.severity when 'critical'");
    assert.ok(orderIndex >= 0, "the queue did not order its rows at all");
    assert.ok(rankIndex > orderIndex, "the severity rank is not part of the ordering");
  });
});

test("a page is bounded by the limit, and one extra row is the signal for more", async () => {
  const rows = Array.from({ length: 4 }, (_, index) =>
    ledgerRow({ event_id: `11111111-1111-4111-8111-11111111111${index}` }),
  );
  await withPool({ incidentRows: rows }, async (statements) => {
    const page = await listIncidents({ tenant_id: "tenant-a", limit: 3 });
    // The query asks for one more than the limit, because the presence of
    // that extra row is how the store knows there is another page — without
    // a count query, and without fetching the next page to find out.
    const limit = Number(queueSelect(statements).params.at(-1));
    assert.equal(limit, 4, "the query must ask for one row more than the limit");
    assert.equal(page.incidents.length, 3, "the page must not exceed the limit");
    assert.ok(page.next_cursor, "a full page must carry a cursor");
  });
});

test("a short page carries no cursor", async () => {
  await withPool({ incidentRows: [ledgerRow()] }, async () => {
    const page = await listIncidents({ tenant_id: "tenant-a", limit: 50 });
    assert.equal(page.incidents.length, 1);
    assert.equal(page.next_cursor, undefined, "a page with room left must not carry a cursor");
  });
});

test("the cursor names the last row of the page it came from", async () => {
  await withPool({ incidentRows: ledgerRows(3) }, async () => {
    const first = await listIncidents({ tenant_id: "tenant-a", limit: 2 });
    const cursor = first.next_cursor;
    assert.ok(cursor, "a page with more behind it must carry a cursor");

    // The cursor is the page's *last* row, not its first and not the row
    // that would have been next: the next page starts after it.
    const decoded = decodeIncidentCursor(cursor);
    assert.equal(decoded.event_id, "11111111-1111-4111-8111-111111111101");
    assert.equal(decoded.severity_rank, 0, "a critical event ranks first");
    assert.equal(decoded.received_ms, 1770000000200);
  });
});

test("the cursor is a keyset, not an offset", async () => {
  await withPool({ incidentRows: ledgerRows(3) }, async (statements) => {
    const first = await listIncidents({ tenant_id: "tenant-a", limit: 2 });
    const cursor = first.next_cursor;
    assert.ok(cursor, "the first page must carry a cursor");

    await listIncidents({ tenant_id: "tenant-a", limit: 2, cursor });
    const select = queueSelect(statements).sql;
    // A keyset: the next page starts strictly after the cursor's row. An
    // offset would shift under an event that arrived in between, and the
    // operator would see one row twice and another not at all.
    assert.match(
      select,
      /case e\.severity when 'critical' then 0 when 'warning' then 1 else 2 end\s*>\s*\$\d+/i,
    );
    assert.match(select, /and \(e\.received_at, e\.event_id\) < \(/i);
    assert.doesNotMatch(select, /\boffset\b/i);
  });
});

test("a cursor that is not one is refused", () => {
  // A cursor is client-supplied, so it is untrusted input. It must not be
  // able to name a row, a page, or a column.
  const encode = (value: Record<string, unknown>) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");

  for (const bad of [
    "",
    "not-base64!!",
    "eyJzdGV2ZXJpdH9fcmFuayI6MH0",
    encode({ severity_rank: 0, received_ms: 1, event_id: "x" }),
    encode({ severity_rank: 9, received_ms: 1, event_id: EVENT_ID }),
    encode({ severity_rank: 0, received_ms: 1.5, event_id: EVENT_ID }),
    encode({ severity_rank: 0, received_ms: 0, event_id: EVENT_ID }),
  ]) {
    assert.throws(() => decodeIncidentCursor(bad), IncidentInputError, `accepted: ${bad}`);
  }
});

test("the counts add up, and they count one tenant", async () => {
  await withPool({}, async (statements) => {
    const counts = await incidentCounts("tenant-a");
    assert.equal(counts.new, 4);
    assert.equal(counts.acknowledged, 2);
    assert.equal(counts.resolved, 1);
    // "open" is what the queue shows by default, and "all" is everything:
    // both are derived, so they cannot drift from the numbers they are
    // made of.
    assert.equal(counts.open, 6);
    assert.equal(counts.all, 7);

    const query = statements.find((statement) => statement.sql.includes("group by 1"));
    assert.ok(query, "the counts were never counted");
    assert.match(query.sql, /where e\.tenant_id = \$1/i);
    assert.deepEqual(query.params, ["tenant-a"]);
  });
});

test("a session that trips more than one layer is counted once", async () => {
  await withPool({}, async (statements) => {
    const count = await crossLayerSessionCount("tenant-a");
    assert.equal(count, 3);
    const query = statements.find((statement) =>
      statement.sql.includes("having count(distinct module) > 1"),
    );
    assert.ok(query, "the cross-layer count was never counted");
    assert.match(query.sql, /where tenant_id = \$1/i);
    assert.deepEqual(query.params, ["tenant-a"]);
  });
});

test("the open filter includes the events nobody has looked at", async () => {
  await withPool({}, async (statements) => {
    await listIncidents({ tenant_id: "tenant-a", status: "open" });
    const select = queueSelect(statements).sql;
    // An event with no triage row at all has never been looked at. It is
    // still open, and the queue has to say so with a coalesce rather than
    // drop it: the null is the absence of a decision, not a decision.
    assert.match(select, /coalesce\(t\.status, 'new'\) in \('new', 'acknowledged'\)/i);
  });
});

test("the triaged filter is the events someone actually acted on", async () => {
  await withPool({}, async (statements) => {
    await listIncidents({ tenant_id: "tenant-a", status: "triaged" });
    assert.match(queueSelect(statements).sql, /t\.status is not null/i);
  });
});

test("a search reaches the fields an analyst would actually use", async () => {
  await withPool({}, async (statements) => {
    await listIncidents({ tenant_id: "tenant-a", q: "read_file" });
    const select = queueSelect(statements).sql;
    for (const pattern of [
      /e\.event_type ilike/i,
      /e\.module ilike/i,
      /e\.severity ilike/i,
      /t\.assignee, ''\) ilike/i,
      /e\.session_id, ''\) ilike/i,
      /e\.agent_id, ''\) ilike/i,
      /e\.trace_id, ''\) ilike/i,
      /e\.correlation_id, ''\) ilike/i,
    ]) {
      assert.ok(
        pattern.test(select),
        `a search does not reach ${pattern.source}, so pasting that value would find nothing`,
      );
    }
  });
});

test("the queue never reads another tenant's events", async () => {
  await withPool({}, async (statements) => {
    await listIncidents({ tenant_id: "tenant-a" });
    const select = queueSelect(statements);
    assert.match(select.sql, /e\.tenant_id = \$1/i);
    assert.equal(select.params[0], "tenant-a");
  });
});

test("the read route returns the queue, the cursor and the counts", async () => {
  await withPool({}, async () => {
    await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV }, async () => {
      const response = await GET(
        new Request("http://localhost/api/incidents?limit=10", {
          headers: { authorization: `Bearer ${ANALYST_TOKEN}` },
        }),
      );
      assert.equal(response.status, 200);
      const body = (await response.json()) as {
        incidents?: Array<{ event_id?: string }>;
        next_cursor?: string;
        counts?: Record<string, number>;
      };
      assert.equal(body.incidents?.length, 1);
      assert.equal(body.incidents?.[0]?.event_id, EVENT_ID);
      // The counts beside the queue are the numbers the overview is built
      // from, and they are counted for the caller's tenant.
      assert.equal(body.counts?.open, 6);
      assert.equal(body.counts?.all, 7);
      assert.equal(body.counts?.cross_layer_sessions, 3);
    });
  });
});

test("a cursor the operator cannot have come from is refused, not obeyed", async () => {
  await withPool({}, async () => {
    await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV }, async () => {
      const response = await GET(
        new Request("http://localhost/api/incidents?cursor=not-a-cursor", {
          headers: { authorization: `Bearer ${ANALYST_TOKEN}` },
        }),
      );
      assert.equal(response.status, 422);
      const body = (await response.json()) as { error?: string };
      assert.match(body.error ?? "", /cursor is invalid or expired/);
    });
  });
});

test("the queue refuses a filter it does not understand", async () => {
  await withPool({}, async () => {
    await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV }, async () => {
      const ask = async (query: string) =>
        GET(
          new Request(`http://localhost/api/incidents?${query}`, {
            headers: { authorization: `Bearer ${ANALYST_TOKEN}` },
          }),
        );

      for (const [query, expected] of [
        ["status=escalated", /unknown status filter/],
        ["severity=catastrophic", /unknown severity filter/],
        ["module=not-a-module", /unknown module filter/],
        ["since_ms=-1", /since_ms must be a positive number/],
        ["limit=0", /limit must be a positive number/],
        ["limit=many", /limit must be a positive number/],
      ] as const) {
        const response = await ask(query);
        assert.equal(response.status, 422, `${query} should be refused`);
        const body = (await response.json()) as { error?: string };
        assert.match(body.error ?? "", expected);
      }
    });
  });
});
