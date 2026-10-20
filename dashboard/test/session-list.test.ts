// The session list's production path.
//
// The list answers "is my agent connected yet?" — the per-session endpoint
// cannot, because it answers 200 with zero events for a session that never
// happened, which is indistinguishable from a connected-but-silent one.
//
// It has two halves. The in-memory one runs when there is no DATABASE_URL;
// the Postgres one is what production actually runs. The in-memory half is
// covered by onboarding.test.ts. The Postgres half was covered by nothing,
// which is the gap this file closes: a query that forgets to scope itself to
// a tenant, or that groups by the wrong columns, or that reports a
// severity the in-memory half would not, would ship silently.
//
// The strongest thing to assert here is that the two halves agree. They are
// two implementations of one list, and the in-memory one exists to stand in
// for the other — so a difference between them is a bug in whichever one
// moved, and the operator sees whichever one ran.

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";
import { GET as sessionsGet } from "../app/api/sessions/route";
import { clearMemoryEvents, normalizeEvent, persistEvents } from "../lib/event-store";
import { listRecentSessions } from "../lib/onboarding-store";

const VIEWER_TOKEN = "viewer-operator-token-00000";
const OTHER_TENANT_TOKEN = "viewer-operator-token-00001";

const OPERATOR_ENV = JSON.stringify({
  reader: { token: VIEWER_TOKEN, role: "viewer", tenant_id: "tenant-a" },
  stranger: { token: OTHER_TENANT_TOKEN, role: "viewer", tenant_id: "tenant-b" },
});

type Statement = { sql: string; params: unknown[] };

/** Run a body with environment variables set, then put them back. */
async function withEnv<T>(
  vars: Record<string, string | undefined>,
  body: () => T | Promise<T>,
): Promise<T> {
  const saved: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(vars)) {
    saved[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    return await body();
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

/**
 * A stand-in for the pooled client. It answers the one statement the
 * session list runs and records every statement it was given.
 */
function standInPool(options: { rows?: Record<string, unknown>[]; fail?: boolean } = {}): {
  pool: unknown;
  statements: Statement[];
} {
  const statements: Statement[] = [];
  const pool = {
    connect: async () => ({
      query: async (sql: string, params: unknown[] = []) => {
        statements.push({ sql, params });
        if (options.fail) throw new Error("the database is unavailable");
        if (sql.includes("from monolith.security_events")) {
          const rows = options.rows ?? [];
          return { rows, rowCount: rows.length };
        }
        return { rows: [], rowCount: 0 };
      },
      release: () => {},
    }),
  };
  return { pool, statements };
}

/** Run a body against the stand-in database, then put the pool back. */
async function withPool(
  options: Parameters<typeof standInPool>[0],
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

/** The statement the session list runs, taken from the record. */
function listQuery(statements: Statement[]): Statement {
  const matches = statements.filter((statement) =>
    statement.sql.includes("from monolith.security_events"),
  );
  assert.equal(matches.length, 1, "the list should run exactly one query");
  return matches[0];
}

/** A row as the database hands it over. */
function row(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    session_id: "sess-a",
    agent_id: "claude-code",
    events: 3,
    modules: ["mcp-shield", "trace-audit"],
    worst: 1,
    first_ms: "1700000000000",
    last_ms: "1700000005000",
    ...overrides,
  };
}

type SeedEvent = {
  module: string;
  severity: "info" | "warning" | "critical";
  session_id: string | null;
  agent_id: string | null;
  received_ms: number;
};

/** A seed, in the shape the in-memory ledger stores it. */
function toLedgerEvent(seed: SeedEvent): Record<string, unknown> {
  return {
    ...normalizeEvent({
      event_id: randomUUID(),
      module: seed.module,
      event_type: "detection",
      severity: seed.severity,
      session_id: seed.session_id,
      agent_id: seed.agent_id,
      tenant_id: "tenant-a",
      timestamp_ms: seed.received_ms,
    }),
    received_ms: seed.received_ms,
  };
}

/**
 * The rows the database would hand over, computed the way the query
 * computes them: grouped by session and agent, counting the events,
 * collecting the distinct modules, taking the worst severity and the first
 * and last received times.
 */
function sqlRowsFor(seeds: SeedEvent[]): Record<string, unknown>[] {
  const groups = new Map<
    string,
    {
      session_id: string;
      agent_id: string | null;
      events: number;
      modules: Set<string>;
      worst: number;
      first_ms: number;
      last_ms: number;
    }
  >();
  for (const seed of seeds) {
    if (seed.session_id === null) continue;
    const key = `${seed.agent_id ?? ""}\u0000${seed.session_id}`;
    const existing = groups.get(key);
    const rank = seed.severity === "critical" ? 2 : seed.severity === "warning" ? 1 : 0;
    if (!existing) {
      groups.set(key, {
        session_id: seed.session_id,
        agent_id: seed.agent_id,
        events: 1,
        modules: new Set([seed.module]),
        worst: rank,
        first_ms: seed.received_ms,
        last_ms: seed.received_ms,
      });
      continue;
    }
    existing.events += 1;
    existing.modules.add(seed.module);
    existing.worst = Math.max(existing.worst, rank);
    existing.first_ms = Math.min(existing.first_ms, seed.received_ms);
    existing.last_ms = Math.max(existing.last_ms, seed.received_ms);
  }
  return [...groups.values()]
    .sort((a, b) => b.last_ms - a.last_ms)
    .map((group) => ({
      session_id: group.session_id,
      agent_id: group.agent_id,
      events: group.events,
      // array_agg(distinct ...) has no defined order in Postgres, so the
      // comparison sorts both sides rather than trusting this one.
      modules: [...group.modules].sort(),
      worst: group.worst,
      first_ms: String(group.first_ms),
      last_ms: String(group.last_ms),
    }));
}

test("the list asks the database for one tenant only", async () => {
  await withPool({ rows: [] }, async (statements) => {
    await listRecentSessions("tenant-a");
    const query = listQuery(statements);
    assert.match(query.sql, /where tenant_id = \$1/i);
    assert.equal(query.params[0], "tenant-a");
  });
});

test("the tenant is also set on the transaction", async () => {
  // The query filters by tenant; the transaction sets the context the
  // row-level security policy reads. Both, or the policy sees nothing.
  await withPool({ rows: [] }, async (statements) => {
    await listRecentSessions("tenant-a");
    const context = statements.filter((statement) =>
      statement.sql.includes("set_config('monolith.tenant_id'"),
    );
    assert.equal(context.length, 1, "the tenant context should be set once");
    assert.deepEqual(context[0].params, ["tenant-a"]);
  });
});

test("an event with no session is not a session", async () => {
  await withPool({ rows: [] }, async (statements) => {
    await listRecentSessions("tenant-a");
    assert.match(listQuery(statements).sql, /session_id is not null/i);
  });
});

test("the sessions are grouped by session and agent", async () => {
  // One session id under two agents is two sessions. Collapsing them would
  // merge two agents' work into one row.
  await withPool({ rows: [] }, async (statements) => {
    await listRecentSessions("tenant-a");
    assert.match(listQuery(statements).sql, /group by session_id, agent_id/i);
  });
});

test("the newest session comes first", async () => {
  await withPool({ rows: [] }, async (statements) => {
    await listRecentSessions("tenant-a");
    assert.match(listQuery(statements).sql, /order by last_ms desc/i);
  });
});

test("the list is bounded", async () => {
  await withPool({ rows: [] }, async (statements) => {
    await listRecentSessions("tenant-a", 5000);
    assert.equal(listQuery(statements).params[1], 100, "a huge limit is capped");
  });
  await withPool({ rows: [] }, async (statements) => {
    await listRecentSessions("tenant-a", 0);
    assert.equal(listQuery(statements).params[1], 1, "a zero limit becomes one");
  });
  await withPool({ rows: [] }, async (statements) => {
    await listRecentSessions("tenant-a", -3);
    assert.equal(listQuery(statements).params[1], 1, "a negative limit becomes one");
  });
  await withPool({ rows: [] }, async (statements) => {
    await listRecentSessions("tenant-a", 7.9);
    assert.equal(listQuery(statements).params[1], 7, "a fractional limit is truncated");
  });
});

test("the worst severity comes from the rank, not from a string", async () => {
  const cases: [number, string][] = [
    [2, "critical"],
    [1, "warning"],
    [0, "info"],
  ];
  for (const [worst, expected] of cases) {
    await withPool({ rows: [row({ worst })] }, async () => {
      const sessions = await listRecentSessions("tenant-a");
      assert.equal(sessions.length, 1);
      assert.equal(sessions[0].worst_severity, expected);
    });
  }
});

test("a module the contract does not define is dropped", async () => {
  await withPool({ rows: [row({ modules: ["mcp-shield", "not-a-module"] })] }, async () => {
    const sessions = await listRecentSessions("tenant-a");
    assert.deepEqual(sessions[0].modules, ["mcp-shield"]);
  });
});

test("the counts and the times are numbers", async () => {
  // Postgres hands back a bigint as a string, and the count as a string
  // when it is cast. The list has to hand the console numbers.
  await withPool(
    { rows: [row({ events: "7", first_ms: "1700000000000", last_ms: "1700000005000" })] },
    async () => {
      const sessions = await listRecentSessions("tenant-a");
      assert.equal(sessions[0].events, 7);
      assert.equal(sessions[0].first_ms, 1_700_000_000_000);
      assert.equal(sessions[0].last_ms, 1_700_000_005_000);
    },
  );
});

test("a time the database did not give is null, not zero", async () => {
  await withPool({ rows: [row({ first_ms: null, last_ms: null })] }, async () => {
    const sessions = await listRecentSessions("tenant-a");
    assert.equal(sessions[0].first_ms, null);
    assert.equal(sessions[0].last_ms, null);
  });
});

test("the database half and the in-memory half agree", async () => {
  const seeds: SeedEvent[] = [
    {
      module: "vector-anchor",
      severity: "info",
      session_id: "sess-old",
      agent_id: "claude-code",
      received_ms: 1_700_000_000_000,
    },
    {
      module: "trace-audit",
      severity: "critical",
      session_id: "sess-new",
      agent_id: "claude-code",
      received_ms: 1_700_000_100_000,
    },
    {
      module: "mcp-shield",
      severity: "warning",
      session_id: "sess-new",
      agent_id: "claude-code",
      received_ms: 1_700_000_200_000,
    },
    // The same session id under a second agent is a second session.
    {
      module: "mcp-shield",
      severity: "info",
      session_id: "sess-new",
      agent_id: "other-agent",
      received_ms: 1_700_000_150_000,
    },
    // An event with no session belongs to no session.
    {
      module: "mcp-shield",
      severity: "critical",
      session_id: null,
      agent_id: "claude-code",
      received_ms: 1_700_000_300_000,
    },
    // Two groups whose halves would run together if the in-memory path
    // joined them without a separator: agent "a" with session "bc", and
    // agent "ab" with session "c".
    {
      module: "mcp-shield",
      severity: "info",
      session_id: "bc",
      agent_id: "a",
      received_ms: 1_700_000_010_000,
    },
    {
      module: "mcp-shield",
      severity: "info",
      session_id: "c",
      agent_id: "ab",
      received_ms: 1_700_000_011_000,
    },
  ];

  clearMemoryEvents();
  await withEnv({ DATABASE_URL: undefined }, async () => {
    await persistEvents(seeds.map(toLedgerEvent));
  });
  const memory = await withEnv({ DATABASE_URL: undefined }, () =>
    listRecentSessions("tenant-a"),
  );

  await withPool({ rows: sqlRowsFor(seeds) }, async () => {
    const postgres = await listRecentSessions("tenant-a");
    assert.equal(postgres.length, memory.length, "the two halves list the same sessions");
    // Five sessions: two of them would run together if the halves of the
    // key were not kept apart.
    assert.equal(memory.length, 5);
    for (let index = 0; index < memory.length; index += 1) {
      const fromMemory = memory[index];
      const fromDatabase = postgres[index];
      assert.equal(fromDatabase.session_id, fromMemory.session_id);
      assert.equal(fromDatabase.agent_id, fromMemory.agent_id);
      assert.equal(fromDatabase.events, fromMemory.events);
      assert.deepEqual(
        [...fromDatabase.modules].sort(),
        [...fromMemory.modules].sort(),
        "the two halves list the same modules",
      );
      assert.equal(fromDatabase.worst_severity, fromMemory.worst_severity);
      assert.equal(fromDatabase.first_ms, fromMemory.first_ms);
      assert.equal(fromDatabase.last_ms, fromMemory.last_ms);
    }
  });
  clearMemoryEvents();
});

test("the route serves the caller's tenant", async () => {
  await withPool({ rows: [row()] }, async () => {
    await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV }, async () => {
      const response = await sessionsGet(
        new Request("http://localhost/api/sessions", {
          headers: { authorization: `Bearer ${VIEWER_TOKEN}` },
        }),
      );
      assert.equal(response.status, 200);
      const body = (await response.json()) as {
        tenant_id: string;
        sessions: { session_id: string }[];
      };
      assert.equal(body.tenant_id, "tenant-a");
      assert.equal(body.sessions.length, 1);
      assert.equal(body.sessions[0].session_id, "sess-a");
    });
  });
});

test("one tenant's list is not another tenant's list", async () => {
  await withPool({ rows: [row()] }, async (statements) => {
    await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV }, async () => {
      const response = await sessionsGet(
        new Request("http://localhost/api/sessions", {
          headers: { authorization: `Bearer ${OTHER_TENANT_TOKEN}` },
        }),
      );
      assert.equal(response.status, 200);
      const body = (await response.json()) as { tenant_id: string };
      assert.equal(body.tenant_id, "tenant-b");
    });
    assert.equal(listQuery(statements).params[0], "tenant-b");
  });
});

test("an unauthenticated caller learns nothing", async () => {
  await withPool({ rows: [row()] }, async (statements) => {
    await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV }, async () => {
      const response = await sessionsGet(new Request("http://localhost/api/sessions"));
      assert.equal(response.status, 401);
    });
    assert.equal(
      statements.filter((statement) =>
        statement.sql.includes("from monolith.security_events"),
      ).length,
      0,
      "no query should run for an unauthenticated caller",
    );
  });
});

test("a limit out of range is refused before the database is touched", async () => {
  await withPool({ rows: [row()] }, async (statements) => {
    await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV }, async () => {
      const response = await sessionsGet(
        new Request("http://localhost/api/sessions?limit=101", {
          headers: { authorization: `Bearer ${VIEWER_TOKEN}` },
        }),
      );
      assert.equal(response.status, 422);
      assert.deepEqual(await response.json(), { error: "limit is out of range" });
    });
    assert.equal(
      statements.filter((statement) =>
        statement.sql.includes("from monolith.security_events"),
      ).length,
      0,
      "no query should run for a limit that was refused",
    );
  });
});

test("a database that is down is a 503, not a crash", async () => {
  await withPool({ fail: true }, async () => {
    await withEnv({ OPERATOR_TOKENS_JSON: OPERATOR_ENV }, async () => {
      const response = await sessionsGet(
        new Request("http://localhost/api/sessions", {
          headers: { authorization: `Bearer ${VIEWER_TOKEN}` },
        }),
      );
      assert.equal(response.status, 503);
      const body = (await response.json()) as { error: string };
      assert.equal(body.error, "the session ledger is temporarily unavailable");
    });
  });
});
