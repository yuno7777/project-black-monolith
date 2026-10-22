// Contract tests for the ingest rate limit: POST /api/ingest must not let
// one module (or one broken module) flood the dashboard and blind the
// operator before a real attack arrives.
//
// No database: the counters fall back to the in-memory table, which is the
// path a dashboard without Postgres runs on, and the budget is configured
// through the environment exactly as an operator would set it.

import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { POST as ingestPost } from "../app/api/ingest/route";
import {
  ingestEventBudget,
  resetMemoryIngestRateLimits,
} from "../lib/ingest-rate-limit";
import { clearMemoryEvents } from "../lib/event-store";

const TOKENS: Record<string, Record<string, string>> = {
  "tenant-alpha": {
    "mcp-shield": "mcp-shield-rate-limit-token-01",
    "vector-anchor": "vector-anchor-rate-limit-token1",
  },
  "tenant-beta": {
    "mcp-shield": "mcp-shield-rate-limit-token-02",
  },
};

const UNKNOWN_TOKEN = "not-a-module-token-00001";

/**
 * Run a body with environment variables set, then put them back.
 *
 * The routes read process.env at call time, so without this a test would
 * inherit whatever the previous one left behind.
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

/** The environment every test in this file runs under. */
function environment(budget?: string): Record<string, string | undefined> {
  return {
    DATABASE_URL: undefined,
    EVENT_INGEST_TOKENS_JSON: JSON.stringify(TOKENS),
    MONOLITH_INGEST_RATE_LIMIT_EVENTS: budget,
  };
}

type PostOptions = {
  /** The credential to present. Defaults to the module's own credential. */
  token?: string;
  /** The address the request claims to come from. */
  address?: string;
};

/** File a batch of events as one module would. */
async function post(
  tenant: string,
  moduleName: string,
  events: number,
  options: PostOptions = {},
): Promise<Response> {
  const token = options.token ?? TOKENS[tenant][moduleName];
  const body = Array.from({ length: events }, (_, index) => ({
    module: moduleName,
    // The id is the module's and the idempotency key, so every event in a
    // batch carries its own — exactly as a module's own emitter does.
    event_id: randomUUID(),
    tenant_id: tenant,
    event_type: "generation_completed",
    severity: "info",
    details: { index },
  }));
  return ingestPost(
    new Request("http://localhost/api/ingest", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
        ...(options.address ? { "x-forwarded-for": options.address } : {}),
      },
      body: JSON.stringify(body),
    }),
  );
}

test("the budget belongs to a module credential, not to an address", async () => {
  await withEnv(environment("5"), async () => {
    resetMemoryIngestRateLimits();
    clearMemoryEvents();

    // Three events from one address, then two from another: the second
    // address spent the first one's remaining budget, because a module's
    // credential — not where it connects from — is what is counted.
    assert.equal((await post("tenant-alpha", "mcp-shield", 3, { address: "203.0.113.7" })).status, 201);
    assert.equal((await post("tenant-alpha", "mcp-shield", 2, { address: "198.51.100.9" })).status, 201);
    assert.equal((await post("tenant-alpha", "mcp-shield", 1, { address: "192.0.2.44" })).status, 429);

    // A different module credential in the same tenant has its own budget.
    assert.equal((await post("tenant-alpha", "vector-anchor", 5)).status, 201);
    assert.equal((await post("tenant-alpha", "vector-anchor", 1)).status, 429);

    // And so does the same module credential in another tenant.
    assert.equal((await post("tenant-beta", "mcp-shield", 5)).status, 201);
    assert.equal((await post("tenant-beta", "mcp-shield", 1)).status, 429);
  });
});

test("a module past its budget is told to wait", async () => {
  await withEnv(environment("2"), async () => {
    resetMemoryIngestRateLimits();
    clearMemoryEvents();

    assert.equal((await post("tenant-alpha", "mcp-shield", 2)).status, 201);
    const refused = await post("tenant-alpha", "mcp-shield", 1);
    assert.equal(refused.status, 429);

    const retryAfter = refused.headers.get("retry-after");
    assert.ok(retryAfter, "a throttled module must be told when to come back");
    assert.match(retryAfter, /^\d+$/);
    assert.ok(Number(retryAfter) >= 1, "Retry-After must be a usable delay");

    // The body names the limit that was hit, so an operator reading the
    // module's logs knows which budget ran out.
    const body = await refused.json();
    assert.equal(body.limit, 2);
    assert.equal(body.limit_window_seconds, 60);
    assert.equal(body.module, "mcp-shield");
    assert.match(body.error, /rate limit/i);
    assert.match(body.error, /2 events/);
  });
});

test("the budget counts events, not requests", async () => {
  await withEnv(environment("100"), async () => {
    resetMemoryIngestRateLimits();
    clearMemoryEvents();

    // One request carrying a hundred events spends the whole budget. A
    // request budget would have let the next request through.
    assert.equal((await post("tenant-alpha", "mcp-shield", 100)).status, 201);
    const refused = await post("tenant-alpha", "mcp-shield", 1);
    assert.equal(refused.status, 429);
    assert.equal((await refused.json()).limit, 100);
  });
});

test("an unauthenticated caller does not spend a module's budget", async () => {
  await withEnv(environment("5"), async () => {
    resetMemoryIngestRateLimits();
    clearMemoryEvents();

    for (let attempt = 0; attempt < 3; attempt += 1) {
      const refused = await post("tenant-alpha", "mcp-shield", 1, { token: UNKNOWN_TOKEN });
      assert.equal(refused.status, 401);
    }

    // The budget is untouched by the calls that were turned away, so the
    // module can still file its five events.
    assert.equal((await post("tenant-alpha", "mcp-shield", 5)).status, 201);
    assert.equal((await post("tenant-alpha", "mcp-shield", 1)).status, 429);
  });
});

test("a mistyped budget setting leaves the default in force", async () => {
  await withEnv(environment("0"), async () => {
    resetMemoryIngestRateLimits();
    clearMemoryEvents();

    // Zero is a mistake, not an off switch.
    assert.equal(ingestEventBudget(), 2000);

    // The default is in force: two thousand events are accepted and the next
    // hundred are not.
    for (let batch = 0; batch < 20; batch += 1) {
      const response = await post("tenant-beta", "mcp-shield", 100);
      assert.equal(response.status, 201, `batch ${batch} should have been accepted`);
    }
    const refused = await post("tenant-beta", "mcp-shield", 100);
    assert.equal(refused.status, 429);
    assert.equal((await refused.json()).limit, 2000);
  });
});

test("an unparseable budget setting leaves the default in force", async () => {
  for (const value of ["", "  ", "many", "1.5", "-1", "1e3", "0x10"]) {
    await withEnv(environment(value), async () => {
      resetMemoryIngestRateLimits();
      clearMemoryEvents();
      assert.equal(ingestEventBudget(), 2000, `${JSON.stringify(value)} must fall back to the default`);
    });
  }

  await withEnv(environment("not-a-number"), async () => {
    resetMemoryIngestRateLimits();
    clearMemoryEvents();
    // A budget that was never understood is the default, so a module with
    // room to spare is not throttled by a setting nobody could read.
    assert.equal((await post("tenant-alpha", "mcp-shield", 100)).status, 201);
  });
});
