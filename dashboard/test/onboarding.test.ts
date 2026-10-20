// Contract tests for the onboarding surface: GET /api/onboarding,
// POST /api/onboarding and GET /api/sessions.
//
// This is a separate file from contracts.test.ts on purpose — that file is
// edited by another working session, and a test file that two people edit at
// once is a merge conflict waiting to happen.
//
// No database and no live stack: the session list is exercised through the
// in-memory ledger, and the calls to the memory layer are answered by a
// stubbed fetch that records what the dashboard actually sent.

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { GET as onboardingGet, POST as onboardingPost } from "../app/api/onboarding/route";
import { GET as sessionsGet } from "../app/api/sessions/route";
import { clearMemoryEvents, normalizeEvent, persistEvents } from "../lib/event-store";

const ADMIN_TOKEN = "admin-operator-token-000000";
const VIEWER_TOKEN = "viewer-operator-token-00000";
const MODULE_TOKEN = "module-admin-token-0000000";

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
function operators(): Record<string, string | undefined> {
  return {
    MONOLITH_DISABLE_AUTH: "false",
    OPERATOR_TOKENS_JSON: JSON.stringify({
      admin: { token: ADMIN_TOKEN, role: "admin", tenant_id: "tenant-a" },
      reader: { token: VIEWER_TOKEN, role: "viewer", tenant_id: "tenant-a" },
    }),
    VECTOR_ANCHOR_INTERNAL_URL: "http://127.0.0.1:8001",
    MONOLITH_MODULE_ADMIN_TOKEN: MODULE_TOKEN,
    DATABASE_URL: undefined,
  };
}

function asOperator(token: string, url = "http://localhost/api/onboarding", method = "GET") {
  return new Request(url, {
    method,
    headers: { authorization: `Bearer ${token}` },
  });
}

/** Answer every fetch with a canned body and record what was asked for. */
async function withStubbedFetch(
  responder: (url: string, init?: RequestInit) => Response | Promise<Response>,
  body: () => void | Promise<void>,
): Promise<void> {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    return responder(url, init);
  }) as typeof globalThis.fetch;
  try {
    await body();
  } finally {
    globalThis.fetch = original;
  }
}

test("the onboarding routes refuse an unauthenticated caller", async () => {
  await withEnv(operators(), async () => {
    const read = await onboardingGet(new Request("http://localhost/api/onboarding"));
    assert.equal(read.status, 401);

    const sessions = await sessionsGet(new Request("http://localhost/api/sessions"));
    assert.equal(sessions.status, 401);

    const write = await onboardingPost(
      new Request("http://localhost/api/onboarding", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "seed-corpus" }),
      }),
    );
    assert.equal(write.status, 401);
  });
});

test("seeding the corpus is an administrator's action", async () => {
  await withEnv(operators(), async () => {
    const response = await onboardingPost(
      asOperator(VIEWER_TOKEN, "http://localhost/api/onboarding", "POST"),
    );
    assert.equal(response.status, 403);
  });
});

test("an unknown onboarding action is rejected before anything is called", async () => {
  await withEnv(operators(), async () => {
    await withStubbedFetch(
      () => {
        throw new Error("the module must not be called for an unknown action");
      },
      async () => {
        const response = await onboardingPost(
          new Request("http://localhost/api/onboarding", {
            method: "POST",
            headers: {
              authorization: `Bearer ${ADMIN_TOKEN}`,
              "content-type": "application/json",
            },
            body: JSON.stringify({ action: "delete-everything" }),
          }),
        );
        assert.equal(response.status, 422);
        assert.deepEqual(await response.json(), { error: "unknown onboarding action" });
      },
    );
  });
});

test("the admin seed reaches the memory layer with the module credential", async () => {
  await withEnv(operators(), async () => {
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    await withStubbedFetch(
      (url, init) => {
        seen.push({ url, init });
        return Response.json({ added: 60, total: 60, bait: false });
      },
      async () => {
        const response = await onboardingPost(
          new Request("http://localhost/api/onboarding", {
            method: "POST",
            headers: {
              authorization: `Bearer ${ADMIN_TOKEN}`,
              "content-type": "application/json",
            },
            body: JSON.stringify({ action: "seed-corpus" }),
          }),
        );
        assert.equal(response.status, 200);
        const body = await response.json();
        assert.equal(body.action, "seed-corpus");
        assert.equal(body.added, 60);
        assert.equal(body.total, 60);
        assert.equal(body.bait, false);
      },
    );

    assert.equal(seen.length, 1);
    assert.match(seen[0].url, /\/admin\/seed-demo$/);
    const headers = new Headers(seen[0].init?.headers);
    // The module credential travels to the module — never to the browser.
    assert.equal(headers.get("authorization"), `Bearer ${MODULE_TOKEN}`);
    assert.deepEqual(JSON.parse(String(seen[0].init?.body)), { include_bait: false });
  });
});

test("the seeded response never carries a credential back to the browser", async () => {
  await withEnv(operators(), async () => {
    await withStubbedFetch(
      () => Response.json({ added: 60, total: 60, bait: true }),
      async () => {
        const response = await onboardingPost(
          new Request("http://localhost/api/onboarding", {
            method: "POST",
            headers: {
              authorization: `Bearer ${ADMIN_TOKEN}`,
              "content-type": "application/json",
            },
            body: JSON.stringify({ action: "seed-bait" }),
          }),
        );
        assert.equal(response.status, 200);
        const text = await response.text();
        assert.ok(!text.includes(MODULE_TOKEN), "the module token leaked into the response");
        assert.ok(!text.includes(ADMIN_TOKEN), "the operator token leaked into the response");
        assert.equal(JSON.parse(text).bait, true);
      },
    );
  });
});

test("the session list is newest first and carries the module set", async () => {
  await withEnv(operators(), async () => {
    clearMemoryEvents();
    const older = randomUUID();
    const newer = randomUUID();
    // Both halves order by the time the dashboard received the event, so the
    // received time is what has to be set here — the in-memory path stamps it
    // with the clock if it is missing, which would make the order a coin toss.
    const event = (over: Record<string, unknown>, received_ms: number) => ({
      ...normalizeEvent(over),
      received_ms,
    });
    await persistEvents([
      event(
        {
          event_id: randomUUID(),
          module: "vector-anchor",
          event_type: "retrieval",
          severity: "info",
          session_id: older,
          agent_id: "claude-code",
          tenant_id: "tenant-a",
          timestamp_ms: 1_700_000_000_000,
        },
        1_700_000_000_000,
      ),
      event(
        {
          event_id: randomUUID(),
          module: "trace-audit",
          event_type: "pii_redacted",
          severity: "critical",
          session_id: newer,
          agent_id: "claude-code",
          tenant_id: "tenant-a",
          timestamp_ms: 1_700_000_100_000,
        },
        1_700_000_100_000,
      ),
      event(
        {
          event_id: randomUUID(),
          module: "mcp-shield",
          event_type: "schema_mismatch",
          severity: "warning",
          session_id: newer,
          agent_id: "claude-code",
          tenant_id: "tenant-a",
          timestamp_ms: 1_700_000_200_000,
        },
        1_700_000_200_000,
      ),
    ]);

    const response = await sessionsGet(asOperator(VIEWER_TOKEN, "http://localhost/api/sessions"));
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.tenant_id, "tenant-a");
    assert.equal(body.sessions.length, 2);
    const top = body.sessions[0];
    assert.equal(top.session_id, newer);
    assert.equal(top.agent_id, "claude-code");
    assert.equal(top.events, 2);
    assert.deepEqual(top.modules.sort(), ["mcp-shield", "trace-audit"]);
    assert.equal(top.worst_severity, "critical");
    assert.equal(body.sessions[1].session_id, older);
  });
});

test("the session list rejects a limit that is not a sane count", async () => {
  await withEnv(operators(), async () => {
    for (const limit of ["0", "-1", "101", "many", "1.5"]) {
      const response = await sessionsGet(
        asOperator(VIEWER_TOKEN, `http://localhost/api/sessions?limit=${limit}`),
      );
      assert.equal(response.status, 422, `limit=${limit} should be rejected`);
      assert.deepEqual(await response.json(), { error: "limit is out of range" });
    }
  });
});

test("the onboarding state describes the stack without leaking a credential", async () => {
  await withEnv(operators(), async () => {
    clearMemoryEvents();
    await withStubbedFetch(
      (url) => {
        if (url.includes("/stats")) {
          return Response.json({ documents: 60, quarantined: 0 });
        }
        return Response.json({ status: "ok" });
      },
      async () => {
        const response = await onboardingGet(asOperator(ADMIN_TOKEN));
        assert.equal(response.status, 200);
        const body = await response.json();
        assert.equal(body.tenant_id, "tenant-a");
        assert.equal(body.role, "admin");
        assert.equal(body.corpus.documents, 60);
        assert.ok(Array.isArray(body.steps));
        assert.ok(body.steps.length > 0);
        for (const step of body.steps) {
          assert.ok(["ready", "todo", "blocked", "unknown"].includes(step.state));
        }
        const text = JSON.stringify(body);
        assert.ok(!text.includes(MODULE_TOKEN), "the module token leaked into the state");
        assert.ok(!text.includes(ADMIN_TOKEN), "the operator token leaked into the state");
      },
    );
  });
});
