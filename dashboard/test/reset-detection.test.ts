// The detector-reset path, tested on the dashboard's side of the wire.
//
// `POST /api/onboarding {"action":"reset-detection"}` is the operator's way of
// clearing the memory layer's frequency history and quarantine without
// running a fixture script by hand. It crosses the wire into VectorAnchor's
// administrative endpoint carrying the module credential — a credential the
// browser must never see.
//
// The module's half of the same contract lives in
// `vector-anchor/tests/test_reset_detection.py`. Between the two, the wire is
// pinned: the URL, the method, the credential, and the shape of the answer.
//
// No database and no live stack: the memory layer is answered by a stubbed
// fetch that records what the dashboard actually sent.
//
// This is a separate file from onboarding.test.ts on purpose — that file is
// edited by another working session, and a test file that two people edit at
// once is a merge conflict waiting to happen.

import assert from "node:assert/strict";
import test from "node:test";
import { POST as onboardingPost } from "../app/api/onboarding/route";
import { ONBOARDING_ACTIONS, type OnboardingAction } from "../lib/onboarding-actions";

const ADMIN_TOKEN = "admin-operator-token-000000";
const VIEWER_TOKEN = "viewer-operator-token-00000";
const MODULE_TOKEN = "module-admin-token-0000000";
const VECTOR_URL = "http://127.0.0.1:8001";

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
    VECTOR_ANCHOR_INTERNAL_URL: VECTOR_URL,
    MONOLITH_MODULE_ADMIN_TOKEN: MODULE_TOKEN,
    DATABASE_URL: undefined,
  };
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

function postReset(token = ADMIN_TOKEN): Request {
  return new Request("http://localhost/api/onboarding", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ action: "reset-detection" }),
  });
}

test("the reset is an administrator's action", async () => {
  await withEnv(operators(), async () => {
    await withStubbedFetch(
      () => {
        throw new Error("the memory layer must not be called for a viewer");
      },
      async () => {
        const response = await onboardingPost(postReset(VIEWER_TOKEN));
        assert.equal(response.status, 403);
      },
    );
  });
});

test("the reset reaches the memory layer's administrative endpoint", async () => {
  await withEnv(operators(), async () => {
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    await withStubbedFetch(
      (url, init) => {
        seen.push({ url, init });
        return Response.json({ status: "reset" });
      },
      async () => {
        const response = await onboardingPost(postReset());
        assert.equal(response.status, 200);
      },
    );

    assert.equal(seen.length, 1);
    assert.equal(seen[0].url, `${VECTOR_URL}/admin/reset-detection`);
    assert.equal(seen[0].init?.method, "POST");
    const headers = new Headers(seen[0].init?.headers);
    // The module credential travels to the module — never to the browser.
    assert.equal(headers.get("authorization"), `Bearer ${MODULE_TOKEN}`);
    // The module's endpoint takes no body, so the dashboard sends none.
    assert.equal(seen[0].init?.body, undefined);
  });
});

test("the reset reports what it did", async () => {
  await withEnv(operators(), async () => {
    await withStubbedFetch(
      () => Response.json({ status: "reset" }),
      async () => {
        const response = await onboardingPost(postReset());
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), {
          action: "reset-detection",
          status: "reset",
        });
      },
    );
  });
});

test("a memory layer that refuses the reset is a failure, not a reset", async () => {
  await withEnv(operators(), async () => {
    await withStubbedFetch(
      () => new Response("no", { status: 401 }),
      async () => {
        const response = await onboardingPost(postReset());
        assert.equal(response.status, 503);
        const body = await response.json();
        // The operator must not be told the detector was cleared when it was
        // not.
        assert.equal(body.status, undefined);
        assert.match(String(body.error), /401/);
      },
    );
  });
});

test("a memory layer that cannot be reached is a failure", async () => {
  await withEnv(operators(), async () => {
    await withStubbedFetch(
      () => {
        throw new Error("ECONNREFUSED");
      },
      async () => {
        const response = await onboardingPost(postReset());
        assert.equal(response.status, 503);
        const body = await response.json();
        assert.equal(body.status, undefined);
      },
    );
  });
});

test("the reset response never carries a credential back to the browser", async () => {
  await withEnv(operators(), async () => {
    await withStubbedFetch(
      () => Response.json({ status: "reset" }),
      async () => {
        const response = await onboardingPost(postReset());
        const text = await response.text();
        assert.ok(!text.includes(MODULE_TOKEN), "the module token leaked into the response");
        assert.ok(!text.includes(ADMIN_TOKEN), "the operator token leaked into the response");
      },
    );
  });
});

/**
 * What each action the surface offers is expected to do to the memory layer.
 *
 * The table has to cover every action in `ONBOARDING_ACTIONS`: an action
 * added there without an entry here fails the test below, rather than
 * quietly falling through to the branch that clears the detector.
 */
const EXPECTED: Record<OnboardingAction, { path: string; body?: unknown }> = {
  "seed-corpus": { path: "/admin/seed-demo", body: { include_bait: false } },
  "seed-bait": { path: "/admin/seed-demo", body: { include_bait: true } },
  "reset-detection": { path: "/admin/reset-detection" },
};

test("every action the onboarding surface offers reaches the memory layer", async () => {
  assert.deepEqual(
    Object.keys(EXPECTED).sort(),
    [...ONBOARDING_ACTIONS].sort(),
    "every action the surface offers needs an expectation here",
  );

  for (const action of ONBOARDING_ACTIONS) {
    await withEnv(operators(), async () => {
      const seen: Array<{ url: string; init?: RequestInit }> = [];
      await withStubbedFetch(
        (url, init) => {
          seen.push({ url, init });
          return Response.json({ added: 60, total: 60, bait: false, status: "reset" });
        },
        async () => {
          const response = await onboardingPost(
            new Request("http://localhost/api/onboarding", {
              method: "POST",
              headers: {
                authorization: `Bearer ${ADMIN_TOKEN}`,
                "content-type": "application/json",
              },
              body: JSON.stringify({ action }),
            }),
          );
          assert.equal(response.status, 200, `action ${action} should have been carried out`);
        },
      );

      assert.equal(seen.length, 1, `action ${action} should reach the memory layer once`);
      assert.match(seen[0].url, new RegExp(`${EXPECTED[action].path}$`));
      if (EXPECTED[action].body === undefined) {
        assert.equal(seen[0].init?.body, undefined);
      } else {
        assert.deepEqual(JSON.parse(String(seen[0].init?.body)), EXPECTED[action].body);
      }
    });
  }
});
