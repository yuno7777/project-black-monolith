import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";
import { POST as review } from "../app/api/github/triage/[id]/route";
import { GET as list, POST as propose } from "../app/api/github/triage/route";
import { GET as read } from "../app/api/github/issues/[issue]/route";
import { getDb } from "../lib/db";
import { actionDigest, githubAction, issueNumber } from "../lib/github-triage";

test("issue and action validation preserve exact approved bytes", () => {
  assert.equal(issueNumber(1), 1);
  assert.throws(() => issueNumber("1"));
  assert.throws(() => githubAction({ kind: "remove_label", value: ".." }));
  assert.throws(() => githubAction({ kind: "reply", value: "   " }));
  const workload = { tenant: "a", agent: "b", session: "c" };
  const action = githubAction({ kind: "reply", value: " Reply\n" });
  const digest = actionDigest(workload, "test/issues", 1, action);
  assert.equal(action.value, " Reply\n");
  assert.notEqual(digest, actionDigest(workload, "test/issues", 2, action));
  assert.notEqual(digest, actionDigest(workload, "test/issues", 1, { ...action, value: "Reply" }));
});

test("PostgreSQL-backed triage sends each approved action once", {
  skip: !process.env.MONOLITH_TRIAGE_TEST_DATABASE_ADMIN_URL || !process.env.DATABASE_URL,
}, async (t) => {
  const fixtureId = randomUUID();
  const tenant = `test-${fixtureId}`;
  const agent = "agent";
  const session = "session";
  const workloadToken = `workload-test-${fixtureId}`;
  const operatorToken = `reviewer-test-${fixtureId}`;
  const otherOperatorToken = `unrelated-reviewer-test-${fixtureId}`;
  const admin = new Pool({ connectionString: process.env.MONOLITH_TRIAGE_TEST_DATABASE_ADMIN_URL });
  t.after(async () => {
    await admin.query("delete from monolith.github_triage_actions where tenant_id = $1", [tenant]);
    await admin.query("delete from monolith.revoked_sessions where tenant_id = $1", [tenant]);
    await admin.end();
    await getDb().end();
  });

  process.env.MONOLITH_GITHUB_REPOSITORY = "example/test-repository";
  process.env.MONOLITH_GITHUB_TOKEN = `github-test-${fixtureId}`;
  process.env.MONOLITH_TENANT_ID = tenant;
  process.env.MONOLITH_WORKLOAD_GRANTS_JSON = JSON.stringify([{
    agent_id: agent, session_id: session,
    token_sha256: createHash("sha256").update(workloadToken).digest("hex"),
  }]);
  process.env.OPERATOR_TOKENS_JSON = JSON.stringify({
    reviewer: { token: operatorToken, role: "analyst", tenant_id: tenant },
    other: { token: otherOperatorToken, role: "analyst", tenant_id: `${tenant}-other` },
  });
  const writes: { url: string; method?: string; body?: BodyInit | null }[] = [];
  let ambiguousWrite = false;
  t.mock.method(globalThis, "fetch", async (url: string, init: RequestInit) => {
    assert.ok(url.startsWith("https://api.github.com/repos/example/test-repository/issues/"));
    if (init.method === "GET") return Response.json({ title: "Fixture issue", body: "An issue", labels: [] });
    writes.push({ url, method: init.method, body: init.body });
    if (ambiguousWrite) throw new TypeError("fixture response lost");
    return url.endsWith("/comments") ? Response.json({ id: 42 }, { status: 201 }) : Response.json([]);
  });

  const api = "http://localhost/api/github";
  const workload = { "x-monolith-workload-token": workloadToken };
  const reviewer = { authorization: `Bearer ${operatorToken}` };
  const other = { authorization: `Bearer ${otherOperatorToken}` };
  const request = (path: string, headers: Record<string, string>, body?: unknown) => new Request(`${api}${path}`, {
    headers: { ...headers, "content-type": "application/json" },
    method: body === undefined ? "GET" : "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const draft = async (kind = "reply", value = "Exact draft", requestId = randomUUID()) => {
    const response = await propose(request("/triage", workload, { request_id: requestId, issue: 7, action: { kind, value } }));
    assert.equal(response.status, 202);
    return (await response.json()).action as { id: string; digest: string; status: string };
  };
  const decide = (action: { id: string; digest: string }, decision = "approve", headers: Record<string, string> = reviewer) => review(
    request(`/triage/${action.id}`, headers, { decision, digest: action.digest }),
    { params: Promise.resolve({ id: action.id }) },
  );
  const expectStatus = async (response: Response, expected: string) => {
    assert.equal(response.status, 200);
    assert.equal((await response.json()).action.status, expected);
  };

  const issue = { params: Promise.resolve({ issue: "7" }) };
  assert.equal((await read(request("/issues/7", {}), issue)).status, 401);
  assert.equal((await read(request("/issues/7", { ...workload, "x-monolith-tenant-id": "other" }), issue)).status, 403);
  assert.equal((await (await read(request("/issues/7", workload), issue)).json()).title, "Fixture issue");

  const requestId = randomUUID();
  const reply = await draft("reply", " Exact draft\n", requestId);
  assert.equal((await draft("reply", " Exact draft\n", requestId)).id, reply.id);
  const changed = await propose(request("/triage", workload, {
    request_id: requestId, issue: 7, action: { kind: "reply", value: "Changed draft" },
  }));
  assert.equal(changed.status, 409);
  assert.equal((await decide({ ...reply, digest: "0".repeat(64) })).status, 409);
  assert.equal((await decide(reply, "approve", other)).status, 404);
  assert.equal((await decide(reply, "approve", workload)).status, 401);
  assert.equal(writes.length, 0);

  const concurrent = await Promise.all([decide(reply), decide(reply)]);
  assert.deepEqual(concurrent.map((response) => response.status).sort(), [200, 409]);
  await expectStatus(concurrent.find((response) => response.status === 200)!, "succeeded");
  assert.equal(writes[0].body, JSON.stringify({ body: " Exact draft\n" }));
  assert.equal(writes.length, 1);

  const denied = await draft("add_label", "needs-review");
  await expectStatus(await decide(denied, "deny"), "denied");
  assert.equal((await decide(denied)).status, 409);
  const expired = await draft();
  await admin.query("update monolith.github_triage_actions set expires_at = now() where id = $1", [expired.id]);
  await expectStatus(await decide(expired), "expired");
  assert.equal(writes.length, 1);

  const label = await draft("add_label", "needs-review");
  await expectStatus(await decide(label), "succeeded");
  assert.equal(writes[1].body, JSON.stringify({ labels: ["needs-review"] }));
  const removal = await draft("remove_label", "needs review / test");
  await expectStatus(await decide(removal), "succeeded");
  assert.match(writes[2].url, /\/labels\/needs%20review%20%2F%20test$/);
  assert.equal(writes[2].method, "DELETE");

  const uncertain = await draft();
  ambiguousWrite = true;
  await expectStatus(await decide(uncertain), "uncertain");
  assert.equal((await decide(uncertain)).status, 409);
  const revoked = await draft();
  assert.equal((await decide(revoked, "revoke_session", other)).status, 404);
  assert.equal((await decide(revoked, "revoke_session")).status, 200);
  await expectStatus(await decide(revoked), "revoked");
  assert.equal((await read(request("/issues/7", workload), issue)).status, 403);
  assert.equal(writes.length, 4);

  const audit = await (await list(request("/triage", reviewer))).json();
  assert.equal(audit.can_review, true);
  assert.equal(audit.actions.find((action: { id: string }) => action.id === reply.id).github_comment_id, "42");
  assert.ok(audit.actions.every((action: { session_revoked_at: string | null }) => action.session_revoked_at));
  assert.deepEqual((await (await list(request("/triage", other))).json()).actions, []);
});
