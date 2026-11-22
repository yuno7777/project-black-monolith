import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { businessDispatcher, reviewerTeams } from "../lib/business-connector";
import { businessBody, businessOperator, businessWorkload } from "../lib/business-http";

const tenant = "shop";
const token = "unit-test-connector-credential";
const url = "https://customer.test/adapter";
const id = randomUUID();
const action = {kind: "refund" as const, orderId: "order-12", destination: "original", amountMinor: 500, currency: "USD" as const};

function env(t: {after: (callback: () => void) => void}, key: string, value: string) {
  const previous = process.env[key];
  process.env[key] = value;
  t.after(() => {
    if (previous === undefined) delete process.env[key];
    else process.env[key] = previous;
  });
}

test("review memberships are specific to the exact actor and tenant", t => {
  env(t, "MONOLITH_BUSINESS_REVIEWERS_JSON", JSON.stringify([
    { tenant, actor: "sam", teams: ["finance"] }, { tenant: "other", actor: "sam", teams: ["support"] },
  ]));
  assert.deepEqual(reviewerTeams(tenant, "sam"), ["finance"]);
  assert.deepEqual(reviewerTeams("other", "sam"), ["support"]);
  assert.deepEqual(reviewerTeams(tenant, "Sam"), []);
  process.env.MONOLITH_BUSINESS_REVIEWERS_JSON = JSON.stringify(Array(2).fill({ tenant, actor: "sam", teams: ["finance"] }));
  assert.throws(() => reviewerTeams(tenant, "sam"), /ambiguous/);
});

test("configuration selects an explicit tenant endpoint and refuses plaintext, URL secrets, and ambiguous routes", t => {
  env(t, "MONOLITH_BUSINESS_CONNECTORS_JSON", "[]");
  assert.throws(() => businessDispatcher(tenant), /configure a connector/);
  for (const bad of ["http://customer.test", "https://x:y@customer.test", "http://localhost.evil.test", "https://customer.test?key=x"]) {
    process.env.MONOLITH_BUSINESS_CONNECTORS_JSON = JSON.stringify([{tenant, token, url: bad}]);
    assert.throws(() => businessDispatcher(tenant), /URL is invalid/);
  }
  process.env.MONOLITH_BUSINESS_CONNECTORS_JSON = JSON.stringify(Array(2).fill({ tenant, token, url }));
  assert.throws(() => businessDispatcher(tenant), /multiple connectors/);
});

test("only a bounded exact-ID receipt yields a definitive connector outcome", async t => {
  env(t, "MONOLITH_BUSINESS_CONNECTORS_JSON", JSON.stringify([{ tenant, token, url }]));
  const dispatch = businessDispatcher(tenant);
  const responses = [
    Response.json({id, status: "succeeded", reference: "refund-12"}),
    Response.json({id, status: "failed", reference: "rejected-12"}),
    Response.json({id: randomUUID(), status: "succeeded", reference: "incorrect"}),
    Response.json({id, status: "succeeded", reference: "x".repeat(4096)}),
    Response.json({id, status: "succeeded", reference: "late"}, {status: 202}),
  ];
  const calls = t.mock.method(globalThis, "fetch", async (target: string, init: RequestInit) => {
    assert.equal(target, url);
    assert.equal(init.redirect, "error");
    const headers = new Headers(init.headers);
    assert.equal(headers.get("idempotency-key"), id);
    assert.equal(headers.get("authorization"), "Bearer " + token);
    assert.deepEqual(JSON.parse(String(init.body)), {id, tenant, action});
    const response = responses.shift();
    if (!response) throw new TypeError("lost acknowledgement");
    return response;
  });
  assert.deepEqual(await dispatch(id, action), {status: "succeeded", reference: "refund-12"});
  assert.deepEqual(await dispatch(id, action), {status: "failed", reference: "rejected-12"});
  for (let i = 0; i < 4; i++) assert.deepEqual(await dispatch(id, action), {status: "uncertain"});
  assert.equal(calls.mock.callCount(), 6);
});

test("workspace rejects demo identity and caller-supplied authorization fields", async t => {
  env(t, "MONOLITH_DISABLE_AUTH", "true");
  const req = new Request("http://localhost/workspace", {
    method: "POST", body: JSON.stringify({action, tenant: "another"}),
  });
  await assert.rejects(businessOperator(req, "viewer"), /authentication/);
  assert.throws(() => businessWorkload(req), /authentication/);
  await assert.rejects(businessBody(req, ["action"]), /unexpected/);
});
