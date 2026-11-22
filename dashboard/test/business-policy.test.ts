import assert from "node:assert/strict";
import test from "node:test";
import {
  BUSINESS_TEMPLATES,
  BusinessPolicyError,
  DEFAULT_BUSINESS_POLICY,
  evaluateBusinessAction,
  parseBusinessAction,
  parseBusinessPolicy,
  practiceBusinessAction,
  validateTemplateAction,
} from "../lib/business-policy";

const policy = DEFAULT_BUSINESS_POLICY;
const refund = { kind: "refund", orderId: "order-5", destination: "original-payment-5", amountMinor: 10000, currency: "USD" };
const reply = { kind: "customer_reply", recipient: "customer-5", body: "  Approved.\nThank you.\n" };
const refundId = "678ee072-2f32-40b5-9a2f-2805995a8f3a";

test("refund routing uses an exclusive threshold and never converts currencies", () => {
  for (const [amountMinor, expected] of [[9999, "support"], [10000, "support"], [10001, "finance"]] as const) {
    const action = parseBusinessAction({ ...refund, amountMinor });
    assert.equal(evaluateBusinessAction(action, policy).reviewerTeam, expected);
    assert.deepEqual(practiceBusinessAction(action, policy, "refund"), { ok: true, ...evaluateBusinessAction(action, policy) });
  }
  assert.equal(practiceBusinessAction({ ...refund, currency: "EUR" }, policy).ok, false);
  const yen = parseBusinessPolicy({ ...policy, currency: "JPY", refundThresholdMinor: 0, financeTeam: "accounts-payable" });
  assert.equal(evaluateBusinessAction(parseBusinessAction({ ...refund, amountMinor: 1, currency: "JPY" }), yen).reviewerTeam, "accounts-payable");
});

test("invalid monetary data and invalid rules fail closed in both validation and preview", () => {
  for (const amountMinor of [undefined, null, "100", 0, -1, 0.001, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => parseBusinessAction({ ...refund, amountMinor }), BusinessPolicyError);
    assert.equal(practiceBusinessAction({ ...refund, amountMinor }, policy).ok, false);
  }
  for (const invalid of [
    { ...policy, currency: "Bitcoin" }, { ...policy, refundThresholdMinor: -1 },
    { ...policy, defaultTeam: "support\n" }, { ...policy, financeTeam: "" }, { ...policy, autoApprove: true },
  ]) {
    assert.throws(() => parseBusinessPolicy(invalid), BusinessPolicyError);
    assert.equal(practiceBusinessAction(refund, invalid).ok, false);
  }
});

test("exact actions retain content and stable field order and reject hidden extra fields", () => {
  const reversed = parseBusinessAction({ body: reply.body, recipient: reply.recipient, kind: reply.kind });
  assert.deepEqual(reversed, reply);
  assert.equal(JSON.stringify(reversed), JSON.stringify(parseBusinessAction(reply)));
  for (const invalid of [
    { ...reply, cc: "other" }, { ...reply, body: " " }, { ...reply, recipient: "customer\ncc" },
    { ...reply, body: "a\u0000b" }, { ...reply, body: "€".repeat(4001) },
    { ...refund, destination: "" }, { ...refund, kind: "transfer" },
  ]) assert.throws(() => parseBusinessAction(invalid), BusinessPolicyError);
});

test("each template restricts actions and the refund follow-up requires an explicit dependency", () => {
  assert.deepEqual(BUSINESS_TEMPLATES.map(({ id }) => id).sort(), ["invoice", "refund", "sales", "support"]);
  const invoice = parseBusinessAction({ kind: "invoice_review", invoiceId: "inv-471", note: "Incorrect discount" });
  assert.equal(validateTemplateAction("invoice", invoice), "invoice");
  assert.equal(evaluateBusinessAction(invoice, policy).reviewerTeam, "finance");
  const update = parseBusinessAction({ kind: "crm_update", recordId: "deal-9", field: "stage", value: "qualified" });
  assert.equal(validateTemplateAction("sales", update), "sales");
  for (const template of ["refund", "support", "invoice"]) {
    assert.equal(practiceBusinessAction(update, policy, template).ok, false);
  }
  assert.equal(practiceBusinessAction(reply, policy, "support").ok, true);
  assert.equal(practiceBusinessAction(reply, policy, "refund").ok, false);
  assert.equal(practiceBusinessAction({ ...reply, afterRefundId: refundId }, policy, "refund").ok, true);
  assert.equal(practiceBusinessAction({ ...reply, afterRefundId: refundId }, policy, "sales").ok, false);
  assert.equal(practiceBusinessAction({ ...reply, afterRefundId: "not-a-decision" }, policy, "refund").ok, false);
});
