// This module is shared by the dashboard policy preview and the server's proposal
// validation. Keep it deterministic and independent of storage and connectors.
export const BUSINESS_CURRENCIES = ["USD", "EUR", "GBP", "CAD", "AUD", "JPY"] as const;
type Currency = typeof BUSINESS_CURRENCIES[number];

export type BusinessAction =
  | { kind: "refund"; orderId: string; destination: string; amountMinor: number; currency: Currency }
  | { kind: "customer_reply"; recipient: string; body: string; afterRefundId?: string }
  | { kind: "crm_update"; recordId: string; field: string; value: string }
  | { kind: "invoice_review"; invoiceId: string; note: string };

export type BusinessActionKind = BusinessAction["kind"];
export type BusinessTemplateId = "support" | "sales" | "invoice" | "refund";
export type BusinessPolicy = {
  refundThresholdMinor: number;
  currency: Currency;
  defaultTeam: string;
  financeTeam: string;
};

export const DEFAULT_BUSINESS_POLICY: Readonly<BusinessPolicy> = Object.freeze({
  refundThresholdMinor: 10000, currency: "USD", defaultTeam: "support", financeTeam: "finance",
});

type Template = {
  id: BusinessTemplateId;
  name: string;
  description: string;
  actionKinds: readonly BusinessActionKind[];
};

export const BUSINESS_TEMPLATES: readonly Template[] = [
  { id: "support", name: "Customer support", description: "Review a reply to a customer.", actionKinds: ["customer_reply"] },
  { id: "sales", name: "Sales follow-up", description: "Review CRM updates and customer messages individually.", actionKinds: ["crm_update", "customer_reply"] },
  { id: "invoice", name: "Invoice review", description: "Send an invoice review note to the finance team for approval.", actionKinds: ["invoice_review"] },
  { id: "refund", name: "Customer refund", description: "Review a refund and a follow-up message after confirmation.", actionKinds: ["refund", "customer_reply"] },
];

export class BusinessPolicyError extends Error {}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BusinessPolicyError("Expected an object.");
  }
  return value as Record<string, unknown>;
}

function fields(value: Record<string, unknown>, required: string[], optional: string[] = []) {
  if (!required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) ||
      Object.keys(value).some((key) => !required.includes(key) && !optional.includes(key))) {
    throw new BusinessPolicyError("Unexpected or missing fields.");
  }
}

function text(value: unknown, field: string, maxBytes: number, multiline = false): string {
  const invalidControl = multiline ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/ : /[\u0000-\u001f\u007f]/;
  if (typeof value !== "string" || !value.trim() || (!multiline && value !== value.trim()) ||
      invalidControl.test(value) || new TextEncoder().encode(value).length > maxBytes) {
    throw new BusinessPolicyError(`Invalid ${field}.`);
  }
  return value;
}

function team(value: unknown): string {
  if (typeof value !== "string" || value !== value.trim() || !/^[a-z][a-z0-9_-]{0,63}$/.test(value)) {
    throw new BusinessPolicyError("Use a team ID of up to 64 lowercase letters, digits, underscores or hyphens.");
  }
  return value;
}

function currency(value: unknown): Currency {
  const match = BUSINESS_CURRENCIES.find((supported) => supported === value);
  if (!match) throw new BusinessPolicyError("Unsupported currency.");
  return match;
}

function minorUnits(value: unknown, minimum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    throw new BusinessPolicyError(`Amount in minor units must be a safe integer of at least ${minimum}.`);
  }
  return value;
}

export function parseBusinessPolicy(input: unknown): BusinessPolicy {
  const value = object(input);
  fields(value, ["refundThresholdMinor", "currency", "defaultTeam", "financeTeam"]);
  return {
    refundThresholdMinor: minorUnits(value.refundThresholdMinor, 0),
    currency: currency(value.currency),
    defaultTeam: team(value.defaultTeam),
    financeTeam: team(value.financeTeam),
  };
}

// Reconstruct in stable field order so JSON serialization is independent of
// input key order. Preserve the exact approved message and reference strings.
export function parseBusinessAction(input: unknown): BusinessAction {
  const value = object(input);
  const kind = value.kind;
  switch (kind) {
    case "refund":
      fields(value, ["kind", "orderId", "destination", "amountMinor", "currency"]);
      return {
        kind, orderId: text(value.orderId, "order reference", 256),
        destination: text(value.destination, "refund destination", 256),
        amountMinor: minorUnits(value.amountMinor, 1), currency: currency(value.currency),
      };
    case "customer_reply": {
      fields(value, ["kind", "recipient", "body"], ["afterRefundId"]);
      const action: BusinessAction = {
        kind, recipient: text(value.recipient, "recipient", 256),
        body: text(value.body, "message", 12000, true),
      };
      if ("afterRefundId" in value) {
        const id = text(value.afterRefundId, "refund decision ID", 36);
        if (!/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/.test(id)) {
          throw new BusinessPolicyError("Expected a lowercase UUID for the refund decision.");
        }
        action.afterRefundId = id;
      }
      return action;
    }
    case "crm_update":
      fields(value, ["kind", "recordId", "field", "value"]);
      return {
        kind, recordId: text(value.recordId, "CRM record", 256),
        field: text(value.field, "CRM field", 128), value: text(value.value, "CRM value", 4000, true),
      };
    case "invoice_review":
      fields(value, ["kind", "invoiceId", "note"]);
      return { kind, invoiceId: text(value.invoiceId, "invoice reference", 256), note: text(value.note, "review note", 4000, true) };
    default:
      throw new BusinessPolicyError("Unsupported action kind.");
  }
}

export function validateTemplateAction(templateId: unknown, action: BusinessAction): BusinessTemplateId {
  const template = BUSINESS_TEMPLATES.find(({ id }) => id === templateId);
  if (!template || !template.actionKinds.includes(action.kind)) {
    throw new BusinessPolicyError("This action is unavailable in the selected workflow.");
  }
  if (action.kind === "customer_reply" && Boolean(action.afterRefundId) !== (template.id === "refund")) {
    throw new BusinessPolicyError("Only a refund workflow reply can and must reference its refund decision.");
  }
  return template.id;
}

export function evaluateBusinessAction(action: BusinessAction, policy: BusinessPolicy) {
  if (action.kind === "refund") {
    if (action.currency !== policy.currency) {
      throw new BusinessPolicyError("Refund and policy currencies must match.");
    }
    if (action.amountMinor > policy.refundThresholdMinor) {
      return { reviewerTeam: policy.financeTeam, reason: "Refund exceeds the finance review threshold." };
    }
    return { reviewerTeam: policy.defaultTeam, reason: "Refund is at or below the finance review threshold." };
  }
  if (action.kind === "invoice_review") {
    return { reviewerTeam: policy.financeTeam, reason: "Invoice review requires the finance team." };
  }
  return { reviewerTeam: policy.defaultTeam, reason: "Standard team approval is required." };
}

export function practiceBusinessAction(input: unknown, policy: unknown, templateId?: unknown) {
  try {
    const action = parseBusinessAction(input);
    if (templateId !== undefined) validateTemplateAction(templateId, action);
    return { ok: true as const, ...evaluateBusinessAction(action, parseBusinessPolicy(policy)) };
  } catch (error) {
    if (error instanceof BusinessPolicyError) return { ok: false as const, reason: error.message };
    throw error;
  }
}
